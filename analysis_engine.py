"""analysis_engine.py — N-17: motor único de análisis, compartido por CLI y GUI.

Antes el pipeline de análisis vivía duplicado en cli.py
(PyThreatAnalyzerCLI.scan_file: ~270 líneas) y en main.py
(PyThreatAnalyzerGUI._analyze_virus: ~160 líneas), con divergencias sutiles
que las pruebas funcionales no detectaban:

  * la GUI no registraba explicaciones de match TLSH/ssdeep (indicator
    'Fuzzy_TLSH'/'Fuzzy_ssdeep', ver explicación de N-19) ni la explicación
    de empaquetado por compresión, pero la CLI sí;
  * la GUI dejaba static_analysis={'note': ...} + 'file_type_is_executable'
    para tipos sin analizador específico; la CLI static_analysis={};
  * la GUI puntuaba virus SIN script/IA y SIN calculate_layered_risk; la
    CLI puntuaba con ambos;
  * la GUI re-analizaba los miembros de contenedores con _scan_member (sin
    caché) y la CLI con self.scan_file (con caché). Aquí se unifica a un
    escaneo recursivo SIN caché para ambos.

Ambos frontales delegan ahora en AnalysisEngine.analyze_file(); solo quedan
diferencias de CAPA (caché, errores amistosos, progreso, schema de caché).
Con esto, measure_corpus.py podrá describir la misma ruta de análisis en
los dos frontales.
"""

import os

from file_type_detector import FileTypeDetector, RealFileType
from explanation_engine import ExplanationEngine
from virus_analyzer import get_advanced_features
from archive_analyzer import (
    ArchiveLimits, analyze_compressed_file, analyze_structured_zip,
)
from risk_scoring import calculate_risk_score, calculate_layered_risk
from analysis_utils import (
    is_analyzable_as_text,
    is_script_code,
    collect_analysis_warnings,
)


class AnalysisEngine:
    """Pipeline completo de análisis de virus, independiente del frontal.

    No conoce cached ni errores amistosos: si el archivo desaparece en medio
    (TOCTOU), las excepciones OSError se propagan y cada frontal las traduce
    a su propio contrato (cli.py: dict 'error'; main.py: handler de errores).
    """

    def __init__(self, static_analyzer, yara_engine, document_analyzer,
                 dynamic_analyzer, ml_detector, script_analyzer, ai_detector,
                 on_checkpoint=None, archive_limits=None):
        self.static_analyzer = static_analyzer
        self.yara_engine = yara_engine
        self.document_analyzer = document_analyzer
        self.dynamic_analyzer = dynamic_analyzer
        self.ml_detector = ml_detector
        self.script_analyzer = script_analyzer
        self.ai_detector = ai_detector
        self.on_checkpoint = on_checkpoint
        # M1 (R-05): límites de contenedores configurables. None -> defaults;
        # dict (config validada) -> se toma max_member_analysis_seconds;
        # ArchiveLimits -> se usa tal cual.
        if isinstance(archive_limits, ArchiveLimits):
            self._archive_limits = archive_limits
        elif isinstance(archive_limits, dict):
            default_seconds = ArchiveLimits().max_member_analysis_seconds
            self._archive_limits = ArchiveLimits(
                max_member_analysis_seconds=archive_limits.get(
                    'max_member_analysis_seconds', default_seconds))
        else:
            self._archive_limits = ArchiveLimits()

    def _checkpoint(self, step, label):
        if self.on_checkpoint:
            self.on_checkpoint(step, label)

    def scan_member(self, file_path):
        """Re-analiza un miembro extraído de un contenedor con el MISMO
        pipeline y SIN caché (antes divergía: cli.py usaba scan_file con
        caché y main.py _scan_member sin caché). N-17.

        Los consumidores de archive_analyzer esperan un dict con 'error' o
        'risk_level' para agregarlo al nivel del contenedor.
        """
        try:
            member_results = self.analyze_file(file_path)
            if member_results.get('risk_score') is None:
                return {'error': 'análisis de miembro vacío', 'risk_level': 'SOSPECHOSO'}
            return member_results
        except Exception as e:
            # La cancelación cooperativa de la GUI se propaga (duck-typed,
            # como en _scan_member de main.py): archive_analyzer re-lanza y
            # el botón Cancelar sigue funcionando dentro de contenedores.
            if getattr(e, '_pythreat_cancelled', False):
                raise
            return {'error': str(e), 'risk_level': 'SOSPECHOSO'}

    def analyze_file(self, file_path, hashes=None):
        """Pipeline único (virus + script + IA) sin caché ni progreso propio.

        Devuelve el dict 'enriquecido' (virus_results) del que la GUI consume
        campos de análisis y de resumen, y del que el CLI deriva su reporte
        compacto. Incluye script_results/ai_results ya calculados para que la
        GUI no los recalcule (N-17).
        """
        if hashes is None:
            hashes = self.static_analyzer.get_file_hashes(file_path)
        self._checkpoint(1, 'Hashes')

        reputation = self.static_analyzer.check_reputation(file_path, hashes=hashes)
        whitelist = self.static_analyzer.check_whitelist(file_path, hashes=hashes)

        real_type, zip_infos = FileTypeDetector.detect(
            file_path, include_zip_metadata=True)
        self._checkpoint(2, f'Tipo: {real_type.name}')

        explainer = ExplanationEngine()
        adv = get_advanced_features(self.static_analyzer)

        is_pe = real_type in (RealFileType.PE32, RealFileType.PE64,
                              RealFileType.DLL)
        # Solo contenedores que deben recorrer sus miembros con el pipeline
        # completo. OOXML/JAR/APK se clasifican aparte para evitar analizar
        # cada XML/recurso como si fuera un archivo independiente.
        is_structured_zip = real_type in (
            RealFileType.OOXML, RealFileType.JAR, RealFileType.APK,
        )
        is_archive = real_type in (
            RealFileType.ZIP, RealFileType.RAR, RealFileType.RAR5,
            RealFileType.SEVEN_ZIP,
        )

        static_analysis = {}
        imphash = None
        entropy_windows = None
        overlay = None
        compression = None

        if is_pe:
            static_analysis = self.static_analyzer.analyze_pe(file_path)

            # FIX BUG #1: imphash_match / tlsh_match / ssdeep_match ya los
            # rellena check_reputation() contra las bases DEDICADAS. Aquí
            # solo se consume el resultado y se explica.
            imphash = reputation.get('imphash')
            if reputation.get('imphash_match'):
                explainer.add_imphash_explanation(imphash, 1)
            if reputation.get('tlsh_match'):
                explainer.add_similarity_explanation('TLSH', 'muestra similar')
            if reputation.get('ssdeep_match'):
                explainer.add_similarity_explanation('ssdeep', 'muestra similar')

            entropy_windows = adv.analyze_entropy_windows(file_path)
            if entropy_windows.get('suspicious_transitions', 0) > 0:
                transitions = entropy_windows.get('transitions') or []
                first_transition = transitions[0] if transitions else None
            else:
                first_transition = None
            if isinstance(first_transition, dict) and 'from_offset' in first_transition:
                explainer.add_entropy_explanation(
                    entropy=entropy_windows['max_entropy'],
                    section='transición',
                    offset=str(first_transition['from_offset']))

            overlay = adv.detect_overlay(file_path)
            if overlay and overlay.get('is_suspicious'):
                if not all(key in overlay for key in ('size', 'entropy', 'offset')):
                    overlay = None
            if overlay and overlay.get('is_suspicious'):
                explainer.add_overlay_explanation(
                    size=overlay['size'], entropy=overlay['entropy'],
                    offset=overlay['offset'])

            compression = adv.test_compression_ratio(file_path)
            if compression.get('likely_packed'):
                explainer.add_packer_explanation('datos_no_compressibles', 'muestra')

        elif real_type == RealFileType.ELF:
            static_analysis = self.static_analyzer.analyze_elf(file_path)
        else:
            static_analysis = {
                'note': f'Sin analizador específico para {real_type.name}'
            }
        self._checkpoint(3, 'Análisis PE/ELF')

        # Un match de hash conocido (HASH_KNOWN_BAD) debe quedar registrado
        # en el explainer: si no, generate_summary() cae en el mensaje por
        # defecto "El archivo parece limpio" aunque el score sea CRÍTICO.
        hash_known_bad = bool(
            reputation.get('sha256_match')
            or reputation.get('sha1_match')
            or reputation.get('md5_match')
        )
        if hash_known_bad:
            # N-07: prioridad SHA256 > SHA1 > MD5 para elegir la etiqueta.
            if reputation.get('sha256_match'):
                hash_type, hash_value = 'SHA256', hashes.get('sha256', '')
            elif reputation.get('sha1_match'):
                hash_type, hash_value = 'SHA1', hashes.get('sha1', '')
            else:
                hash_type, hash_value = 'MD5', hashes.get('md5', '')
            explainer.add_hash_match_explanation(hash_type, hash_value)

        # YARA se calcula ANTES del resumen (si no, sus matches suman al
        # score pero no dejan explicación registrada).
        yara_results = self.yara_engine.scan(file_path)
        self._checkpoint(4, 'YARA')
        for match in (yara_results.get('matches', []) or []):
            sev = (match.get('meta', {}) or {}).get('severity', 'low')
            explainer.add_yara_explanation(match.get('rule', '?'), sev)

        archive_analysis = None
        if is_structured_zip:
            archive_analysis = analyze_structured_zip(
                file_path, zip_infos=zip_infos, member_analyzer=self.scan_member,
                limits=self._archive_limits)
            if archive_analysis.get('is_password_protected'):
                explainer.add_archive_password_explanation()
        elif is_archive:
            archive_analysis = analyze_compressed_file(
                file_path, recursive=True, member_analyzer=self.scan_member,
                limits=self._archive_limits)
            if archive_analysis.get('is_password_protected'):
                explainer.add_archive_password_explanation()
        self._checkpoint(5, 'Contenedor / documento')

        document_analysis = None
        if self.document_analyzer.is_supported(file_path, real_type):
            document_analysis = self.document_analyzer.analyze(file_path, real_type)

        strings_info = self.static_analyzer.extract_strings(file_path)
        polyglot = self.static_analyzer.check_polyglot(file_path)
        behavior_analysis = self.dynamic_analyzer.analyze(file_path, real_type)
        ml_prediction = self.ml_detector.predict(file_path)

        # N-04: el analizador de scripts solo sobre código real; la detección
        # de prompts IA sí se aplica a cualquier texto/documento.
        script_results = {}
        ai_results = {}
        if is_script_code(file_path, real_type):
            script_results = self.script_analyzer.analyze_script(
                file_path, real_type)
        if is_analyzable_as_text(file_path, real_type):
            ai_results = self.ai_detector.analyze_file(file_path)
        self._checkpoint(6, 'Comportamiento y contenido')

        virus_results = {
            'file': file_path,
            'hashes': hashes,
            'reputation': reputation,
            'whitelist': whitelist,
            'static_analysis': static_analysis,
            'yara': yara_results,
            'file_type': real_type.name,
            'file_type_is_executable': FileTypeDetector.is_executable(real_type),
            'imphash': imphash,
            'tlsh': reputation.get('tlsh'),
            'entropy_windows': entropy_windows,
            'overlay': overlay,
            'compression': compression,
            'archive_analysis': archive_analysis,
            'document_analysis': document_analysis,
            'strings': strings_info,
            'polyglot': polyglot,
            'behavior_analysis': behavior_analysis,
            'ml_prediction': ml_prediction,
        }
        analysis_warnings = collect_analysis_warnings(
            reputation, yara_results, document_analysis, archive_analysis,
            static_analysis, behavior_analysis, entropy_windows,
            script_results=script_results)
        virus_results['analysis_warnings'] = analysis_warnings
        virus_results['analysis_status'] = (
            'INCOMPLETE' if analysis_warnings else 'COMPLETE'
        )

        score, risk_level, indicators = calculate_risk_score(
            virus_results, script_results, ai_results)
        virus_results['risk_score'] = score
        virus_results['risk_level'] = risk_level
        virus_results['indicators'] = indicators

        _, _, _, layers = calculate_layered_risk(
            virus_results, script_results, ai_results)
        virus_results['layer_scores'] = {
            name: {'score': l.score, 'confidence': l.confidence,
                   'findings': l.findings}
            for name, l in layers.items()
        }

        virus_results['explanation'] = explainer.generate_summary(
            risk_level=risk_level, risk_indicators=indicators)

        # N-17: la GUI reutiliza los cálculos de script/IA del motor (también
        # desde caché) en lugar de recomputarlos aparte.
        virus_results['script_results'] = script_results
        virus_results['ai_results'] = ai_results
        return virus_results