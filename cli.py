

#!/usr/bin/env python3
"""
PyThreatAnalyzer CLI - Análisis por lotes y salida JSON/CSV.

FIXES aplicados:
  - BUG imphash corregido: antes se comparaba contra known_bad_hashes (MD5/
    SHA1/SHA256 de ARCHIVOS). Ahora se usa la base DEDICADA de imphashes
    (check_imphash / malware_imphashes.txt).
  - El explainer SÍ recibe datos reales (imphash, entropía, overlay).
  - Análisis de archivos comprimidos (ZIP/RAR/7z) integrado.
  - calculate_layered_risk para desglose por capas (requisito #6).
  - Trust Decay en caché (get_with_trust_decay).

  - FIX BUG #2 (TabError): había TABs delante del 'if real_type in (...)' del
    bloque PE, lo que rompía la indentación y abortaba TODO el CLI al importar.
  - FIX BUG D (TOCTOU): get_file_hashes/check_reputation/check_whitelist
    reabren el archivo; si desaparece entre la comprobación inicial y estas
    lecturas, el CLI crasheaba con FileNotFoundError. Ahora todo el bloque
    está protegido con except OSError (FileNotFoundError es subclase).
"""

import argparse
import json
import logging
import sys
import os
from pathlib import Path
from typing import List, Dict
import csv
import time
from datetime import datetime

from virus_analyzer import StaticAnalyzer
from yara_engine import YARAEngine
from analysis_cache import AnalysisCache, ENGINE_VERSION, cache_report_matches_schema, expire_whitelist_hash_if_needed
# FIX BUG #1 (CRÍTICO): estos analizadores ya existían y estaban probados en
# test_pythreatanalyzer.py, y main.py (GUI) sí los usa, pero cli.py -el único
# punto de entrada "de producción" según el propio --help- nunca los
# invocaba. Resultado: scripts maliciosos (.ps1/.js/.vbs), documentos con
# macros, y señales de comportamiento (IOCs de red/persistencia/anti-VM
# extraídos de forma 100% estática) quedaban completamente sin analizar vía
# CLI, aunque los módulos que los detectan funcionan perfectamente cuando
# se llaman directamente.
from document_analyzer import DocumentAnalyzer
from dynamic_analyzer import DynamicAnalyzer
from ml_detector import MLDetector
from script_analyzer import ScriptAnalyzer
from ai_detector import AIDetector
from analysis_engine import AnalysisEngine
from archive_analyzer import ArchiveLimits
from analysis_utils import coverage_gap_messages
from report_generator import REPORT_SCHEMA_VERSION
from app_logging import setup_logging
from config_loader import load_config

CLI_CACHE_SCHEMA = 'cli-report-v1'

logger = logging.getLogger('PyThreatAnalyzer')

# K9: un OSError transitorio (p. ej. un parpadeo de NFS) se reintenta una vez.
TRANSIENT_RETRY_BACKOFF = 0.5


def _retry_transient_oserror(func, *args, retries=1, backoff=None, **kwargs):
    """Ejecuta func y reintenta `retries` veces ante OSError transitorio.

    FileNotFoundError NO se reintenta: un archivo que desapareció (TOCTOU) no
    va a reaparecer y reintentar solo retrasaría el lote.
    """
    delay = TRANSIENT_RETRY_BACKOFF if backoff is None else backoff
    attempt = 0
    while True:
        try:
            return func(*args, **kwargs)
        except FileNotFoundError:
            raise
        except OSError as exc:
            if attempt >= retries:
                raise
            attempt += 1
            logger.warning("OSError transitorio (%s); reintento %d/%d",
                           exc, attempt, retries)
            time.sleep(delay)


class PyThreatAnalyzerCLI:
    def __init__(self, config_path: str = 'config.json'):
        self.config = load_config(config_path)
        setup_logging(log_format=self.config.get('log_format', 'text'))
        self.analyzer = StaticAnalyzer(
            self.config.get('malware_hashes_db', 'malware_hashes.txt'),
            self.config.get('known_good_hashes_db', 'known_good_hashes.txt'),
            self.config.get('malware_imphashes_db', 'malware_imphashes.txt'),
            self.config.get('nsrl_db', None),
            # N-08: las bases fuzzy TLSH/ssdeep ahora son configurables.
            tlsh_db_path=self.config.get('malware_tlsh_db', 'malware_tlsh.txt'),
            ssdeep_db_path=self.config.get('malware_ssdeep_db', 'malware_ssdeep.txt'),
        )
        self.yara = YARAEngine(self.config.get('yara_rules_path', 'yara_rules/'),
                               timeout_seconds=self.config.get('yara_timeout_seconds', 30))
        # FIX BUG #1: capas de análisis que antes solo existían en la GUI
        # (main.py) y nunca se instanciaban/llamaban desde la CLI.
        self.document_analyzer = DocumentAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer()
        self.ml_detector = MLDetector(
            self.config.get('ml_model_path'), self.config.get('trusted_ml_model_sha256'))
        self.script_analyzer = ScriptAnalyzer()
        self.ai_detector = AIDetector()
        # N-17: pipeline único compartido con la GUI (main.py). La lógica de
        # análisis (PE/ELF, YARA, contenedores, scripts, IA, puntuación) vive
        # en analysis_engine.py; aquí queda la capa CLI (caché, errores
        # amistosos, reporte compacto, progreso).
        self.engine = AnalysisEngine(
            self.analyzer, self.yara, self.document_analyzer,
            self.dynamic_analyzer, self.ml_detector, self.script_analyzer,
            self.ai_detector,
            archive_limits=ArchiveLimits(
                max_member_analysis_seconds=self.config.get(
                    'max_member_analysis_seconds',
                    ArchiveLimits().max_member_analysis_seconds)))
        self.cache = AnalysisCache(
            self.config.get('cache_db_path', 'analysis_cache.db'),
            self.config.get('cache_ttl_days', 30),
            self.config.get('trust_decay_days', 90),
        )
        self.force_rescan = False

    _coverage_warned = False

    def _warn_coverage_gaps_once(self, virus_results):
        """Return gaps for reports and log them once per process."""
        reputation = virus_results.get('reputation') or {}
        status = ((reputation.get('database_status') or {})
                  .get('malware_hashes') or {}).get('status')
        gaps = coverage_gap_messages(
            malware_hash_status=status,
            nsrl_status=((reputation.get('database_status') or {}).get('nsrl') or {}).get('status'),
            known_good_status=((reputation.get('database_status') or {}).get('known_good_hashes') or {}).get('status'),
            tlsh_status=((reputation.get('database_status') or {}).get('malware_tlsh') or {}).get('status'),
            ssdeep_status=((reputation.get('database_status') or {}).get('malware_ssdeep') or {}).get('status'),
            yara_rule_count=getattr(getattr(self, 'yara', None), 'loaded_rule_count', None))
        if not self._coverage_warned:
            self._coverage_warned = True
            for gap in gaps:
                logger.warning("Cobertura reducida: %s", gap)
        return gaps

    def scan_file(self, file_path: str, progress_callback=None) -> Dict:
        def progress(index, label):
            if progress_callback:
                progress_callback(index, 6, label)
        if not os.path.exists(file_path):
            return {'error': f'Archivo no encontrado: {file_path}'}
        # N-06: /dev/zero (o cualquier dispositivo/pipe) bloquea la lectura
        # indefinidamente y colgaba el análisis. Solo se admiten ficheros
        # regulares; el resto se rechaza sin abrirlos.
        if not os.path.isfile(file_path):
            return {'error': f'No es un archivo regular: {file_path}'}

        file_path = os.path.abspath(file_path)

        # FIX BUG D: el archivo puede desaparecer en cualquier momento entre
        # llamadas (TOCTOU). Este bloque reabre el archivo: cualquier
        # OSError (incluye FileNotFoundError) se reporta como error en vez
        # de crashear el CLI.
        #
        # OPTIMIZACIÓN: antes se llamaba a _quick_hash() (una pasada
        # completa calculando solo SHA256, únicamente para mirar la caché)
        # y, si había cache-miss, se volvía a leer el archivo entero de
        # nuevo en get_file_hashes() (MD5+SHA1+SHA256). Para archivos
        # grandes eso son dos lecturas/hasheos completos del archivo antes
        # de empezar siquiera el análisis. Ahora se calculan los hashes una
        # sola vez y su SHA256 se reutiliza como clave de caché.
        try:
            hashes = _retry_transient_oserror(
                self.analyzer.get_file_hashes, file_path)
            file_hash = hashes['sha256']
        except OSError as e:
            return {'error': f'Archivo inaccesible: {e}'}
        progress(1, 'Hashes')

        # N-05(a): la CLI ignoraba por completo `use_cache` de config.json
        # (solo la GUI lo respetaba), de modo que use_cache=false seguía
        # leyendo y escribiendo analysis_cache.db. Se unifica con force_rescan:
        # cache desactivada => ni se lee ni se escribe.
        cache_enabled = self.config.get('use_cache', True)
        if cache_enabled and not self.force_rescan:
            # N-10/2.3: en la CLI el trust decay estaba derogado en la práctica.
            # get_with_trust_decay invalidaba la caché pero el hash seguía en
            # known_good_hashes (memoria) y en known_good_hashes.txt (disco),
            # así que el siguiente scan volvía a whitelistarlo para siempre.
            expire_whitelist_hash_if_needed(self.cache, self.analyzer, file_hash)
            cached = self.cache.get_with_trust_decay(file_hash)
            if cached and cache_report_matches_schema(cached.get('report'), CLI_CACHE_SCHEMA):
                result = {'report_schema_version': REPORT_SCHEMA_VERSION,
                          **cached['report']}
                result['coverage_warnings'] = self._warn_coverage_gaps_once({
                    'reputation': {
                        'database_status': getattr(self.analyzer,
                                                   'database_status', {})
                    }
                })
                # N-05(b): la clave de caché es el SHA256, pero el campo 'file'
                # del reporte cacheado apuntaba a la ruta ORIGINAL. Al escanear
                # una copia con el mismo hash se reportaba el archivo
                # equivocado. Se sobreescribe con la ruta realmente escaneada.
                result['file'] = file_path
                result['_cached'] = True
                return result

        # N-17: todo el análisis (tipo, PE/ELF+entropía/overlay/compresión,
        # YARA, contenedores y sus miembros, documentos, strings, polyglot,
        # comportamiento, ML, scripts, IA, puntuación con capas y resumen
        # explainable) vive en el motor único compartido con la GUI
        # (analysis_engine.py). Antes este cuerpo (~270 líneas) duplicaba
        # main.py:_analyze_virus (~160 líneas) con divergencias reales:
        # la GUI no registraba explicaciones fuzzy TLSH/ssdeep ni de
        # empaquetado, puntuaba sin script/IA y sin capas, y re-analizaba
        # los miembros de contenedores de forma distinta. Aquí solo queda
        # la capa CLI: progreso, errores amistosos y reporte compacto.
        #
        # FIX BUG D: el motor reabre el archivo (reputación, detección,
        # YARA...); si desaparece en medio (TOCTOU), cualquiera de esas
        # lecturas puede lanzar OSError y aquí se reporta como error.
        try:
            prev_hook = self.engine.on_checkpoint
            self.engine.on_checkpoint = progress
            try:
                virus_results = _retry_transient_oserror(
                    self.engine.analyze_file, file_path, hashes=hashes)
            finally:
                self.engine.on_checkpoint = prev_hook
        except OSError as e:
            return {'error': f'Archivo inaccesible: {e}'}

        coverage_warnings = self._warn_coverage_gaps_once(virus_results)

        whitelist = virus_results.get('whitelist') or {}
        result = {
            'report_schema_version': REPORT_SCHEMA_VERSION,
            '_cache_schema': CLI_CACHE_SCHEMA,
            'file': file_path,
            'real_type': virus_results.get('file_type'),
            'hashes': virus_results.get('hashes'),
            'imphash': virus_results.get('imphash'),
            'risk_score': virus_results.get('risk_score'),
            'risk_level': virus_results.get('risk_level'),
            'indicators': virus_results.get('indicators'),
            'layer_scores': virus_results.get('layer_scores'),
            'is_whitelisted': whitelist.get('is_whitelisted', False),
            'whitelist_reason': whitelist.get('reason'),
            'explanation': virus_results.get('explanation'),
            'timestamp': datetime.now().isoformat(),
            'engine_version': ENGINE_VERSION,
            'analysis_status': virus_results.get('analysis_status'),
            'analysis_warnings': virus_results.get('analysis_warnings'),
            'coverage_warnings': coverage_warnings,
        }

        archive_analysis = virus_results.get('archive_analysis')
        if archive_analysis:
            result['archive_analysis'] = archive_analysis

        if cache_enabled:
            try:
                self.cache.set(file_hash, file_path,
                               virus_results.get('risk_level'), result)
            except Exception:
                pass

        return result

    def scan_directory(self, directory: str, recursive: bool = False, *,
                       max_files: int = 10000, max_time: float = 3600,
                       progress: bool = True) -> List[Dict]:
        results = []
        path = Path(directory)
        files = path.rglob('*') if recursive else path.glob('*')
        started = time.monotonic()
        for file_path in files:
            if len(results) >= max_files or time.monotonic() - started >= max_time:
                break
            if not file_path.is_file():
                continue
            if progress:
                print(f"\rProgreso: {len(results) + 1} (límite {max_files}) - {file_path.name[:40]:<40}",
                      end='', file=sys.stderr, flush=True)
            try:
                results.append(
                    _retry_transient_oserror(self.scan_file, str(file_path)))
            except KeyboardInterrupt:
                break
            except Exception as e:
                # N-06: un único fichero problemático no debe abortar el lote
                # completo. Se registra como resultado de error y se sigue.
                if getattr(e, '_pythreat_cancelled', False):
                    raise
                results.append({
                    'file': str(file_path),
                    'risk_score': 0,
                    'risk_level': 'UNKNOWN',
                    'error': f'Análisis falló ({type(e).__name__}): {e}',
                })
        if progress:
            print(file=sys.stderr)
        return results

    def export_json(self, results: List[Dict], output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({'report_schema_version': REPORT_SCHEMA_VERSION,
                       'results': results}, f, indent=2, default=str)

    def export_csv(self, results: List[Dict], output_file: str) -> bool:
        """R-10: escribe SIEMPRE el CSV (con cabecera aunque no haya filas) y
        devuelve True; antes un lote vacío no creaba el archivo pero la CLI
        imprimía igualmente «Reporte guardado». Se añaden `analysis_status` y
        `error` para distinguir un fallo de análisis de un resultado limpio."""
        fields = ['file', 'real_type', 'risk_level', 'risk_score',
                  'md5', 'sha256', 'is_whitelisted', 'indicators_count', 'cached',
                  'analysis_status', 'error']
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in results:
                hashes = r.get('hashes', {}) or {}
                writer.writerow({
                    'file': r.get('file', ''),
                    'real_type': r.get('real_type', ''),
                    'risk_level': r.get('risk_level', 'UNKNOWN'),
                    'risk_score': r.get('risk_score', 0),
                    'md5': hashes.get('md5', ''),
                    'sha256': hashes.get('sha256', ''),
                    'is_whitelisted': r.get('is_whitelisted', False),
                    'indicators_count': len(r.get('indicators') or []),
                    'cached': r.get('_cached', False),
                    'analysis_status': ('ERROR' if r.get('error') else
                                        r.get('analysis_status', '')),
                    'error': r.get('error', ''),
                })
        return True


# R-10: fuente única de la versión; pyproject.toml la lee de aquí
# ([tool.setuptools.dynamic] version = {attr = "cli.__version__"}).
from pythreat_version import __version__

# Orden de niveles para --fail-on (código de salida 3 si se alcanza el umbral).
_LEVEL_ORDER = {'SIN RIESGO DETECTADO': 0, 'BAJO': 1, 'MEDIO': 2, 'ALTO': 3, 'CRÍTICO': 4}


def _reaches_level(results, threshold: str) -> bool:
    limit = _LEVEL_ORDER[threshold]
    return any(_LEVEL_ORDER.get(r.get('risk_level'), 0) >= limit for r in results)


def main():
    parser = argparse.ArgumentParser(
        description='PyThreatAnalyzer CLI - Análisis estático de malware',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s scan archivo.exe --output json
  %(prog)s scan-directorio ~/Descargas/ --recursive --output csv -o reporte.csv
        """
    )
    parser.add_argument('--version', action='version', version=f'PyThreatAnalyzer {__version__}')
    parser.add_argument('--force', action='store_true', help='Forzar re-análisis ignorando caché')

    subparsers = parser.add_subparsers(dest='command', help='Comandos')

    scan_parser = subparsers.add_parser('scan', help='Analizar archivo')
    scan_parser.add_argument('file', help='Archivo a analizar')
    scan_parser.add_argument('--output', choices=['json', 'text'], default='text')
    scan_parser.add_argument('--progress', action='store_true', help='Mostrar progreso por fase')
    scan_parser.add_argument('--quiet', action='store_true', help='Imprimir solo el resultado JSON')
    scan_parser.add_argument('--fail-on', choices=[k for k in _LEVEL_ORDER if k != 'SIN RIESGO DETECTADO'],
                             help='Salir con código 3 si el riesgo alcanza este nivel (para CI)')

    dir_parser = subparsers.add_parser('scan-directorio', help='Analizar directorio')
    dir_parser.add_argument('directory', help='Directorio a escanear')
    dir_parser.add_argument('--recursive', '-r', action='store_true')
    dir_parser.add_argument('--output', choices=['json', 'csv'], default='json')
    dir_parser.add_argument('-o', '--output-file', required=True)
    dir_parser.add_argument('--max-files', type=int, default=10000)
    dir_parser.add_argument('--max-time', type=float, default=3600)
    dir_parser.add_argument('--quiet', action='store_true')
    dir_parser.add_argument('--fail-on', choices=[k for k in _LEVEL_ORDER if k != 'SIN RIESGO DETECTADO'],
                            help='Salir con código 3 si algún archivo alcanza este nivel (para CI)')

    args = parser.parse_args()
    logger.info("PyThreatAnalyzer v%s CLI iniciado", __version__)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = PyThreatAnalyzerCLI()
    if getattr(args, 'quiet', False):
        for handler in logging.getLogger('PyThreatAnalyzer').handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                    handler, logging.FileHandler):
                handler.setLevel(logging.CRITICAL + 1)
    if args.force:
        cli.force_rescan = True

    if args.command == 'scan':
        callback = (lambda i, n, label: print(f'[{i}/{n}] {label}...', file=sys.stderr)) if args.progress and not args.quiet else None
        result = cli.scan_file(args.file, progress_callback=callback)
        if 'error' in result:
            print(f"ERROR: {result['error']}", file=sys.stderr)
            sys.exit(2)

        if args.output == 'json' or args.quiet:
            print(json.dumps(result, indent=2, default=str))
        elif not args.quiet:
            print(f"\n{'='*60}")
            print(f"Archivo: {result['file']}")
            print(f"Tipo real: {result['real_type']}")
            print(f"Riesgo: {result['risk_level']} ({result['risk_score']}/100)")
            if result.get('analysis_status') == 'INCOMPLETE':
                print("Cobertura: INCOMPLETA; este resultado no confirma ausencia de amenazas.")
                for warning in result.get('analysis_warnings', []):
                    print(f"  - {warning}")
            if result.get('coverage_warnings'):
                print("Cobertura de datos reducida:")
                for warning in result['coverage_warnings']:
                    print(f"  - {warning}")
            print(f"{'='*60}")
            if result.get('is_whitelisted'):
                print(f"OK Whitelist: {result['whitelist_reason']}")
            if result['indicators']:
                print(f"\nIndicadores:")
                for ind in result['indicators']:
                    print(f"  - {ind}")
            layer_scores = result.get('layer_scores', {})
            if layer_scores:
                print(f"\nScore por capa:")
                for name, data in layer_scores.items():
                    if data['score'] > 0:
                        print(f"  {name}: {data['score']} (conf {data['confidence']})")
            exp = result.get('explanation', {})
            if exp and exp.get('summary'):
                print(f"\nResumen: {exp['summary']}")
                if exp.get('mitre_techniques'):
                    print(f"MITRE ATT&CK:")
                    for tech in exp['mitre_techniques']:
                        print(f"  - {tech}")
                if exp.get('recommendations'):
                    print(f"Recomendaciones:")
                    for rec in exp['recommendations']:
                        print(f"  -> {rec}")
        if getattr(args, 'fail_on', None) and _reaches_level([result], args.fail_on):
            sys.exit(3)

    elif args.command == 'scan-directorio':
        results = cli.scan_directory(args.directory, args.recursive,
                                     max_files=max(1, args.max_files),
                                     max_time=max(0.1, args.max_time), progress=not args.quiet)
        risk_counts = {}
        for r in results:
            level = r.get('risk_level', 'UNKNOWN')
            risk_counts[level] = risk_counts.get(level, 0) + 1
        if not args.quiet:
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"Total archivos: {len(results)}", file=sys.stderr)
            for level, count in sorted(risk_counts.items()):
                print(f"  {level}: {count}", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)
        if args.output == 'json':
            cli.export_json(results, args.output_file)
        else:
            cli.export_csv(results, args.output_file)
        if not args.quiet:
            print(f"Reporte guardado: {args.output_file}")
        if getattr(args, 'fail_on', None) and _reaches_level(results, args.fail_on):
            sys.exit(3)


if __name__ == '__main__':
    main()
    
    
    
