# archive_analyzer.py
"""
Analizador de archivos comprimidos (ZIP/RAR/7z) con protección anti-zip-bomb.

FIX BUG #3: doble recursión. Antes analyze_archive() recursaba internamente
SOBRE anidados Y analyze_compressed_file() volvía a llamar member_analyzer por
cada archivo extraído: con member_analyzer=scan_file, cada miembro anidado se
analizaba DOS veces. Ahora la recursión vive en UN SOLO lugar:
  - analyze_archive(nested, depth+1, member_analyzer) recorre anidados y
    propaga member_analyzer a todos los niveles.
  - member_analyzer se aplica SOLO a miembros NO-archivo (los anidados los
    cubre la propia recursión).
  - Los contadores anti-zip-bomb (1GB / 10k archivos) siguen ACUMULATIVOS
    entre niveles (un solo ArchiveAnalyzer por llamada de alto nivel).

FIX BUG #4: la puerta de entrada decidía por EXTENSIÓN (SUPPORTED_EXTENSIONS),
así que un ZIP renombrado a .exe se rechazaba con "Formato no soportado".
Ahora:
  - _sniff_format() lee magic bytes (PK/Rar!/7z) y decide el formato REAL.
  - analyze_archive() y _is_archive() usan magic bytes primero; la extensión
    es solo fallback. Un ZIP disfrazado de .exe se analiza, y un RAR
    renombrado a .zip se despacha al analizador correcto.

Otros fixes vigentes: sin extractall nunca, path traversal bloqueado,
nombres únicos, profundidad máxima efectiva.
"""

import contextvars
import os
import ntpath
import re
import tempfile
import time
import shutil
import zipfile
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from analysis_utils import classify_structured_zip_names, zip_member_count_from_eocd
from risk_levels import LEVEL_RANK

try:
    import py7zr
    _PY7ZR_AVAILABLE = True
except ImportError:
    _PY7ZR_AVAILABLE = False

try:
    import rarfile
    _RARFILE_AVAILABLE = True
except ImportError:
    _RARFILE_AVAILABLE = False


# R-02: contexto compartido entre ArchiveAnalyzer anidados. Un JAR/OOXML
# dentro de otro contenedor NO es "archivo" para _is_archive, así que se
# analiza con member_analyzer -> motor -> un ArchiveAnalyzer NUEVO. Sin este
# contexto cada capa arrancaba con profundidad 0 y contadores a cero, y
# max_depth/max_total_size/max_file_count no se aplicaban entre capas.
class _ArchiveContext:
    __slots__ = ('level', 'total_size', 'file_count', 'deadline')

    def __init__(self, budget_seconds: float = 0.0):
        self.level = 0          # nivel de anidamiento del analizador activo
        self.total_size = 0     # bytes descomprimidos acumulados (todas las capas)
        self.file_count = 0     # miembros acumulados (todas las capas)
        # R-05: instante límite (monotonic) para analizar miembros; None = sin límite
        self.deadline = (time.monotonic() + budget_seconds) if budget_seconds else None


_ARCHIVE_CTX = contextvars.ContextVar('pta_archive_ctx', default=None)


def _apply_ratio_heuristic(results: Dict, ratio: float) -> None:
    """R-03: el ratio de compresión es una señal DÉBIL.

    Antes `ratio > 100` marcaba CRÍTICO (100 puntos tras N-12): una imagen de
    disco de ceros o un XLSX repetitivo puntuaban igual que un hash malicioso
    conocido. La protección real contra zip bombs son los límites duros de
    extracción (tamaño total, número de archivos, profundidad), que siguen
    marcando CRÍTICO/ALTO. El ratio solo eleva a MEDIO (extremo) o deja una
    nota informativa (alto); el contenido se juzga miembro a miembro.
    """
    if ratio > 100:
        results['suspicious_patterns'].append(
            f"Ratio de compresión extremo ({ratio:.0f}x); señal débil, "
            f"el contenido se analiza miembro a miembro"
        )
        if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['MEDIO']:
            results['risk_level'] = 'MEDIO'
    elif ratio > 20:
        results['suspicious_patterns'].append(
            f"Ratio de compresión alto ({ratio:.0f}x) (informativo)"
        )


@dataclass
class ArchiveLimits:
    max_total_size: int = 1 * 1024 * 1024 * 1024
    # Mantener un límite independiente de tamaño/ratio: muchos miembros
    # pequeños también consumen memoria y tiempo de procesamiento.
    max_file_count: int = 10000
    max_depth: int = 5
    max_file_size: int = 100 * 1024 * 1024
    password_protected_is_suspicious: bool = True
    # R-05: presupuesto de tiempo (segundos) para analizar los MIEMBROS de un
    # contenedor y de todos los anidados. Cada miembro pasa por el pipeline
    # completo (~40-50 ms); un contenedor de 10.000 miembros tardaba minutos.
    # Al agotarse, los miembros restantes NO se analizan y el resultado queda
    # marcado como incompleto (ANALISIS_MIEMBRO_INCOMPLETO). 0 = sin límite.
    max_member_analysis_seconds: float = 120.0


@dataclass
class ExtractedFileInfo:
    path: str
    name: str
    size: int
    depth: int
    parent_archive: str
    is_password_protected: bool = False


class ArchiveAnalysisError(Exception):
    pass


class ZipBombDetectedError(ArchiveAnalysisError):
    pass


_LEVEL_RANK = LEVEL_RANK  # K4: fuente única en risk_levels.py


class ArchiveAnalyzer:
    SUPPORTED_EXTENSIONS = {'.zip', '.7z', '.rar'}

    def __init__(self, limits: Optional[ArchiveLimits] = None):
        self.limits = limits or ArchiveLimits()
        self._extracted_files: List[ExtractedFileInfo] = []
        self._temp_dirs: List[str] = []
        self._total_extracted_size = 0
        self._file_count = 0
        self._password_protected_found = False
        self._name_counter = 0
        self._ctx = None
        self._base_level = 0

    def _enter_ctx(self):
        """R-02: engancha este analizador al contexto compartido (o lo crea)."""
        outer = _ARCHIVE_CTX.get()
        if outer is None:
            self._ctx = _ArchiveContext(self.limits.max_member_analysis_seconds)
        else:
            self._ctx = outer
        self._base_level = self._ctx.level
        self._total_extracted_size = self._ctx.total_size
        self._file_count = self._ctx.file_count

    def _depth_exceeded_result(self, results=None):
        """Resultado uniforme cuando el anidamiento total supera max_depth."""
        msg = (f"Profundidad máxima ({self.limits.max_depth}) alcanzada entre "
               f"contenedores anidados; no se desempaqueta más")
        res = results if results is not None else {
            'type': 'ARCHIVE', 'format': 'NESTED', 'depth': self._base_level,
            'files_analyzed': 0, 'total_size': 0, 'is_password_protected': False,
            'nested_archives': [], 'extracted_files': [],
        }
        res.setdefault('suspicious_patterns', []).append(msg)
        res['error'] = 'Profundidad máxima excedida'
        res['risk_level'] = 'ALTO'
        res['aggregated_risk'] = 'ALTO'
        return res

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    @staticmethod
    def _sniff_format(file_path: str) -> Optional[str]:
        """FIX BUG #4: formato REAL por magic bytes, nunca por extensión.
        Devuelve '.zip' / '.7z' / '.rar', o None si no es un contenedor
        reconocido (entonces decide la extensión, como fallback)."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
        except OSError:
            return None
        if header.startswith(b'PK\x03\x04') or header.startswith(b'PK\x05\x06'):
            return '.zip'
        if header.startswith(b'Rar!'):
            # RAR4 = 'Rar!\x1a\x07\x00', RAR5 = 'Rar!\x1a\x07\x01\x00':
            # ambos comparten prefijo 'Rar!' y rarfile maneja las dos versiones.
            return '.rar'
        if header.startswith(b'7z\xbc\xaf\x27\x1c'):
            return '.7z'
        return None

    def analyze_structured(self, file_path: str, zip_infos=None,
                           member_analyzer: Optional[Callable[[str], Dict]] = None) -> Dict:
        """Preflight + análisis de miembros de un contenedor OOXML/JAR/APK.

        El preflight solo mira el directorio central. Si recibe member_analyzer,
        extrae y analiza los miembros con las mismas protecciones que un ZIP
        (path traversal, límites, nombres seguros). Antes solo se hacía el
        preflight, así que un payload con hash conocido dentro de un
        JAR/OOXML/docx quedaba SIN RIESGO (evasión N-01).
        """
        self._extracted_files = []
        self._name_counter = 0
        self._enter_ctx()
        if self._base_level > self.limits.max_depth:
            return self._depth_exceeded_result()
        result = {
            'type': 'ARCHIVE',
            'format': 'ZIP_STRUCTURED',
            'depth': 0,
            'files_analyzed': 0,
            'total_size': 0,
            'is_password_protected': False,
            'suspicious_patterns': [],
            'risk_level': 'BENIGNO',
            'nested_archives': [],
            'extracted_files': [],
            'inspection_mode': 'central_directory_only',
        }
        try:
            if zip_infos is None:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    infos = zf.infolist()
            else:
                # ZipInfo permanece utilizable tras cerrar el ZipFile detector.
                infos = zip_infos

            structured_type = classify_structured_zip_names(
                info.filename for info in infos
            )
            if not structured_type:
                raise zipfile.BadZipFile('No se reconoció OOXML, JAR ni APK')

            total_uncompressed = sum(max(0, info.file_size or 0) for info in infos)
            result['format'] = structured_type
            result['files_analyzed'] = len(infos)
            result['total_size'] = total_uncompressed
            result['is_password_protected'] = any(info.flag_bits & 0x1 for info in infos)

            if result['is_password_protected'] and self.limits.password_protected_is_suspicious:
                result['suspicious_patterns'].append(
                    'Archivo protegido con contraseña - patrón de evasión'
                )
                result['risk_level'] = 'SOSPECHOSO'

            if total_uncompressed > self.limits.max_total_size:
                result['suspicious_patterns'].append(
                    f"Tamaño total descomprimido excede límite ({total_uncompressed} > "
                    f"{self.limits.max_total_size} bytes)"
                )
                result['risk_level'] = 'CRÍTICO'
            if len(infos) > self.limits.max_file_count:
                result['suspicious_patterns'].append(
                    f"Cantidad de miembros excede límite ({len(infos)} > {self.limits.max_file_count})"
                )
                result['risk_level'] = 'CRÍTICO'

            compressed_size = os.path.getsize(file_path)
            ratio = total_uncompressed / compressed_size if compressed_size else 0
            result['compression_ratio'] = ratio
            _apply_ratio_heuristic(result, ratio)

            if member_analyzer is not None:
                # Extrae los miembros (misma lógica anti-bomb que _analyze_zip)
                # y agrega su riesgo al del contenedor.
                extracted = self._analyze_zip(file_path, 0)
                result['nested_archives'] = extracted.get('nested_archives', [])
                result['is_password_protected'] = (
                    result['is_password_protected']
                    or extracted.get('is_password_protected', False)
                )
                # 3.1: _analyze_zip también marca path traversal ("Ruta
                # insegura en ZIP") y límites; antes se descartaban y un
                # JAR/OOXML/APK con path traversal no registraba la
                # advertencia que sí registra un ZIP genérico.
                result['suspicious_patterns'].extend(
                    extracted.get('suspicious_patterns', []))
                if _LEVEL_RANK.get(extracted.get('risk_level', 'BENIGNO'), 0) > \
                        _LEVEL_RANK.get(result['risk_level'], 0):
                    result['risk_level'] = extracted['risk_level']
                result['inspection_mode'] = 'central_directory_and_members'
                self._aggregate_members(result, 0, member_analyzer)
            else:
                result['aggregated_risk'] = result['risk_level']

        except ZipBombDetectedError as e:
            result['error'] = str(e)
            result['risk_level'] = 'CRÍTICO'
            result['suspicious_patterns'].append(f"ZIP_BOMB: {e}")
            result['aggregated_risk'] = 'CRÍTICO'
        except Exception as exc:
            if getattr(exc, '_pythreat_cancelled', False):
                raise
            result['error'] = (
                f"Error en preflight del contenedor estructurado "
                f"({type(exc).__name__}): {exc}"
            )
            result['suspicious_patterns'].append(
                'No se pudo validar el directorio central del contenedor'
            )
            if _LEVEL_RANK.get(result['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                result['risk_level'] = 'SOSPECHOSO'
            result['aggregated_risk'] = result['risk_level']

        return result

    def _aggregate_members(self, results: Dict, current_depth: int,
                           member_analyzer: Optional[Callable[[str], Dict]]) -> None:
        """Analiza los miembros NO-archivo extraídos y agrega su riesgo.

        Extraído de analyze_archive() para reutilizarlo también con los
        contenedores estructurados (OOXML/JAR/APK), que antes solo hacían
        preflight del directorio central y por tanto no analizaban nunca el
        contenido de sus miembros (vector de evasión N-01).
        """
        # ---- Análisis de miembros NO-archivo (una sola vez por miembro) ----
        member_results = []
        if member_analyzer is not None:
            budget_skipped = 0
            for extracted in [f for f in self._extracted_files if f.depth == current_depth]:
                if not os.path.isfile(extracted.path):
                    continue
                if self._is_archive(extracted.path):
                    continue  # los anidados los cubre la recursión de abajo
                # R-05: presupuesto de tiempo agotado -> no analizar más miembros.
                if (self._ctx is not None and self._ctx.deadline is not None
                        and time.monotonic() > self._ctx.deadline):
                    budget_skipped += 1
                    continue
                try:
                    ctx = self._ctx
                    token = prev_level = None
                    if ctx is not None:
                        # R-02: el miembro se analiza un nivel más adentro.
                        prev_level = ctx.level
                        ctx.level = self._base_level + current_depth + 1
                        token = _ARCHIVE_CTX.set(ctx)
                    try:
                        nested = member_analyzer(extracted.path)
                    finally:
                        if ctx is not None:
                            ctx.level = prev_level
                            _ARCHIVE_CTX.reset(token)
                    if not isinstance(nested, dict):
                        raise TypeError('member_analyzer no devolvió un diccionario')
                    member_error = nested.get('error')
                    member_results.append({
                        'name': extracted.name,
                        'size': extracted.size,
                        'depth': extracted.depth,
                        'result': nested,
                    })
                    if member_error:
                        # Un miembro que no pudo analizarse no equivale a
                        # un miembro benigno. Hacer visible la cobertura
                        # perdida y evitar que el contenedor quede limpio
                        # solo porque el callback devolvió {'error': ...}.
                        results['suspicious_patterns'].append(
                            f"ANALISIS_MIEMBRO_INCOMPLETO: {extracted.name}: {member_error}"
                        )
                        lvl = 'SOSPECHOSO'
                    else:
                        lvl = nested.get('risk_level', 'BENIGNO')
                    if _LEVEL_RANK.get(lvl, 0) > _LEVEL_RANK.get(results['risk_level'], 0):
                        results['risk_level'] = lvl
                except Exception as e:
                    if getattr(e, '_pythreat_cancelled', False):
                        raise
                    member_results.append({
                        'name': extracted.name,
                        'size': extracted.size,
                        'depth': extracted.depth,
                        'error': str(e),
                    })
                    results['suspicious_patterns'].append(
                        f"ANALISIS_MIEMBRO_INCOMPLETO: {extracted.name}: {e}"
                    )
                    if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                        results['risk_level'] = 'SOSPECHOSO'
            if budget_skipped:
                results['suspicious_patterns'].append(
                    f"ANALISIS_MIEMBRO_INCOMPLETO: presupuesto de tiempo "
                    f"({self.limits.max_member_analysis_seconds:g}s) agotado; "
                    f"{budget_skipped} miembro(s) sin analizar"
                )
                if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                    results['risk_level'] = 'SOSPECHOSO'
            if member_results:
                results['member_analysis'] = member_results

        # ---- ÚNICA recursión sobre anidados (agregación de riesgo) ----
        nested_results = []
        for nested in results.get('nested_archives', []):
            if current_depth + 1 > self.limits.max_depth:
                results['suspicious_patterns'].append(
                    f"Profundidad máxima ({self.limits.max_depth}) alcanzada; "
                    f"no se desempaqueta más allá: {os.path.basename(nested)}"
                )
                if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['ALTO']:
                    results['risk_level'] = 'ALTO'
                break
            try:
                nested_res = self.analyze_archive(nested, current_depth + 1, member_analyzer)
                nested_results.append({
                    'name': os.path.basename(nested),
                    'depth': current_depth + 1,
                    'result': nested_res,
                })
                lvl = nested_res.get('risk_level', 'BENIGNO')
                if _LEVEL_RANK.get(lvl, 0) > _LEVEL_RANK.get(results['risk_level'], 0):
                    results['risk_level'] = lvl
            except ZipBombDetectedError as e:
                nested_results.append({'name': os.path.basename(nested), 'error': str(e)})
                results['risk_level'] = 'CRÍTICO'
                results['suspicious_patterns'].append(f"ZIP_BOMB_ANIDADA: {e}")

        if nested_results:
            results['nested_analysis'] = nested_results

        # Alias de compatibilidad (risk_scoring lo consume)
        results['aggregated_risk'] = results['risk_level']

        results['files_analyzed'] = sum(
            1 for f in self._extracted_files if f.depth == current_depth
        ) or len(results.get('nested_archives', []))

    def analyze_archive(self, file_path: str, current_depth: int = 0,
                        member_analyzer: Optional[Callable[[str], Dict]] = None) -> Dict:
        if current_depth == 0:
            self._enter_ctx()
            self._password_protected_found = False
            self._extracted_files = []
            self._name_counter = 0
            for temp_dir in self._temp_dirs:
                shutil.rmtree(temp_dir, ignore_errors=True)
            self._temp_dirs = []

        ext = os.path.splitext(file_path)[1].lower()

        # FIX BUG #4: magic bytes tienen prioridad sobre la extensión.
        fmt = self._sniff_format(file_path)
        if fmt:
            ext = fmt
        elif ext not in self.SUPPORTED_EXTENSIONS:
            return {'error': f'Formato no soportado: {ext}', 'supported': False}

        if current_depth + self._base_level > self.limits.max_depth:
            return self._depth_exceeded_result({
                'type': 'ARCHIVE', 'format': ext.replace('.', ''),
                'depth': current_depth, 'files_analyzed': 0, 'total_size': 0,
                'is_password_protected': False, 'nested_archives': [],
                'extracted_files': [], 'suspicious_patterns': [],
            })

        results = {
            'type': 'ARCHIVE',
            'format': ext.replace('.', ''),
            'depth': current_depth,
            'files_analyzed': 0,
            'total_size': 0,
            'is_password_protected': False,
            'suspicious_patterns': [],
            'risk_level': 'BENIGNO',
            'nested_archives': [],
            'extracted_files': [],
        }

        try:
            if ext == '.zip':
                archive_results = self._analyze_zip(file_path, current_depth)
            elif ext == '.7z' and _PY7ZR_AVAILABLE:
                archive_results = self._analyze_7z(file_path, current_depth)
            elif ext == '.rar' and _RARFILE_AVAILABLE:
                archive_results = self._analyze_rar(file_path, current_depth)
            else:
                missing = []
                if ext == '.7z' and not _PY7ZR_AVAILABLE:
                    missing.append('py7zr')
                if ext == '.rar' and not _RARFILE_AVAILABLE:
                    missing.append('rarfile')
                return {
                    'error': f"Librería(s) requerida(s): {', '.join(missing)}. "
                             f"Instala: pip install {' '.join(missing)}",
                    'supported': False
                }

            results.update(archive_results)

            if results['is_password_protected'] and self.limits.password_protected_is_suspicious:
                results['suspicious_patterns'].append(
                    "Archivo protegido con contraseña - patrón de evasión"
                )
                if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                    results['risk_level'] = 'SOSPECHOSO'

            original_size = os.path.getsize(file_path)
            if original_size > 0:
                ratio = results['total_size'] / original_size
                _apply_ratio_heuristic(results, ratio)

            self._aggregate_members(results, current_depth, member_analyzer)

        except ZipBombDetectedError as e:
            declared = getattr(e, 'total_size', None)
            if declared is not None:
                results['total_size'] = declared
            results['error'] = str(e)
            results['risk_level'] = 'CRÍTICO'
            results['suspicious_patterns'].append(f"ZIP_BOMB: {e}")
            results['aggregated_risk'] = 'CRÍTICO'

        except (zipfile.BadZipFile, EOFError) as e:
            # FIX BUG C-1: analyze_archive() solo capturaba
            # ZipBombDetectedError. Un ZIP corrupto/truncado hace que
            # zipfile.BadZipFile (o EOFError al leerlo) se propague sin
            # manejar y crashee el CLI/GUI. Un contenedor corrupto es
            # además una señal a tener en cuenta (puede ser un intento
            # deliberado de romper el parser para evadir el análisis).
            results['error'] = f"Contenedor ZIP corrupto o malformado: {e}"
            results['suspicious_patterns'].append(f"CONTENEDOR_CORRUPTO: {e}")
            if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                results['risk_level'] = 'SOSPECHOSO'
            results['aggregated_risk'] = results['risk_level']

        except Exception as e:
            if getattr(e, '_pythreat_cancelled', False):
                raise
            # FIX BUG C-1 / C-2 (defensa en profundidad): py7zr y rarfile
            # lanzan sus propias excepciones (no siempre subclases
            # documentadas) ante 7z/RAR corruptos o malformados. En lugar
            # de dejar que cualquiera de ellas escale y crashee la
            # aplicación, se reporta como error de análisis y se marca el
            # archivo como sospechoso en vez de asumir que está limpio.
            results['error'] = f"Error analizando el contenedor ({type(e).__name__}): {e}"
            results['suspicious_patterns'].append(f"ERROR_ANALISIS_CONTENEDOR: {e}")
            if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                results['risk_level'] = 'SOSPECHOSO'
            results['aggregated_risk'] = results['risk_level']

        return results

    def _check_limits(self, file_size: int, file_count: int = 1):
        if self._ctx is not None:
            # R-02: contadores compartidos con los analizadores anidados.
            self._ctx.total_size += file_size
            self._ctx.file_count += file_count
            self._total_extracted_size = self._ctx.total_size
            self._file_count = self._ctx.file_count
        else:
            self._total_extracted_size += file_size
            self._file_count += file_count

        # K7: el tamaño declarado de ESTA capa viaja en la excepción; el dict
        # parcial de _analyze_* se pierde al propagarse, y sin esto el
        # reporte de una bomba quedaba con total_size == 0.
        if self._total_extracted_size > self.limits.max_total_size:
            err = ZipBombDetectedError(
                f"Tamaño total {self._total_extracted_size / 1e9:.2f}GB "
                f"excede límite {self.limits.max_total_size / 1e9:.2f}GB"
            )
            err.total_size = file_size
            raise err
        if self._file_count > self.limits.max_file_count:
            err = ZipBombDetectedError(
                f"Cantidad de archivos {self._file_count} excede límite "
                f"{self.limits.max_file_count}"
            )
            err.total_size = file_size
            raise err

    def _create_temp_dir(self) -> str:
        temp_dir = tempfile.mkdtemp(prefix='pta_archive_')
        self._temp_dirs.append(temp_dir)
        return temp_dir

    def _unique_name(self, depth: int, name: str) -> str:
        self._name_counter += 1
        return f"{depth}_{self._name_counter}_{name}"

    @staticmethod
    def _is_safe_path(name: str) -> bool:
        if not name:
            return False
        if '\x00' in name or name.startswith('/') or name.startswith('\\'):
            return False
        if ntpath.isabs(name) or re.match(r'^[A-Za-z]:', name):
            return False
        parts = name.replace('\\', '/').split('/')
        if any(p == '..' or ':' in p for p in parts):
            return False
        return True

    def _analyze_zip(self, file_path: str, depth: int) -> Dict:
        results = {'total_size': 0, 'is_password_protected': False,
                   'nested_archives': [], 'suspicious_patterns': [],
                   'risk_level': 'BENIGNO'}

        declared_count = zip_member_count_from_eocd(file_path)
        if declared_count is not None and declared_count > self.limits.max_file_count:
            raise ZipBombDetectedError(
                f"Cantidad de miembros declarada ({declared_count}) excede límite "
                f"{self.limits.max_file_count}"
            )

        with zipfile.ZipFile(file_path, 'r') as zf:
            infos = zf.infolist()
            for info in infos:
                if info.flag_bits & 0x1:
                    results['is_password_protected'] = True
                    self._password_protected_found = True
                    break

            total_uncompressed = sum(info.file_size for info in infos)
            results['total_size'] = total_uncompressed
            self._check_limits(total_uncompressed, len(infos))

            temp_dir = self._create_temp_dir()

            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size > self.limits.max_file_size:
                    # BUG-02: un miembro omitido por tamaño es cobertura perdida;
                    # no debe dejar el contenedor en BENIGNO sin aviso.
                    results['suspicious_patterns'].append(
                        f"ANALISIS_MIEMBRO_OMITIDO: {info.filename} (tamaño > límite)"
                    )
                    if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                        results['risk_level'] = 'SOSPECHOSO'
                    continue

                if not self._is_safe_path(info.filename):
                    results['suspicious_patterns'].append(
                        f"Ruta insegura en ZIP: {info.filename} (path traversal)"
                    )
                    # N-08 residual: un path traversal no debe dejar el
                    # contenedor en BENIGNO/SIN RIESGO pese a reportarse en
                    # warnings. Sube al menos a SOSPECHOSO.
                    if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                        results['risk_level'] = 'SOSPECHOSO'
                    continue

                safe_name = os.path.basename(info.filename.replace('\\', '/'))
                # N-02: NO saltar ficheros ocultos. Antes se descartaba todo
                # miembro cuyo basename empezara por '.', de modo que un
                # payload llamado '.payload.exe' (o 'dir/.payload.exe') nunca
                # se extraía ni analizaba (evasión). Solo se descartan nombres
                # vacíos y las entradas de navegación '.'/'..'.
                if not safe_name or safe_name in ('.', '..'):
                    continue

                try:
                    extracted_path = os.path.join(temp_dir, self._unique_name(depth, safe_name))
                    with zf.open(info) as src, open(extracted_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst, length=65536)

                    extracted = ExtractedFileInfo(
                        path=extracted_path,
                        name=info.filename,
                        size=info.file_size,
                        depth=depth,
                        parent_archive=file_path,
                        is_password_protected=bool(info.flag_bits & 0x1)
                    )
                    self._extracted_files.append(extracted)

                    if self._is_archive(extracted_path):
                        results['nested_archives'].append(extracted_path)

                except RuntimeError:
                    results['is_password_protected'] = True

        return results

    def _analyze_7z(self, file_path: str, depth: int) -> Dict:
        if not _PY7ZR_AVAILABLE:
            return {'error': 'py7zr no disponible'}

        results = {'total_size': 0, 'is_password_protected': False,
                   'nested_archives': [], 'suspicious_patterns': [],
                   'risk_level': 'BENIGNO'}

        with py7zr.SevenZipFile(file_path, mode='r') as sz:
            file_list = sz.list()
            # FIX BUG C-2: en un 7z malformado/truncado, py7zr puede
            # devolver entradas cuyo atributo `uncompressed` es None (no
            # siempre trae el tamaño real, p.ej. directorios o cabeceras
            # dañadas). sum() sobre esos valores lanzaba TypeError y
            # crasheaba el análisis. Se sustituye None por 0.
            total_size = sum((f.uncompressed or 0) for f in file_list)
            results['total_size'] = total_size
            self._check_limits(total_size, len(file_list))

            safe_targets = []
            for entry in file_list:
                if self._is_safe_path(entry.filename):
                    safe_targets.append(entry.filename)
                else:
                    results['suspicious_patterns'].append(
                        f"Ruta insegura en 7z: {entry.filename} (path traversal)"
                    )
                    # N-08 residual: ver _analyze_zip (ZIP).
                    if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                        results['risk_level'] = 'SOSPECHOSO'

            temp_dir = self._create_temp_dir()

            try:
                if safe_targets:
                    sz.extract(path=temp_dir, targets=safe_targets)
            except Exception as e:
                if e.__class__.__name__ == 'PasswordRequired':
                    results['is_password_protected'] = True
                    return results
                raise

            for root, _, files in os.walk(temp_dir):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    size = os.path.getsize(full_path)

                    extracted = ExtractedFileInfo(
                        path=full_path, name=rel_path, size=size,
                        depth=depth, parent_archive=file_path
                    )
                    self._extracted_files.append(extracted)

                    if self._is_archive(full_path):
                        results['nested_archives'].append(full_path)

        return results

    def _analyze_rar(self, file_path: str, depth: int) -> Dict:
        if not _RARFILE_AVAILABLE:
            return {'error': 'rarfile no disponible'}

        results = {'total_size': 0, 'is_password_protected': False,
                   'nested_archives': [], 'suspicious_patterns': [],
                   'risk_level': 'BENIGNO'}

        with rarfile.RarFile(file_path, 'r') as rf:
            infos = rf.infolist()
            for info in infos:
                if info.needs_password():
                    results['is_password_protected'] = True
                    break

            total_size = sum(f.file_size for f in infos)
            results['total_size'] = total_size
            self._check_limits(total_size, len(infos))

            temp_dir = self._create_temp_dir()

            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size > self.limits.max_file_size:
                    # BUG-02: un miembro omitido por tamaño es cobertura perdida;
                    # no debe dejar el contenedor en BENIGNO sin aviso.
                    results['suspicious_patterns'].append(
                        f"ANALISIS_MIEMBRO_OMITIDO: {info.filename} (tamaño > límite)"
                    )
                    if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                        results['risk_level'] = 'SOSPECHOSO'
                    continue

                if not self._is_safe_path(info.filename):
                    results['suspicious_patterns'].append(
                        f"Ruta insegura en RAR: {info.filename} (path traversal)"
                    )
                    # N-08 residual: ver _analyze_zip (ZIP).
                    if _LEVEL_RANK.get(results['risk_level'], 0) < _LEVEL_RANK['SOSPECHOSO']:
                        results['risk_level'] = 'SOSPECHOSO'
                    continue

                if info.needs_password():
                    continue

                try:
                    # Copiar el stream del miembro a un nombre generado localmente.
                    # No delegar la ruta del archivo a rarfile y evitar colisiones
                    # cuando el contenedor repite nombres.
                    safe_name = os.path.basename(info.filename.replace('\\', '/')) or 'member'
                    extracted_path = os.path.join(temp_dir, self._unique_name(depth, safe_name))
                    with rf.open(info) as source, open(extracted_path, 'wb') as destination:
                        shutil.copyfileobj(source, destination, length=65536)

                    extracted = ExtractedFileInfo(
                        path=extracted_path, name=info.filename,
                        size=info.file_size, depth=depth,
                        parent_archive=file_path,
                        is_password_protected=info.needs_password()
                    )
                    self._extracted_files.append(extracted)

                    if self._is_archive(extracted_path):
                        results['nested_archives'].append(extracted_path)

                except Exception as e:
                    if getattr(e, '_pythreat_cancelled', False):
                        raise
                    if e.__class__.__name__ in ('PasswordRequired', 'RarWrongPassword'):
                        results['is_password_protected'] = True
                    else:
                        results['suspicious_patterns'].append(
                            f"ERROR_ANALISIS_MIEMBRO_RAR: {info.filename}: {e}"
                        )
                        # Un miembro incompleto es sospechoso, pero no debe
                        # impedir inspeccionar el resto del contenedor.
                        results['risk_level'] = 'SOSPECHOSO'

        return results

    def _is_archive(self, file_path: str) -> bool:
        """Indica si se debe recursar el contenedor extraído.

        OOXML (DOCX/XLSX/PPTX), JAR y APK usan ZIP como formato físico,
        pero deben pasar como miembros al analizador de archivos para que,
        por ejemplo, el analizador de documentos pueda extraer macros. Si se
        recursan como ZIP genérico, cada XML/recurso se somete al pipeline
        completo y el documento nunca llega a document_analyzer.
        """
        fmt = self._sniff_format(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        if fmt == '.zip':
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    structured_type = classify_structured_zip_names(
                        info.filename for info in zf.infolist()
                    )
                if structured_type:
                    return False
            except (OSError, zipfile.BadZipFile, EOFError):
                # Un ZIP inválido sigue tratándose como archivo comprimido
                # para que analyze_archive reporte el error estructural.
                pass
            return True
        if fmt:
            return True
        return ext in self.SUPPORTED_EXTENSIONS

    def get_extracted_files(self) -> List[ExtractedFileInfo]:
        return self._extracted_files

    def cleanup(self):
        for temp_dir in self._temp_dirs:
            shutil.rmtree(temp_dir, ignore_errors=True)
        self._extracted_files.clear()
        self._temp_dirs.clear()
        self._total_extracted_size = 0
        self._file_count = 0


def analyze_compressed_file(
    file_path: str,
    recursive: bool = True,
    member_analyzer: Optional[Callable[[str], Dict]] = None,
    limits: Optional[ArchiveLimits] = None,
    current_depth: int = 0,
) -> Dict:
    """Función de alto nivel. La recursión sobre anidados y la aplicación de
    member_analyzer viven DENTRO de analyze_archive (fuente única): un miembro
    nunca se analiza dos veces y los límites anti-zip-bomb son acumulativos.

    - recursive=False: deshabilita member_analyzer (solo estructura).
    - current_depth: expuesto para quien integre esta función como
      member_analyzer de otro ArchiveAnalyzer (evita ciclos).
    """
    effective_limits = limits or ArchiveLimits()
    if current_depth > effective_limits.max_depth:
        return {'error': 'Profundidad máxima excedida', 'risk_level': 'ALTO'}

    with ArchiveAnalyzer(effective_limits) as analyzer:
        return analyzer.analyze_archive(
            file_path,
            current_depth=current_depth,
            member_analyzer=member_analyzer if recursive else None,
        )


def analyze_structured_zip(file_path: str,
                           limits: Optional[ArchiveLimits] = None,
                           zip_infos=None,
                           member_analyzer: Optional[Callable[[str], Dict]] = None,
                           recursive: bool = True) -> Dict:
    """Preflight anti-zip-bomb a OOXML/JAR/APK y análisis de sus miembros.

    El preflight consulta solo el directorio central (tamaños, ratio,
    contraseña). Si se recibe member_analyzer, además se extraen y analizan
    los miembros con las mismas protecciones que un ZIP normal: antes solo se
    hacía preflight y un payload con hash conocido oculto en un JAR/OOXML/docx
    quedaba SIN RIESGO (evasión N-01).
    """
    limits = limits or ArchiveLimits()
    with ArchiveAnalyzer(limits) as analyzer:
        return analyzer.analyze_structured(
            file_path,
            zip_infos=zip_infos,
            member_analyzer=member_analyzer if recursive else None,
        )

        
