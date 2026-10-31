"""
Utilidades compartidas. Sirve para evitar el bug de tratar archivos binarios
(videos, imágenes, ejecutables, etc.) como si fueran texto/script, lo cual
generaba falsos positivos masivos (bytes aleatorios "coincidiendo" con
patrones de ofuscación) y desperdiciaba tiempo leyendo archivos enormes.
"""

import os
import struct

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MiB compartidos por los analizadores
SAMPLE_CHUNK_SIZE = 2 * 1024 * 1024      # 2 MiB por región muestreada
MAX_ZIP_MEMBER_COUNT = 10000


def zip_member_count_from_eocd(file_path):
    """Lee el conteo declarado del directorio ZIP sin construir ZipInfo.

    zipfile.ZipFile carga todos los registros centrales durante su creación,
    antes de que la aplicación pueda aplicar max_file_count. El lector
    estándar _EndRecData solo inspecciona el final del archivo e incluye el
    caso ZIP64. Si la estructura no se reconoce, devuelve None y el parser
    normal conserva la responsabilidad de reportar el contenedor malformado.
    """
    try:
        with open(file_path, 'rb') as stream:
            stream.seek(0, os.SEEK_END)
            file_size = stream.tell()
            tail_size = min(file_size, 22 + 65535)
            stream.seek(file_size - tail_size)
            tail = stream.read(tail_size)
            end_offset = tail.rfind(b'PK\x05\x06')
            while end_offset >= 0:
                if end_offset + 22 <= len(tail):
                    comment_size = struct.unpack_from('<H', tail, end_offset + 20)[0]
                    if end_offset + 22 + comment_size <= len(tail):
                        count = struct.unpack_from('<H', tail, end_offset + 10)[0]
                        if count != 0xFFFF:
                            return count

                        # ZIP64 locator immediately precedes the classic EOCD.
                        locator_offset = end_offset - 20
                        if locator_offset >= 0 and tail[locator_offset:locator_offset + 4] == b'PK\x06\x07':
                            zip64_record_offset = struct.unpack_from('<Q', tail, locator_offset + 8)[0]
                            if zip64_record_offset > file_size - 56:
                                return count
                            stream.seek(zip64_record_offset)
                            zip64_record = stream.read(56)
                            if len(zip64_record) >= 56 and zip64_record[:4] == b'PK\x06\x06':
                                return struct.unpack_from('<Q', zip64_record, 32)[0]
                        # El sentinel ya excede el límite normal del analizador;
                        # devolverlo fuerza la ruta de rechazo conservadora.
                        return count
                end_offset = tail.rfind(b'PK\x05\x06', 0, end_offset)
        return None
    except (OSError, EOFError, IndexError, TypeError, ValueError):
        return None


def collect_analysis_warnings(reputation=None, yara_results=None, document_results=None,
                              archive_results=None, static_analysis=None,
                              behavior_analysis=None, entropy_windows=None,
                              script_results=None):
    """Resume cobertura incompleta para que un análisis parcial no parezca limpio."""
    warnings = []
    for name, state in ((reputation or {}).get('database_status') or {}).items():
        # La allowlist reduce falsos positivos, pero no aumenta la capacidad
        # de detección de malware. Su ausencia no significa análisis parcial.
        if name == 'known_good_hashes':
            continue
        if state.get('status') not in ('ready', 'disabled'):
            reason = state.get('error') or state.get('status', 'unavailable')
            warnings.append(f"Base de reputación '{name}' incompleta: {reason}")
    if (reputation or {}).get('ssdeep_skipped'):
        warnings.append((reputation or {}).get('ssdeep_note', 'ssdeep omitido por tamaño'))
    if isinstance(yara_results, dict):
        if yara_results.get('error'):
            warnings.append(f"Cobertura YARA incompleta: {yara_results['error']}")
        elif yara_results.get('rules_skipped'):
            warnings.append(
                f"Cobertura YARA parcial: {yara_results['rules_skipped']} regla(s) omitida(s)"
            )
    if isinstance(document_results, dict):
        if document_results.get('error'):
            warnings.append(f"Análisis de documento incompleto: {document_results['error']}")
        if document_results.get('truncated'):
            warnings.append("Análisis de documento truncado por límite de tamaño")
    if isinstance(static_analysis, dict):
        if static_analysis.get('error'):
            warnings.append(f"Análisis estático incompleto: {static_analysis['error']}")
        if static_analysis.get('truncated'):
            warnings.append("Análisis estático truncado")
    if isinstance(archive_results, dict):
        # N-08: los fallos/parcialidades del contenedor tampoco llegaban
        # antes al resumen; un ZIP corrupto o con miembros omitidos podía
        # parecer un análisis limpio y COMPLETE.
        if archive_results.get('error'):
            warnings.append(f"Análisis de contenedor incompleto: {archive_results['error']}")
        for pattern in archive_results.get('suspicious_patterns') or []:
            p = str(pattern)
            if p.startswith(('ANALISIS_MIEMBRO_INCOMPLETO:',
                             'ANALISIS_MIEMBRO_OMITIDO:',
                             'ERROR_ANALISIS_MIEMBRO_RAR:',
                             'CONTENEDOR_CORRUPTO:',
                             'ERROR_ANALISIS_CONTENEDOR:',
                             'ZIP_BOMB', 'Ruta insegura')):
                warnings.append(p)
    if isinstance(behavior_analysis, dict):
        if behavior_analysis.get('truncated'):
            warnings.append("Análisis de comportamiento truncado por límite de tamaño")
        if behavior_analysis.get('sampled'):
            warnings.append("Análisis de comportamiento por muestreo (archivo grande)")
    if isinstance(entropy_windows, dict) and entropy_windows.get('sampled'):
        warnings.append("Análisis de entropía por muestreo (archivo grande)")
    lim = (reputation or {}).get('fuzzy_scan_limited') if isinstance(reputation, dict) else None
    if lim:
        warnings.append(
            f"Coincidencia difusa limitada a {lim.get('limit')} referencias "
            f"(TLSH: {lim.get('tlsh_refs')}, ssdeep: {lim.get('ssdeep_refs')}); "
            f"las restantes no se compararon")
    # R-06: la capa AST falló por una causa que NO es "no es Python"
    # (RecursionError, MemoryError, ValueError): el script quedó sin analizar.
    ast_res = (script_results or {}).get('ast_analysis') if isinstance(script_results, dict) else None
    if isinstance(ast_res, dict) and ast_res.get('incomplete'):
        warnings.append(f"Análisis AST de script incompleto: {ast_res.get('error')}")
    return warnings


def coverage_gap_messages(malware_hash_status=None, known_bad_count=None,
                          yara_rule_count=None, tlsh_status=None,
                          ssdeep_status=None, nsrl_status=None,
                          known_good_status=None):
    """K8: avisos de arranque/primer escaneo cuando falta cobertura de detección.

    config_loader valida tipos pero no presencia de datos: sin una denylist
    SHA-256 o sin reglas YARA, la herramienta arranca "bien" y el
    usuario solo descubre la falta de cobertura tras el primer escaneo.
    `malware_hash_status` es database_status['malware_hashes']['status'] de
    check_reputation(); `known_bad_count` permite avisar en el arranque (donde
    aún no hay reputación). Devuelve una lista (vacía si todo está cargado).
    """
    messages = []
    if malware_hash_status in ('unavailable', 'empty') or known_bad_count == 0:
        messages.append(
            "Base SHA-256 de amenazas vacía o no disponible: "
            "sin detección por hash conocido.")
    if yara_rule_count == 0:
        messages.append(
            "Sin reglas YARA cargadas (yara_rules/): sin detección por firmas YARA.")
    if tlsh_status in ('unavailable', 'empty'):
        messages.append(
            "Base TLSH vacía o no disponible (malware_tlsh.txt): sin comparación TLSH.")
    if ssdeep_status in ('unavailable', 'empty'):
        messages.append(
            "Base ssdeep vacía o no disponible (malware_ssdeep.txt): sin comparación ssdeep.")
    if (nsrl_status in ('disabled', 'unavailable', 'empty') and
            known_good_status in ('disabled', 'unavailable', 'empty', None)):
        messages.append(
            "Allowlist NSRL no configurada o no disponible: aumentan los falsos positivos "
            "en software legítimo. Descarga y configura el RDSv3 con "
            "NSRL_DOWNLOAD_DATE=YYYY-MM-DD ./setup-data.sh /ruta/al/RDS.sqlite.")
    return messages


def classify_structured_zip_names(names):
    """Devuelve APK, OOXML o JAR según nombres del directorio central ZIP."""
    if names is None:
        return None
    names = set(names)
    if 'AndroidManifest.xml' in names and any(
        name == 'classes.dex' or
        (name.startswith('classes') and name.endswith('.dex'))
        for name in names
    ):
        return 'APK'
    if '[Content_Types].xml' in names and any(
        name.startswith(('word/', 'xl/', 'ppt/')) for name in names
    ):
        return 'OOXML'
    if 'META-INF/MANIFEST.MF' in names:
        return 'JAR'
    return None

TEXT_SCRIPT_EXTENSIONS = {
    '.py', '.ps1', '.psm1', '.psd1', '.js', '.vbs', '.vbe', '.bat', '.cmd',
    '.sh', '.bash', '.php', '.rb', '.pl', '.txt', '.md', '.json', '.xml',
    '.html', '.htm', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.hta',
    '.wsf', '.au3', '.jse',
}

# Extensiones que sabemos que NO son texto (evita incluso leer una muestra)
KNOWN_BINARY_EXTENSIONS = {
    '.mkv', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.ogg',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.iso',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.exe', '.dll', '.sys', '.bin', '.so', '.o',
}


def looks_like_text(file_path, sample_size=4096):
    """Heurística: si una muestra del archivo es mayormente imprimible, se trata como texto."""
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
    except OSError:
        return False
    if not sample:
        return True
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return (printable / len(sample)) > 0.85


TEXT_FILE_TYPES = {'TEXT', 'PYTHON_SCRIPT', 'SHELL_SCRIPT', 'POWERSHELL', 'JAVASCRIPT'}


def is_analyzable_as_text(file_path, file_type=None):
    """Decide si vale la pena correr analizadores de texto (script/IA) sobre este archivo."""
    file_type_name = getattr(file_type, 'name', file_type)
    if file_type_name in TEXT_FILE_TYPES:
        return True
    ext = os.path.splitext(file_path)[1].lower()
    if ext in KNOWN_BINARY_EXTENSIONS:
        return False
    if ext in TEXT_SCRIPT_EXTENSIONS:
        return True
    return looks_like_text(file_path)


# N-04: extensiones que son CÓDIGO ejecutable (no datos). El analizador de
# scripts aplica regex de "eval/exec/subprocess/red/persistencia": sobre
# prosa o datos (Markdown, TXT, JSON, XML...) generaba falsos positivos
# masivos (p.ej. doc.md puntuaba ALTO por una URL y la palabra "cron").
SCRIPT_CODE_EXTENSIONS = {
    '.py', '.ps1', '.psm1', '.psd1', '.js', '.vbs', '.vbe', '.bat', '.cmd',
    '.sh', '.bash', '.php', '.rb', '.pl', '.hta', '.wsf', '.au3', '.jse',
}

SCRIPT_CODE_TYPES = {'PYTHON_SCRIPT', 'SHELL_SCRIPT', 'POWERSHELL', 'JAVASCRIPT'}


def is_script_code(file_path, file_type=None):
    """True solo para código/scripts, no para texto de datos (N-04).

    Mantiene `is_analyzable_as_text` para la detección de prompts de IA (que
    sí aplica a documentos), pero el analizador de scripts solo debe correr
    sobre código real.
    """
    file_type_name = getattr(file_type, 'name', file_type)
    if file_type_name in SCRIPT_CODE_TYPES:
        return True
    ext = os.path.splitext(file_path)[1].lower()
    if ext in KNOWN_BINARY_EXTENSIONS:
        return False
    if ext in SCRIPT_CODE_EXTENSIONS:
        return True
    # Scripts sin extensión (p.ej. /usr/bin/systemd-analyze visto como texto):
    # se aceptan si parecen texto y no son un tipo conocido de datos.
    return looks_like_text(file_path) and file_type_name not in ('TEXT', 'PDF')


# Contenedores donde una entropía cercana a 8.0 es NORMAL y esperada por
# diseño (ya vienen comprimidos/codificados): video, audio, imágenes,
# archivos comprimidos, y formatos Office modernos (que internamente son
# ZIP). Se EXCLUYEN a propósito extensiones de ejecutables (.exe/.dll/.sys)
# — ahí la entropía alta SÍ sigue siendo una señal legítima de empaquetado
# o cifrado malicioso, no se debe suprimir para esos casos.
# N-11: ampliar el set. Faltaban formatos habituales también comprimidos/
# codificados por diseño (varios contenedores de vídeo/audio, imágenes con
# compresión interna, suites de Office con macros que siguen siendo ZIP,
# formatos LibreOffice, e-books y archivos comprimidos menos comunes).
HIGH_ENTROPY_EXPECTED_EXTENSIONS = {
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v',
    '.mpg', '.mpeg', '.mts', '.m2ts', '.ts', '.3gp', '.ogv',
    '.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac', '.opus',
    '.wma', '.m4b', '.aif', '.aiff', '.oga',
    '.jpg', '.jpeg', '.jfif', '.png', '.gif', '.bmp', '.webp', '.ico',
    '.heic', '.jxl', '.avif', '.jp2', '.j2k', '.svgz',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz',
    '.txz', '.tlz', '.lzma', '.lz4', '.zst', '.zstd', '.iso', '.cab',
    '.deb', '.rpm', '.dmg',
    '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm',
    '.odt', '.ods', '.odp', '.odg', '.odf',
    '.epub', '.cbz', '.cbr',
    '.apk', '.jar',             # también contenedores ZIP
    '.pdf',                     # suele comprimir sus streams internos
}

# FIX (limpieza de código muerto): esta función estaba definida DOS VECES
# en este archivo. La primera definición (con su propio set local
# "compressed_extensions", incompleto: le faltaban .apk/.jar/.heic/.opus/
# etc. respecto a HIGH_ENTROPY_EXPECTED_EXTENSIONS) quedaba completamente
# sombreada por la segunda -Python se queda solo con la última- así que
# nunca se ejecutaba: no causaba un bug en tiempo de ejecución hoy, pero
# era una trampa de mantenimiento (quien editara "la de arriba" pensando
# que es la vigente no vería ningún efecto). Se deja una sola versión,
# la que realmente se usa en producción y que consume el set completo
# HIGH_ENTROPY_EXPECTED_EXTENSIONS declarado arriba.
# Firmas de ejecutables/scripts que NUNCA deben tratarse como "formato comprimido
# por diseño" aunque la extensión diga lo contrario (N-11 residual).
_EXECUTABLE_MAGICS = (
    b'MZ', b'\x7fELF', b'#!',
    b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe',
    b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce',
)


def _looks_executable_by_magic(file_path):
    """True si la cabecera real es la de un ejecutable (PE/ELF/Mach-O) o un
    script con shebang. Falla en silencio (False) si no se puede leer."""
    try:
        with open(file_path, 'rb') as f:
            head = f.read(4)
    except OSError:
        return False
    return any(head.startswith(m) for m in _EXECUTABLE_MAGICS)


def is_high_entropy_expected(file_path):
    """True si el formato del archivo ya es comprimido/codificado por
    diseño, y por lo tanto una entropía alta NO debe tratarse como señal
    de empaquetado/cifrado malicioso (a diferencia de un .exe/.dll, donde
    sí lo es).

    N-11 residual: la decisión se apoya en la extensión, que el autor controla.
    Renombrar un .exe/.elf/script a .zip/.jpg/.mp4 suprimía las señales de
    entropía, strings y comportamiento. Ahora, si la cabecera real es la de un
    ejecutable o un script con shebang, la extensión NO concede esa exención."""
    if not file_path:
        return False
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in HIGH_ENTROPY_EXPECTED_EXTENSIONS:
        return False
    return not _looks_executable_by_magic(file_path)
