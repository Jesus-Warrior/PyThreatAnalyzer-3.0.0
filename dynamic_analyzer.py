r"""
Simulación de comportamiento — 100% ESTÁTICA. CERO ejecución.

Esta versión reemplaza por completo el enfoque anterior (bwrap/firejail/
Windows Sandbox), que SÍ llegó a ejecutar binarios de forma contenida y
verificada. Se elimina esa capacidad a propósito, por dos razones dadas
explícitamente por el usuario:

  1. Restricción dura: "nunca importar subprocess/os.system/eval/exec sobre
     el contenido del archivo analizado". Ninguna cantidad de banderas de
     contención (--network none, --cap-drop ALL, namespaces...) cambia el
     hecho de que una llamada a subprocess.run(cmd_que_incluye_el_archivo)
     sigue siendo "ejecutar el archivo". No hay forma de cumplir esa regla
     y seguir ejecutando código, así que se prioriza la regla.
  2. Instrucción explícita: "si no es posible hacerlo seguro, eliminarlo".

Este módulo GARANTIZA no-ejecución de una forma verificable: no importa
subprocess, no usa os.system/os.popen/os.exec*, no usa eval/exec/compile.
Puedes confirmarlo tú mismo (y el test suite lo hace automáticamente):

    grep -E "subprocess|os\.system|os\.popen|os\.exec|eval\(|exec\(" dynamic_analyzer.py

No debería devolver ninguna coincidencia real de uso (solo puede aparecer
dentro de strings/comentarios como este).

Lo que SÍ hace: lee los bytes del archivo (solo lectura) y busca patrones
—strings, imports de PE, palabras clave— que APROXIMAN qué haría el
archivo si se ejecutara, sin ejecutarlo nunca. Es la misma técnica que ya
usan extract_strings()/check_polyglot() en virus_analyzer.py, pero aquí
extendida a categorías más específicas de "comportamiento" (persistencia,
anti-análisis, operaciones de archivo) para dar una aproximación más rica
sin cruzar la línea de ejecutar nada.

Si en el futuro se quiere análisis dinámico REAL (ejecución observada),
la recomendación es usar una herramienta externa dedicada y ya validada
por la comunidad de seguridad —Cuckoo Sandbox, CAPE, or ANY.RUN/
Hybrid Analysis/Triage como servicios— corriendo en una VM completamente
separada de esta aplicación, nunca invocada desde ella.
"""

import codecs
import hashlib
import os
import re
from urllib.parse import urlparse

try:
    import pefile
except ImportError:
    pefile = None

from analysis_utils import is_high_entropy_expected, is_script_code, looks_like_text
from file_type_detector import FileTypeDetector

# Límite de lectura para no cargar archivos gigantes en memoria por completo.
MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB

_PERSISTENCE_PATTERNS = [
    r'\\run\\', r'\\runonce\\', r'\bstartup\b', r'currentversion\\run',
    r'scheduled task', r'\bcron\b', r'\bcrontab\b', r'\bsystemd\b',
    r'HKLM\\', r'HKCU\\', r'reg\s+add', r'\bregistry\b',
    r'/etc/rc', r'/etc/init\.d', r'\.bashrc', r'\.profile',
]
_PERSISTENCE_REGEXES = tuple(
    (pattern, re.compile(pattern, re.IGNORECASE))
    for pattern in _PERSISTENCE_PATTERNS
)
_MAX_PERSISTENCE_PATTERN_LENGTH = max(len(pattern) for pattern in _PERSISTENCE_PATTERNS)
_PERSISTENCE_OVERLAP = _MAX_PERSISTENCE_PATTERN_LENGTH + 8

# Nota de diseño: se excluyó 'IsProcessorFeaturePresent' de esta lista (a
# diferencia del borrador original) porque es una API de detección de
# características de CPU usada rutinariamente por el runtime de C/C++ de
# CASI cualquier binario legítimo (inicialización estándar de MSVCRT) — 
# incluirla generaba falsos positivos sistemáticos, justo lo que la
# prioridad #2 (whitelist/reducción de FPs) busca evitar.
_ANTI_ANALYSIS_KEYWORDS = [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtGlobalFlag',
    'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
    'SbieDll', 'sandboxie', 'cuckoo', 'wireshark', 'process monitor',
]

_FILE_OP_PATTERNS = [
    r'CreateFile', r'WriteFile', r'DeleteFile', r'CopyFile', r'MoveFile',
    r'\.exe\b', r'\.dll\b', r'\.bat\b', r'\.ps1\b',
    r'\bAppData\b', r'\bTemp\b', r'\bRoaming\b', r'\bProgramData\b',
]


# R-01: patrones de "dropper" de alta confianza. Los IOC sueltos (URL,
# 'cron', 'systemd') siguen siendo de baja confianza en ELF y scripts, pero
# una CADENA de descarga + ejecución (wget|curl ... | sh, chmod +x tras
# descargar, base64 -d | sh) es una señal estructural, no vocabulario
# genérico. Se evalúa línea a línea sobre los strings extraídos.
_RE_DOWNLOAD = re.compile(
    r'\b(?:wget|curl|tftp|ftpget)\b[^|;&]*(?:https?|ftp)://'
    r'|\b(?:wget|curl|tftp|ftpget)\b[^|;&]*\b\d{1,3}(?:\.\d{1,3}){3}\b',
    re.IGNORECASE)
_RE_PIPE_SHELL = re.compile(
    r'\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh\b', re.IGNORECASE)
_RE_CHMOD_EXEC = re.compile(
    r'\bchmod\s+(?:-[a-zA-Z]+\s+)?(?:[ugoa]*\+[rw]*x|[0-7]?[1357][0-7]{2})\b')
_RE_B64_PIPE_SHELL = re.compile(
    r'base64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:ba)?sh\b', re.IGNORECASE)
_RE_LOG_WIPE = re.compile(
    r'\brm\s+-[a-z]*[rf][a-z]*\s+(?:-[a-z]+\s+)?/var/log\b'
    r'|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*/var/log/\S+',
    re.IGNORECASE)
_RE_BUSYBOX = re.compile(r'/bin/busybox\s+[A-Za-z]{3,}', re.IGNORECASE)

# Puntos por patrón. Los "fuertes" activan el hallazgo; los "débiles" solo
# suman si hay al menos uno fuerte (por sí solos son comunes en scripts
# legítimos de administración).
_DROPPER_STRONG = {'DOWNLOAD_PIPE_SHELL': 25, 'DOWNLOAD_CHMOD_EXEC': 20,
                   'BASE64_PIPE_SHELL': 20}
_DROPPER_WEAK = {'LOG_WIPE': 10, 'BUSYBOX_BOT': 10}


_PE_TYPE_NAMES = ('PE32', 'PE64', 'DLL')
_NETWORK_CONTEXT_RE = re.compile(
    r'\b(?:post|user-agent|authorization|cookie)\b', re.IGNORECASE)


class DynamicAnalyzer:
    """A pesar del nombre (se conserva por compatibilidad con el resto de
    la app), esta clase NUNCA ejecuta el archivo. Solo lo lee."""

    def __init__(self, max_read_bytes=MAX_READ_BYTES):
        self.max_read_bytes = max_read_bytes

    def analyze(self, file_path, file_type=None):
        """Punto de entrada único. Determinista, de solo lectura, sin
        subprocess/eval/exec en ningún punto del flujo."""
        file_path = os.path.abspath(file_path)
        if file_type is None:
            file_type = FileTypeDetector.detect(file_path)
        file_type = getattr(file_type, 'name', file_type)

        if not os.path.exists(file_path):
            return {'error': 'Archivo no existe', 'executed': False}

        try:
            with open(file_path, 'rb') as f:
                data = f.read(self.max_read_bytes)
        except OSError as e:
            return {'error': f'No se pudo leer el archivo: {e}', 'executed': False}

        strings = self._extract_strings(data)
        # N-04: los IOCs por substring (red/persistencia/anti-análisis) son
        # señales débiles y generaban falsos positivos sistemáticos en:
        #   - texto/scripts (p.ej. doc.md, la stdlib platform.py), donde
        #     palabras genéricas como "systemd"/"cron"/una URL en un comentario
        #     no indican intención;
        #   - binarios ELF del sistema (p.ej. systemd-analyze), donde cadenas
        #     sueltas coinciden con el propio nombre de la herramienta.
        # Se marcan de baja confianza para que risk_scoring no las puntúe. La
        # detección real de scripts la cubre script_analyzer y la de PE los
        # imports/YARA/hash, que sí son señales estructurales.
        low_confidence = (
            is_high_entropy_expected(file_path)
            or looks_like_text(file_path)
            or str(file_type).upper() == 'ELF'
        )

        # R-01: en ELF y scripts los IOC sueltos son de baja confianza, pero
        # las cadenas de descarga+ejecución no. Texto de datos (md/txt/html)
        # queda fuera: ahí 'curl ... | sh' es documentación.
        if str(file_type).upper() == 'ELF' or is_script_code(file_path, file_type):
            dropper_indicators = self._detect_dropper_patterns(strings)
        else:
            dropper_indicators = []

        network_indicators = self._extract_network_iocs(strings)
        network_low_confidence = []
        if str(file_type).upper() in _PE_TYPE_NAMES:
            network_indicators, network_low_confidence = self._apply_pe_network_context(
                network_indicators, strings)

        results = {
            'file': file_path,
            # K5: antes 'file_hash' (ambiguo: parecía el hash del archivo). Es el
            # SHA-256 de lo LEÍDO (hasta max_read_bytes), no del archivo entero.
            'sample_sha256': self._hash_prefix(data),
            'executed': False,  # Invariante: SIEMPRE False. No hay ninguna
                                 # rama de código en este módulo que pueda
                                 # ponerlo en True.
            'truncated': len(data) >= self.max_read_bytes,
            'low_confidence_container': low_confidence,
            'dropper_indicators': dropper_indicators,
            'network_indicators': network_indicators,
            'network_indicators_low_confidence': network_low_confidence,
            'persistence_indicators': self._detect_persistence_bytes(data),
            'anti_analysis_indicators': self._detect_anti_analysis(strings),
            'file_op_indicators': self._detect_file_ops(strings),
            'pe_imports': self._analyze_pe_imports(file_path, file_type) if pefile else [],
            'note': ("Análisis 100% estático: aproxima comportamiento a partir de "
                     "strings/imports embebidos. El archivo NUNCA se ejecuta."
                     + (" ⚠️ Este formato (contenedor comprimido/codificado, "
                        "texto/script o binario ELF) hace que coincidencias de "
                        "substrings cortos puedan ocurrir por puro azar o por "
                        "vocabulario genérico. Estos indicadores tienen BAJA "
                        "CONFIANZA y no se ponderan en el score de riesgo." if low_confidence else "")),
        }
        return results

    def _hash_prefix(self, data):
        # Hash solo de lo leído (puede ser una muestra si el archivo es
        # gigante); no reemplaza el SHA256 completo que ya calcula
        # StaticAnalyzer.get_file_hashes() sobre el archivo entero.
        return hashlib.sha256(data).hexdigest()

    def _extract_strings(self, data, min_length=4):
        strings = []
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        strings.extend(m.decode('ascii', errors='ignore') for m in re.findall(ascii_pattern, data))

        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        for m in re.findall(unicode_pattern, data):
            try:
                strings.append(m.decode('utf-16le', errors='ignore'))
            except UnicodeDecodeError:
                continue

        # N-15: orden determinista. list(set(...)) dependía de PYTHONHASHSEED,
        # por lo que el orden de los strings (y con él los primeros N IOCs
        # reportados o las coincidencias de red/archivo) variaba entre
        # ejecuciones del mismo archivo.
        return sorted(set(strings))

    def _detect_dropper_patterns(self, strings):
        """R-01: detecta cadenas descarga+ejecución en los strings (sin ejecutar).

        Devuelve [{'id': ..., 'points': n}]; vacío si no hay ningún patrón
        fuerte. Prefiltro por subcadena para no aplicar regex a millones de
        strings de un binario grande."""
        flags = set()
        for raw in strings:
            s = raw[:2000]
            low = s.lower()
            if 'wget' in low or 'curl' in low or 'tftp' in low or 'ftpget' in low:
                if _RE_DOWNLOAD.search(s):
                    flags.add('download')
                    if _RE_PIPE_SHELL.search(s):
                        flags.add('pipe_shell')
            if 'chmod' in low and _RE_CHMOD_EXEC.search(s):
                flags.add('chmod_exec')
            if 'base64' in low and _RE_B64_PIPE_SHELL.search(s):
                flags.add('b64_pipe_shell')
            if ('/var/log' in low or 'history' in low or 'histfile' in low) \
                    and _RE_LOG_WIPE.search(s):
                flags.add('log_wipe')
            if 'busybox' in low and _RE_BUSYBOX.search(s):
                flags.add('busybox')

        found = []
        if 'pipe_shell' in flags:
            found.append('DOWNLOAD_PIPE_SHELL')
        if 'download' in flags and 'chmod_exec' in flags:
            found.append('DOWNLOAD_CHMOD_EXEC')
        if 'b64_pipe_shell' in flags:
            found.append('BASE64_PIPE_SHELL')
        if not found:
            return []
        if 'log_wipe' in flags:
            found.append('LOG_WIPE')
        if 'busybox' in flags:
            found.append('BUSYBOX_BOT')
        weights = {**_DROPPER_STRONG, **_DROPPER_WEAK}
        return [{'id': name, 'points': weights[name]} for name in found]

    def _extract_network_iocs(self, strings):
        iocs = []
        url_re = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_re = re.compile(
            r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        # Bug corregido (falso positivo confirmado): el patrón original
        # aceptaba UN SOLO carácter antes del TLD ("8.Tk", "C.ml" fueron
        # coincidencias reales reportadas sobre datos binarios de video).
        # Exigir 3+ caracteres alfanuméricos reduce drásticamente las
        # coincidencias aleatorias sin perder dominios reales como
        # "videolan.org".
        domain_re = re.compile(
            r'\b[a-zA-Z0-9-]{3,}\.(?:com|net|org|info|xyz|tk|ml|ga|top|club|online)\b', re.IGNORECASE)

        seen = set()
        for s in strings:
            for pattern, ioc_type in ((url_re, 'url'), (ip_re, 'ip'), (domain_re, 'domain')):
                m = pattern.search(s)
                if m and m.group(0) not in seen:
                    seen.add(m.group(0))
                    iocs.append({'type': ioc_type, 'value': m.group(0)})
        return iocs[:50]

    @staticmethod
    def _ioc_host_key(ioc):
        """Clave de host (dominio registrable aprox. o IP) de un IOC de red."""
        value = ioc.get('value', '')
        if ioc.get('type') == 'url':
            host = (urlparse(value).hostname or '').lower()
        else:
            host = value.lower()
        if ioc.get('type') == 'ip' or re.fullmatch(r'[\d.]+', host or ''):
            return host
        labels = [label for label in host.split('.') if label]
        return '.'.join(labels[-2:]) if len(labels) >= 2 else host

    def _apply_pe_network_context(self, iocs, strings):
        """K6 (F.3): filtro de contexto para IOCs de red en PE.

        Casi todo PE lleva una URL suelta (xmlns del manifiesto, URL de
        certificado o de soporte) y low_confidence_container no cubre PE. Un
        IOC de red solo puntúa si (a) hay >= 2 HOSTS distintos (url y dominio
        de una misma cadena cuentan como uno; si no, 'http://schemas.
        microsoft.com/...' ya serían 2), o (b) aparece en la misma cadena que
        un marcador de comunicación (POST, User-Agent, Authorization,
        Cookie). Devuelve (conservados, de_baja_confianza).
        """
        if not iocs:
            return [], []
        if len({self._ioc_host_key(ioc) for ioc in iocs}) >= 2:
            return iocs, []
        kept, dropped = [], []
        for ioc in iocs:
            in_context = any(
                ioc['value'] in text and _NETWORK_CONTEXT_RE.search(text)
                for text in strings
            )
            (kept if in_context else dropped).append(ioc)
        return kept, dropped

    def _detect_persistence(self, text):
        findings = []
        for pattern in _PERSISTENCE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(f"Referencia a persistencia: {pattern}")
        return findings

    def _detect_persistence_bytes(self, data, chunk_size=256 * 1024):
        """Busca IOCs por bloques para no crear otro string de hasta 10 MiB."""
        decoder = codecs.getincrementaldecoder('utf-8')(errors='ignore')
        tail = ''
        found = set()
        for offset in range(0, len(data), chunk_size):
            decoded = decoder.decode(data[offset:offset + chunk_size])
            window = tail + decoded
            safe_start = max(0, len(tail) - _MAX_PERSISTENCE_PATTERN_LENGTH)
            for pattern, regex in _PERSISTENCE_REGEXES:
                if pattern in found:
                    continue
                if any(match.start() >= safe_start for match in regex.finditer(window)):
                    found.add(pattern)
            tail = window[-_PERSISTENCE_OVERLAP:]

        final_text = decoder.decode(b'', final=True)
        if final_text:
            window = tail + final_text
            safe_start = max(0, len(tail) - _MAX_PERSISTENCE_PATTERN_LENGTH)
            for pattern, regex in _PERSISTENCE_REGEXES:
                if pattern not in found and any(
                    match.start() >= safe_start for match in regex.finditer(window)
                ):
                    found.add(pattern)

        return [f"Referencia a persistencia: {pattern}"
                for pattern in _PERSISTENCE_PATTERNS if pattern in found]

    def _detect_anti_analysis(self, strings):
        findings = []
        # Nota de diseño: aquí se usa substring simple (sin anclas de
        # límite de palabra) a propósito. Se probó con \b...\b y con
        # lookbehind negativo, y ambos rompían la detección real de
        # patrones legítimos como "VMwareService.exe" o "VBoxTray.exe"
        # (el sufijo pegado sin separador, o un carácter alfanumérico
        # adyacente por puro azar en datos binarios, hacía fallar el ancla).
        # La supresión de falsos positivos en archivos multimedia/comprimidos
        # NO depende de este regex — la maneja por completo el flag
        # low_confidence_container (ver analyze() y risk_scoring.py), que
        # excluye estas señales del score para ese tipo de contenedores
        # sin importar qué tan flexible sea la coincidencia aquí.
        lowered = [s.lower() for s in strings]
        for indicator in _ANTI_ANALYSIS_KEYWORDS:
            if any(indicator.lower() in s for s in lowered):
                findings.append(f"Posible anti-análisis: {indicator}")
        return findings

    def _detect_file_ops(self, strings):
        findings = []
        for op in _FILE_OP_PATTERNS:
            if any(re.search(op, s, re.IGNORECASE) for s in strings):
                findings.append(f"Referencia a operación de archivo: {op}")
        return findings

    def _analyze_pe_imports(self, file_path, file_type=None):
        """Solo lectura de la tabla de imports (parsing de estructura PE,
        no ejecución). El tipo real evita depender de una extensión confiable."""
        if file_type is None:
            file_type = FileTypeDetector.detect(file_path)
        file_type = getattr(file_type, 'name', file_type)
        if not (file_type in {'PE32', 'PE64', 'DLL'} and pefile):
            return []
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        if func.name:
                            imports.append(func.name.decode('utf-8', errors='ignore'))
            pe.close()
            return imports
        except Exception:
            return []
