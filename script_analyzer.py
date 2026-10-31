"""
Analizador de scripts. Combina:
  - Detección por patrones (regex), rápida y agnóstica al lenguaje.
  - Análisis AST específico de Python (más preciso que regex).
  - Detección de cmdlets sospechosos en PowerShell.

Antes esto estaba duplicado en dos clases (ScriptAnalyzer / AdvancedScriptAnalyzer)
que main.py nunca combinaba realmente. Ahora es una sola clase con un único
punto de entrada: analyze_script().
"""

import ast
import base64
import binascii
import codecs
import os
import re
from file_type_detector import FileTypeDetector

MAX_SCRIPT_READ_SIZE = 10 * 1024 * 1024  # bytes por análisis

# B3: candidatos a blob base64 con límites estrictos (no es un trozo de un
# token más largo). Se valida además decodificándolo (ver _has_suspicious_base64).
_BASE64_BLOB_RE = re.compile(
    r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/])')
_HEX_ONLY_RE = re.compile(r'[0-9a-fA-F]+')
_MAX_BASE64_CANDIDATES = 100


def _decode_bounded_script(raw):
    """Decodifica un bloque acotado respetando BOM comunes de texto."""
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding, alignment = 'utf-32', 4
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding, alignment = 'utf-16', 2
    elif raw.startswith(codecs.BOM_UTF8):
        encoding, alignment = 'utf-8-sig', 1
    else:
        encoding, alignment = 'utf-8', 1
    if alignment > 1 and len(raw) % alignment:
        raw = raw[:len(raw) - (len(raw) % alignment)]
    return raw.decode(encoding, errors='ignore')


class ScriptAnalyzer:
    SUSPICIOUS_PATTERNS = {
        'obfuscation': [
            r'eval\s*\(', r'exec\s*\(', r'base64\.b64decode',
            r'__import__\s*\(', r'(?<![.\w])compile\s*\(', r'bytes\.fromhex',
        ],
        'network': [
            r'requests\.get\s*\(', r'urllib\.request',
            r'socket\.', r'http\.client', r'ftp\.',
        ],
        'system': [
            r'os\.system\s*\(', r'subprocess\.', r'Popen\s*\(',
            r'os\.popen', r'os\.startfile',
        ],
        'persistence': [
            r'schedule\.', r'\bcron\b', r'task\s*create',
            r'Add-MpPreference', r'reg\s*add',
        ],
        'encoding': [
            r'base64', r'hex\(', r'ord\(', r'chr\(', r'str\.encode',
        ],
    }

    # B1: `from sys import exit` / `from os import fork` son importaciones de
    # uso corriente en CLIs y utilidades legítimas; antes sumaban +2 cada una
    # (tope +10 vía SCRIPT_SUSPICIOUS_IMPORT) y, junto a otras señales débiles,
    # podían escalar un script benigno a MEDIO. Ahora solo se REPORTAN como
    # nota (results['informational_imports']) y no puntúan.
    INFORMATIONAL_IMPORTS = {
        'sys': ['exit'],
        'os': ['fork', 'spawn'],
    }

    DANGEROUS_IMPORTS = {
        'os': ['system', 'popen', 'exec'],
        'subprocess': ['call', 'run', 'Popen', 'check_output'],
        'socket': ['socket', 'connect', 'send'],
        'requests': ['get', 'post', 'put', 'delete'],
        'urllib': ['urlopen', 'Request'],
        'base64': ['b64decode', 'b32decode', 'b16decode'],
        'codecs': ['decode'],
        'marshal': ['loads'],
        'pickle': ['loads'],
        'ctypes': ['CDLL', 'windll', 'oledll'],
        'sys': ['_exit', 'modules'],
    }
    # R-04: marcadores PowerShell con límites de palabra. Antes eran subcadenas:
    # '-enc' coincidía con '-Encoding' y 'invoke-webrequest' bastaba por sí
    # solo, de modo que un script administrativo benigno puntuaba MEDIO.
    # FUERTES: ejecución dinámica, ofuscación o evasión; siempre cuentan.
    POWERSHELL_STRONG_MARKERS = [
        ('invoke-expression/iex', r'(?<![\w-])(?:invoke-expression|iex)(?![\w-])'),
        ('downloadstring', r'downloadstring'),
        ('net.webclient', r'net\.webclient'),
        ('frombase64string', r'frombase64string'),
        ('encodedcommand', r'(?<![\w-])-(?:e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{16,}'),
        ('executionpolicy bypass', r'(?<![\w-])-(?:executionpolicy|ep)\s+bypass\b'),
        ('windowstyle hidden', r'(?<![\w-])-w(?:indowstyle)?\s+hidden\b'),
        ('noprofile', r'(?<![\w-])-nop(?:rofile)?(?![\w-])'),
    ]
    # DÉBILES: de uso corriente en administración; solo suman si ya hay al
    # menos un marcador fuerte.
    POWERSHELL_WEAK_MARKERS = [
        ('invoke-webrequest', r'invoke-webrequest'),
        ('downloadfile', r'downloadfile'),
        ('get-wmiobject', r'get-wmiobject'),
        ('get-ciminstance', r'get-ciminstance'),
        ('convertfrom-securestring', r'convertfrom-securestring'),
    ]

    # N-03 (restante): marcadores de droppers JS/VBS/HTA (Windows Script Host
    # / ActiveX). Se buscan como substring en minúsculas + un par de regex
    # tolerantes a espacios (eval(unescape(...))).
    #
    # N-03 residual: '.run(' y '.exec(' se ELIMINARON porque producían FPs en
    # JS legítimo (RegExp.prototype.exec es trivial; '.run(' aparece en
    # runtimes de test y métodos comunes). 'WScript.Shell.Run'/'Shell.Run'
    # siguen cubiertos por los marcadores 'wscript.shell'/'shell.application'.
    JS_VBS_SUSPICIOUS = [
        'activexobject', 'wscript.shell', 'wsh.shell', 'new function(',
        'createobject("wscript.shell', 'createobject("shell.application',
        'createobject("scripting.filesystemobject',
        'regread(', 'mshta',
    ]
    # R-04: PowerShell lanzado desde un script WSH con evasión/descarga.
    WSH_POWERSHELL_LAUNCH = re.compile(
        r'\bpowershell(?:\.exe)?\b[^\n]{0,300}?'
        r'(?:(?<![\w-])-(?:e|ec|enc|encodedcommand)\s+\S{16,}'
        r'|(?<![\w-])-w(?:indowstyle)?\s+hidden'
        r'|(?<![\w-])(?:iex|invoke-expression)(?![\w-])'
        r'|downloadstring)', re.IGNORECASE)

    # ---------- Punto de entrada único ----------
    def analyze_script(self, file_path, file_type=None):
        """Elige estrategia por tipo real y usa la extensión como compatibilidad."""
        ext = os.path.splitext(file_path)[1].lower()
        if file_type is None:
            file_type = FileTypeDetector.detect(file_path)
        file_type_name = getattr(file_type, 'name', file_type)

        try:
            with open(file_path, 'rb') as f:
                raw = f.read(MAX_SCRIPT_READ_SIZE + 1)
        except OSError as e:
            return {'error': f'No se pudo leer el archivo: {e}'}

        truncated = len(raw) > MAX_SCRIPT_READ_SIZE
        if truncated:
            raw = raw[:MAX_SCRIPT_READ_SIZE]
        content = _decode_bounded_script(raw)
        del raw

        results = self._analyze_patterns(content)

        if ext == '.py' or file_type_name == 'PYTHON_SCRIPT':
            ast_results = self._analyze_python_ast(content)
            results['ast_analysis'] = ast_results
            results['total_risk_score'] += ast_results.get('obfuscation_score', 0)
        elif ext in ('.ps1', '.psm1', '.psd1') or file_type_name == 'POWERSHELL':
            ps_results = self._analyze_powershell(content)
            results['powershell_analysis'] = ps_results
            results['total_risk_score'] += len(ps_results['suspicious']) * 2
        elif (ext in ('.js', '.vbs', '.vbe', '.jse', '.hta', '.wsf', '.au3')
              or file_type_name == 'JAVASCRIPT'):
            # N-03 (restante): JS/VBS no tenían consumidores en risk_scoring.
            # Un .js con ActiveXObject + eval(unescape()) puntuaba BAJO pese a
            # ser una descarga/ejecución clásica de dropper. Esta rama
            # alimenta web_script_analysis, que risk_scoring ahora consume.
            web_results = self._analyze_js_vbs(content)
            results['web_script_analysis'] = web_results
            results['total_risk_score'] += len(web_results['suspicious']) * 2

        results['risk_level'] = self._score_to_level(results['total_risk_score'])
        results['truncated'] = truncated
        if truncated:
            results['analysis_note'] = (
                f"Análisis parcial: se inspeccionaron los primeros {MAX_SCRIPT_READ_SIZE} "
                "bytes por el límite de lectura."
            )
        return results

    # ---------- Análisis por patrones (cualquier lenguaje) ----------
    def _analyze_patterns(self, content):
        results = {}
        total_risk = 0
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            matches = []
            for pattern in patterns:
                matches.extend(re.findall(pattern, content, re.IGNORECASE))
            results[category] = {'count': len(matches), 'matches': matches[:5]}
            total_risk += len(matches) * 2
        results['total_risk_score'] = total_risk
        return results

    # ---------- Análisis AST específico de Python ----------
    def _analyze_python_ast(self, code):
        results = {
            'suspicious_calls': [], 'obfuscation_score': 0,
            'network_ops': {}, 'file_ops': [], 'dynamic_exec': [], 'imports': [],
            'informational_imports': [],
        }
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
            # N-06: ast.parse puede lanzar RecursionError (expresiones muy
            # anidadas) o ValueError (bytes NUL en Python <3.12), no solo
            # SyntaxError. Antes esas excepciones escapaban y abortaban el
            # lote completo de un scan-directorio.
            results['error'] = f"No es un script Python válido ({type(e).__name__})"
            # R-06: un SyntaxError es un archivo que simplemente no es Python
            # (normal en .py de otras versiones); RecursionError/MemoryError/
            # ValueError son un fallo del ANÁLISIS y dejan la capa AST ciega.
            # Se marca para que analysis_status lo refleje.
            if not isinstance(e, SyntaxError):
                results['incomplete'] = True
            return results

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                # N-04: importar módulos ubicuos (os, sys, subprocess, socket)
                # NO es sospechoso por sí solo; marcarlo generaba falsos
                # positivos masivos en código legítimo (p.ej. la stdlib). Solo
                # se marcan los USOS concretos peligrosos (rama siguiente).
                for alias in node.names:
                    results['imports'].append(alias.name)

            elif isinstance(node, ast.ImportFrom) and (
                    node.module in self.DANGEROUS_IMPORTS
                    or node.module in self.INFORMATIONAL_IMPORTS):
                for alias in node.names:
                    if alias.name in self.DANGEROUS_IMPORTS.get(node.module, ()):
                        results['suspicious_calls'].append(f"Uso crítico: {node.module}.{alias.name}")
                    elif alias.name in self.INFORMATIONAL_IMPORTS.get(node.module, ()):
                        results['informational_imports'].append(f"{node.module}.{alias.name}")

            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec', 'compile'):
                    results['dynamic_exec'].append({'function': node.func.id, 'line': node.lineno})
                    results['obfuscation_score'] += 5
                elif isinstance(node.func, ast.Attribute) and node.func.attr in ('system', 'popen', 'urlopen'):
                    results['suspicious_calls'].append(f"Llamada a {node.func.attr} en línea {node.lineno}")

        results['obfuscation_score'] += self._check_obfuscation_patterns(code)
        results['network_ops'] = self._extract_network_patterns(code)
        results['file_ops'] = self._extract_file_operations(code)
        return results

    @staticmethod
    def _has_suspicious_base64(code):
        """B3: un blob base64 solo es sospechoso si decodifica a datos binarios.

        El regex antiguo sumaba +3 con cualquier racha de 100+ caracteres
        alfanuméricos: JWT, data-URI, hashes hex, identificadores largos. Aquí
        se exige (1) que no sea un comentario de línea completa, (2) que no sea
        puro hexadecimal (digests), (3) que sea base64 válido y (4) que lo
        decodificado contenga bytes > 0x7F (un ejecutable/blob comprimido o
        cifrado; un JWT o un JSON codificado decodifican a ASCII).
        """
        for index, match in enumerate(_BASE64_BLOB_RE.finditer(code)):
            if index >= _MAX_BASE64_CANDIDATES:
                break
            line_start = code.rfind('\n', 0, match.start()) + 1
            if code[line_start:match.start()].lstrip().startswith('#'):
                continue
            blob = match.group(0).rstrip('=')
            if _HEX_ONLY_RE.fullmatch(blob):
                continue
            try:
                decoded = base64.b64decode(blob + '=' * (-len(blob) % 4))
            except (binascii.Error, ValueError):
                continue
            if any(byte > 0x7F for byte in decoded):
                return True
        return False

    def _check_obfuscation_patterns(self, code):
        score = 0
        if re.search(r'\\x[0-9a-fA-F]{2}', code):
            score += 2
        if self._has_suspicious_base64(code):
            score += 3
        if re.search(r'\\u[0-9a-fA-F]{4}', code):
            score += 2
        if len(re.findall(r'["\']\s*\+\s*["\']', code)) > 10:
            score += 2
        return score

    def _extract_network_patterns(self, code):
        # Bug corregido: el regex de dominios tenía un grupo de captura, así que
        # re.findall devolvía solo el TLD capturado (ej. "com") en vez del dominio
        # completo. Se cambió a grupo no-capturante (?:...) para devolver el match completo.
        return {
            'urls': re.findall(r'https?://[^\s"\']+', code),
            'ips': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', code),
            'domains': re.findall(r'\b[a-zA-Z0-9-]+\.(?:com|net|org|info|xyz|tk|ml|ga)\b', code),
        }

    def _extract_file_operations(self, code):
        patterns = [r'open\s*\([^)]*[\'"]w[\'"]', r'\.write\s*\(', r'makedirs\s*\(', r'rename\s*\(', r'remove\s*\(']
        matches = []
        for pattern in patterns:
            matches.extend(re.findall(pattern, code))
        return matches

    # ---------- PowerShell ----------
    def _analyze_powershell(self, content):
        results = {'suspicious': []}
        strong = [label for label, rx in self.POWERSHELL_STRONG_MARKERS
                  if re.search(rx, content, re.IGNORECASE)]
        for label in strong:
            if label == 'encodedcommand':
                results['suspicious'].append("Comando codificado detectado")
            else:
                results['suspicious'].append(f"Cmdlet/parámetro sospechoso: {label}")
        if strong:
            for label, rx in self.POWERSHELL_WEAK_MARKERS:
                if re.search(rx, content, re.IGNORECASE):
                    results['suspicious'].append(f"Cmdlet/parámetro sospechoso: {label}")
        return results

    # ---------- JS/VBS/HTA (Windows Script Host) ----------
    def _analyze_js_vbs(self, content):
        content_lower = content.lower()
        results = {'suspicious': []}
        for marker in self.JS_VBS_SUSPICIOUS:
            if marker in content_lower:
                results['suspicious'].append(f"Marcador WSH/ActiveX: {marker}")
        if self.WSH_POWERSHELL_LAUNCH.search(content):
            results['suspicious'].append(
                "Marcador WSH/ActiveX: PowerShell con evasión/descarga lanzado desde script"
            )
        if re.search(r'\beval\s*\(\s*unescape\s*\(', content, re.IGNORECASE):
            results['suspicious'].append(
                "Marcador WSH/ActiveX: eval(unescape()) (ofuscación)"
            )
        return results

    @staticmethod
    def _score_to_level(score):
        if score >= 20:
            return 'CRÍTICO'
        if score >= 10:
            return 'ALTO'
        if score >= 5:
            return 'MEDIO'
        return 'BAJO'
