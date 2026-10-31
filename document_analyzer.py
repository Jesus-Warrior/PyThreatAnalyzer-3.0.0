"""
Amplía la cobertura más allá de PE/ELF: analiza documentos ofimáticos
(macros VBA) y PDFs (JavaScript embebido, auto-ejecución), que antes caían
en 'UNKNOWN' y prácticamente no se analizaban.
"""

import os
import re
import struct
from file_type_detector import FileTypeDetector, RealFileType

try:
    from oletools.olevba import VBA_Parser
    _OLETOOLS_AVAILABLE = True
except ImportError:
    _OLETOOLS_AVAILABLE = False


OFFICE_EXTENSIONS = {'.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx',
                      '.ppt', '.pptm', '.pptx', '.rtf'}
PDF_EXTENSIONS = {'.pdf'}
MAX_PDF_READ_SIZE = 50 * 1024 * 1024  # 50 MiB por análisis
MAX_OFFICE_ANALYSIS_SIZE = 100 * 1024 * 1024  # límite para VBA_Parser

# Palabras clave de VBA frecuentemente usadas en macros maliciosas
VBA_SUSPICIOUS_KEYWORDS = [
    'Shell', 'WScript.Shell', 'CreateObject', 'Environ(', 'PowerShell',
    'AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open',
    'Chr(', 'StrReverse', 'Base64', 'URLDownloadToFile', 'ADODB.Stream',
]

# Pares (nombre, regex, descripción, contextual).
# Los nombres PDF se delimitan con lookahead: '/JS' no debe coincidir con
# '/JSON' ni '/AA' con '/AAAAAA+Arial' (etiqueta de fuente) ni con 3 bytes al
# azar dentro de un stream binario. Los marcadores `contextual` (hoy solo
# /OpenAction, habitual en PDFs de LaTeX/hyperref y Acrobat para fijar la vista
# inicial) solo cuentan si coexisten con contenido ACTIVO.
_PDF_NAME_END = rb'(?![A-Za-z0-9_.#+\-])'
PDF_SUSPICIOUS_MARKERS = [
    ('/JavaScript', rb'/JavaScript' + _PDF_NAME_END, 'Contiene JavaScript embebido', False),
    ('/JS', rb'/JS' + _PDF_NAME_END, 'Contiene JavaScript embebido (marcador /JS)', False),
    ('/OpenAction', rb'/OpenAction' + _PDF_NAME_END,
     'Tiene una acción de apertura automática (/OpenAction) junto a contenido activo', True),
    ('/AA', rb'/AA(?=\s*(?:<<|\d))', 'Tiene acciones automáticas asociadas (/AA)', False),
    ('/Launch', rb'/Launch' + _PDF_NAME_END,
     'Contiene una acción /Launch (ejecución de programa externo)', False),
    ('/EmbeddedFile', rb'/EmbeddedFile' + _PDF_NAME_END, 'Contiene archivos embebidos', False),
    ('/RichMedia', rb'/RichMedia' + _PDF_NAME_END,
     'Contiene contenido RichMedia (Flash/vectores de exploit históricos)', False),
]
# Marcadores que hacen relevante a un /OpenAction.
_PDF_ACTIVE_CONTENT = ('/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/RichMedia')


# B4: tope de candidatos validados por firma (los streams Flate son aleatorios
# y 'MZ' aparece por azar cada ~64 KiB; se acota el coste, no la detección:
# basta con encontrar UNA firma válida por tipo).
_MAX_SIGNATURE_CANDIDATES = 2000


def _valid_pe_at(data, offset):
    """'MZ' solo cuenta si e_lfanew apunta a una firma 'PE\\0\\0' real."""
    if offset + 0x40 > len(data):
        return False
    e_lfanew = struct.unpack_from('<I', data, offset + 0x3C)[0]
    if not 0x40 <= e_lfanew <= 0x1000:
        return False
    pe_at = offset + e_lfanew
    return data[pe_at:pe_at + 4] == b'PE\x00\x00'


def _valid_elf_at(data, offset):
    # EI_CLASS (1=32b, 2=64b) y EI_DATA (1=LE, 2=BE) válidos.
    return (offset + 6 <= len(data)
            and data[offset + 4] in (1, 2) and data[offset + 5] in (1, 2))


def _valid_zip_local_header_at(data, offset):
    # Cabecera local: versión necesaria <= 100, longitud de nombre 1..1024.
    if offset + 30 > len(data):
        return False
    version = struct.unpack_from('<H', data, offset + 4)[0]
    name_len = struct.unpack_from('<H', data, offset + 26)[0]
    return version <= 100 and 1 <= name_len <= 1024


_EMBEDDED_SIGNATURES = (
    (b'MZ', _valid_pe_at, 'ejecutable PE'),
    (b'\x7fELF', _valid_elf_at, 'ejecutable ELF'),
    (b'PK\x03\x04', _valid_zip_local_header_at, 'ZIP'),
)


def find_embedded_signatures(data):
    """Devuelve [(descripcion, offset)] con la primera firma VÁLIDA (offset>0)
    de cada tipo. Offset 0 se ignora: ahí el archivo no sería un PDF."""
    found = []
    for magic, validator, label in _EMBEDDED_SIGNATURES:
        position = data.find(magic, 1)
        checked = 0
        while position != -1 and checked < _MAX_SIGNATURE_CANDIDATES:
            checked += 1
            if validator(data, position):
                found.append((label, position))
                break
            position = data.find(magic, position + 1)
    return found


class DocumentAnalyzer:
    @staticmethod
    def _document_kind(file_path, file_type=None):
        ext = os.path.splitext(file_path)[1].lower()
        if ext in OFFICE_EXTENSIONS:
            return 'office'
        if ext in PDF_EXTENSIONS:
            return 'pdf'
        if file_type is None:
            file_type = FileTypeDetector.detect(file_path)
        file_type_name = getattr(file_type, 'name', file_type)
        if file_type_name in ('OOXML', 'OLE2'):
            return 'office'
        if file_type_name == 'PDF':
            return 'pdf'
        return None

    def is_supported(self, file_path, file_type=None):
        return self._document_kind(file_path, file_type) is not None

    def analyze(self, file_path, file_type=None):
        kind = self._document_kind(file_path, file_type)
        if kind == 'office':
            return self._analyze_office(file_path)
        if kind == 'pdf':
            return self._analyze_pdf(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        return {'error': f'Extensión no soportada por DocumentAnalyzer: {ext}'}

    # ---------- Office (macros VBA vía oletools) ----------
    def _analyze_office(self, file_path):
        results = {'type': 'OFFICE', 'has_macros': False, 'suspicious': [], 'macro_keywords': []}

        if not _OLETOOLS_AVAILABLE:
            results['error'] = "oletools no está instalado (pip install oletools)"
            return results

        try:
            office_size = os.path.getsize(file_path)
        except OSError as exc:
            results['error'] = f"No se pudo leer el tamaño del documento: {exc}"
            return results
        if office_size > MAX_OFFICE_ANALYSIS_SIZE:
            results['error'] = (
                f"Análisis de macros omitido: documento supera el límite de "
                f"{MAX_OFFICE_ANALYSIS_SIZE} bytes"
            )
            results['truncated'] = True
            return results

        # Bug corregido (resource leak): si VBA_Parser() se creaba pero
        # extract_macros() lanzaba una excepción, el flujo saltaba
        # directo al except externo y vba_parser.close() NUNCA se
        # ejecutaba, dejando el handle del archivo abierto. Ahora
        # vba_parser se inicializa antes del try y se cierra siempre en
        # el finally, pase lo que pase.
        vba_parser = None
        try:
            vba_parser = VBA_Parser(file_path)
            results['has_macros'] = vba_parser.detect_vba_macros()

            if results['has_macros']:
                found_keywords = set()
                try:
                    for (_filename, _stream_path, _vba_filename, vba_code) in vba_parser.extract_macros():
                        if not vba_code:
                            continue
                        for kw in VBA_SUSPICIOUS_KEYWORDS:
                            if kw.lower() in vba_code.lower():
                                found_keywords.add(kw)
                except Exception as e:
                    # Distingue "hay macros pero no se pudieron extraer" de
                    # un fallo total del parser (que cae al except externo).
                    results['macro_extraction_error'] = str(e)

                results['macro_keywords'] = sorted(found_keywords)
                if found_keywords:
                    results['suspicious'].append(
                        f"Macro contiene {len(found_keywords)} palabra(s) clave sospechosa(s): "
                        + ', '.join(sorted(found_keywords)))

                auto_exec = {'AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open'} & found_keywords
                if auto_exec:
                    results['suspicious'].append(f"Macro con auto-ejecución al abrir: {', '.join(auto_exec)}")

        except Exception as e:
            results['error'] = str(e)
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass  # No dejamos que un error al cerrar oculte el resultado ya obtenido

        return results

    # ---------- PDF (marcadores sospechosos, sin dependencias pesadas) ----------
    def _analyze_pdf(self, file_path):
        results = {'type': 'PDF', 'suspicious': [], 'markers_found': [], 'truncated': False}

        try:
            with open(file_path, 'rb') as f:
                data = f.read(MAX_PDF_READ_SIZE + 1)
        except OSError as e:
            results['error'] = str(e)
            return results

        if len(data) > MAX_PDF_READ_SIZE:
            data = data[:MAX_PDF_READ_SIZE]
            results['truncated'] = True
            results['analysis_note'] = (
                f"Análisis parcial: se inspeccionaron los primeros {MAX_PDF_READ_SIZE} "
                "bytes por el límite de lectura."
            )

        counts = {name: len(re.findall(rx, data)) for name, rx, _d, _c in PDF_SUSPICIOUS_MARKERS}
        has_active = any(counts.get(n, 0) > 0 for n in _PDF_ACTIVE_CONTENT)
        for name, _rx, description, contextual in PDF_SUSPICIOUS_MARKERS:
            count = counts[name]
            if count <= 0:
                continue
            results['markers_found'].append({'marker': name, 'count': count})
            if contextual and not has_active:
                continue  # informativo: queda en markers_found, no puntúa
            results['suspicious'].append(f"{description} ({count} vez/veces)")

        # B4: un PE/ELF/ZIP con firma válida dentro de un PDF (sin pasar por
        # /EmbeddedFile) es una señal de payload oculto. Esto NO se mide con
        # la entropía: .pdf está exento de ella por diseño (streams Flate).
        for _label, offset in find_embedded_signatures(data):
            results['suspicious'].append(
                f"PDF contiene firma de ejecutable/ZIP embebido (offset {offset})")

        # JavaScript ofuscado con eval/unescape es una señal clásica de exploit kits en PDF
        if re.search(rb'eval\s*\(', data) or re.search(rb'unescape\s*\(', data):
            results['suspicious'].append("JavaScript con eval()/unescape() (patrón de ofuscación/exploit)")

        return results
