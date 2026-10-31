# file_type_detector.py


"""
Detector de tipos de archivo por magic bytes - NUNCA confía en extensiones.

FIX BUG #3: en MAGIC_PATTERNS el patrón corto b'Rar!' iba antes que el de
RAR5, así que TODOS los RAR5 se clasificaban como RAR (la firma de RAR5,
'Rar!\x1a\x07\x01\x00', empieza igual que la de RAR4). Además, el patrón
RAR5 original era b'Rar\x1a\x07\x01\x00' (sin el '!'), por lo que nunca
matcheaba un RAR5 real. Ahora:
  - RAR5 (firma completa de 8 bytes) se evalúa ANTES que RAR4.
  - RAR4 usa su firma completa b'Rar!\x1a\x07\x00' (no el prefijo genérico).
"""

import struct
import os
import zipfile
from enum import Enum, auto
from typing import Optional, Tuple
from analysis_utils import (
    MAX_ZIP_MEMBER_COUNT, classify_structured_zip_names,
    zip_member_count_from_eocd,
)


class RealFileType(Enum):
    UNKNOWN = auto()
    PE32 = auto()
    PE64 = auto()
    DLL = auto()
    ELF = auto()
    MACH_O = auto()
    ZIP = auto()
    GZIP = auto()
    BZIP2 = auto()
    XZ = auto()
    TAR = auto()
    RAR = auto()
    RAR5 = auto()
    SEVEN_ZIP = auto()
    PDF = auto()
    OLE2 = auto()
    OOXML = auto()
    MP4 = auto()
    MKV = auto()
    AVI = auto()
    MP3 = auto()
    FLAC = auto()
    PNG = auto()
    JPEG = auto()
    GIF = auto()
    BMP = auto()
    WEBP = auto()
    ICO = auto()
    JAR = auto()
    APK = auto()
    PYTHON_SCRIPT = auto()
    SHELL_SCRIPT = auto()
    POWERSHELL = auto()
    JAVASCRIPT = auto()
    TEXT = auto()
    BINARY = auto()


class FileTypeDetector:
    MAGIC_PATTERNS = [
        (0, b'MZ', RealFileType.PE32),
        (0, b'\x7fELF', RealFileType.ELF),
        (0, b'\xcf\xfa\xed\xfe', RealFileType.MACH_O),
        (0, b'\xfe\xed\xfa\xcf', RealFileType.MACH_O),
        # N-14 residual: Mach-O de 32 bits (LE/BE). El binario universal ("fat",
        # CAFEBABE) se resuelve aparte porque comparte magic con .class de Java.
        (0, b'\xce\xfa\xed\xfe', RealFileType.MACH_O),
        (0, b'\xfe\xed\xfa\xce', RealFileType.MACH_O),
        (0, b'RIFF', RealFileType.WEBP),
        (0, b'RIFF', RealFileType.AVI),
        (0, b'PK\x03\x04', RealFileType.ZIP),
        (0, b'PK\x05\x06', RealFileType.ZIP),
        # FIX BUG #3: RAR5 (firma más larga/específica) DEBE ir antes que RAR4.
        (0, b'Rar!\x1a\x07\x01\x00', RealFileType.RAR5),
        (0, b'Rar!\x1a\x07\x00', RealFileType.RAR),
        (0, b'7z\xbc\xaf\x27\x1c', RealFileType.SEVEN_ZIP),
        (0, b'\x1f\x8b', RealFileType.GZIP),
        (0, b'BZh', RealFileType.BZIP2),
        (0, b'\xfd7zXZ', RealFileType.XZ),
        (257, b'ustar\x00', RealFileType.TAR),
        (257, b'ustar\x20\x20\x00', RealFileType.TAR),
        (0, b'%PDF-', RealFileType.PDF),
        (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', RealFileType.OLE2),
        (4, b'ftyp', RealFileType.MP4),
        (0, b'\x1aE\xdf\xa3', RealFileType.MKV),
        (0, b'ID3', RealFileType.MP3),
        (0, b'\xff\xfb', RealFileType.MP3),
        (0, b'\xff\xf3', RealFileType.MP3),
        (0, b'fLaC', RealFileType.FLAC),
        (0, b'\x89PNG\x0d\x0a\x1a\x0a', RealFileType.PNG),
        (0, b'\xff\xd8\xff', RealFileType.JPEG),
        (0, b'GIF87a', RealFileType.GIF),
        (0, b'GIF89a', RealFileType.GIF),
        (0, b'BM', RealFileType.BMP),
        (0, b'\x00\x00\x01\x00', RealFileType.ICO),
        (0, b'\x00\x00\x02\x00', RealFileType.ICO),
    ]

    MP4_VALID_BRANDS = {
        b'isom', b'iso2', b'mp41', b'mp42', b'M4V ', b'M4A ',
        b'avc1', b'qt  ', b'3gp4', b'3gp5', b'3g2a', b'mjp2',
        b'mp71', b'MSNV', b'dby1'
    }

    ENTROPY_PROFILES = {
        RealFileType.PE32: (5.0, 7.2, "PE32 sin empaquetar"),
        RealFileType.PE64: (5.0, 7.2, "PE64 sin empaquetar"),
        RealFileType.DLL: (5.0, 7.2, "DLL sin empaquetar"),
        RealFileType.ELF: (4.5, 7.0, "ELF"),
        RealFileType.ZIP: (7.5, 8.0, "ZIP (ya comprimido)"),
        RealFileType.SEVEN_ZIP: (7.5, 8.0, "7z"),
        RealFileType.RAR: (7.5, 8.0, "RAR"),
        RealFileType.RAR5: (7.5, 8.0, "RAR5"),
        RealFileType.MP4: (7.0, 7.9, "MP4"),
        RealFileType.MKV: (7.0, 7.9, "MKV"),
        RealFileType.MP3: (7.0, 7.9, "MP3"),
        RealFileType.FLAC: (7.0, 7.9, "FLAC"),
        RealFileType.PNG: (7.0, 7.9, "PNG"),
        RealFileType.JPEG: (6.5, 7.8, "JPEG"),
        RealFileType.GIF: (5.0, 7.5, "GIF"),
        RealFileType.BMP: (3.0, 6.0, "BMP"),
        RealFileType.PDF: (5.0, 7.5, "PDF"),
        RealFileType.OLE2: (5.0, 7.5, "OLE2"),
        RealFileType.OOXML: (7.5, 8.0, "Office Open XML"),
    }

    @classmethod
    def detect(cls, file_path: str, include_zip_metadata: bool = False):
        """Detecta el tipo; opcionalmente devuelve metadatos ZIP en la misma lectura."""
        def result(file_type, zip_infos=None):
            return (file_type, zip_infos) if include_zip_metadata else file_type

        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
        except (OSError, IOError):
            return result(RealFileType.UNKNOWN)

        if not header:
            return result(RealFileType.UNKNOWN)

        # N-14 residual: Mach-O universal. CAFEBABE también abre los .class de Java,
        # cuyo campo siguiente es (minor<<16 | major) con major >= 45; en un fat
        # ese campo es el nº de arquitecturas (pequeño). Umbral clásico: < 45.
        if header[:4] == b'\xca\xfe\xba\xbe' and len(header) >= 8:
            if int.from_bytes(header[4:8], 'big') < 45:
                return result(RealFileType.MACH_O)

        for offset, magic, file_type in cls.MAGIC_PATTERNS:
            if len(header) >= offset + len(magic):
                if header[offset:offset + len(magic)] == magic:
                    if file_type in (RealFileType.AVI, RealFileType.WEBP):
                        return result(cls._desambiguate_riff(header))

                    if file_type == RealFileType.MP4:
                        return result(cls._validate_mp4_brand(header))

                    if file_type == RealFileType.PE32:
                        return result(cls._classify_pe(file_path, header))

                    if file_type == RealFileType.BMP:
                        # N-14: 'BM' son 2 bytes demasiado débiles (texto ASCII
                        # que empiece por "BM..." daba falso positivo). Validar
                        # la cabecera BITMAP antes de afirmar que es BMP; si no
                        # valida, seguir a la detección por contenido.
                        validated = cls._validate_bmp(header)
                        if validated is not None:
                            return result(validated)
                        continue

                    if file_type == RealFileType.ZIP:
                        # FIX BUG C-3: un contenedor con firma PK puede ser
                        # OOXML (.docx/.xlsx/.pptx), JAR o APK, no solo un ZIP
                        # genérico. Devolver siempre ZIP hacía que documentos
                        # Office nunca pasaran por el analizador de macros.
                        return cls._classify_zip(file_path, include_metadata=include_zip_metadata)

                    return result(file_type)

        return result(cls._detect_by_content(file_path))

    @classmethod
    def _desambiguate_riff(cls, header: bytes) -> RealFileType:
        if len(header) < 12:
            return RealFileType.BINARY
        fourcc = header[8:12]
        if fourcc == b'AVI ':
            return RealFileType.AVI
        if fourcc == b'WEBP':
            return RealFileType.WEBP
        return RealFileType.BINARY

    @classmethod
    def _validate_mp4_brand(cls, header: bytes) -> RealFileType:
        if len(header) < 12:
            return RealFileType.BINARY
        brand = header[8:12]
        if brand in cls.MP4_VALID_BRANDS:
            return RealFileType.MP4
        return RealFileType.BINARY

    @classmethod
    def _classify_zip(cls, file_path: str, include_metadata: bool = False):
        """FIX BUG C-3: distingue contenedores basados en ZIP (OOXML/JAR/APK)
        del ZIP genérico, inspeccionando los nombres internos. Si el ZIP no
        se puede abrir (corrupto, cifrado, truncado) cae a ZIP genérico en
        vez de propagar la excepción."""
        try:
            declared_count = zip_member_count_from_eocd(file_path)
            if declared_count is not None and declared_count > MAX_ZIP_MEMBER_COUNT:
                return (RealFileType.ZIP, None) if include_metadata else RealFileType.ZIP
            with zipfile.ZipFile(file_path, 'r') as zf:
                infos = zf.infolist()
                structured_type = classify_structured_zip_names(
                    info.filename for info in infos
                )
        except Exception:
            return (RealFileType.ZIP, None) if include_metadata else RealFileType.ZIP

        file_type = {
            'APK': RealFileType.APK,
            'OOXML': RealFileType.OOXML,
            'JAR': RealFileType.JAR,
        }.get(structured_type, RealFileType.ZIP)
        if include_metadata:
            return file_type, infos if structured_type else None
        return file_type

    @classmethod
    def _validate_bmp(cls, header: bytes):
        """N-14: 'BM' (2 bytes) no basta para afirmar BMP.

        Valida el BITMAPFILEHEADER + BITMAPINFOHEADER clásico: tamaño del
        encabezado DIB (40 bytes o variantes), planes == 1 y profundidad de
        color conocida. Devuelve RealFileType.BMP si es coherente y None si
        no lo es (para que la detección continúe, p. ej. texto "BM...")."""
        if len(header) < 54:
            return None
        dib_size = struct.unpack('<I', header[14:18])[0]
        if dib_size not in (40, 52, 56, 108, 124):
            return None
        planes = struct.unpack('<H', header[26:28])[0]
        bpp = struct.unpack('<H', header[28:30])[0]
        if planes != 1:
            return None
        if bpp not in (0, 1, 4, 8, 16, 24, 32):
            return None
        return RealFileType.BMP

    @classmethod
    def _classify_pe(cls, file_path: str, header: bytes) -> RealFileType:
        """FIX BUG C-6: antes `except Exception: return RealFileType.PE32`
        clasificaba como PE32 VÁLIDO cualquier archivo con cabecera 'MZ'
        seguida de basura (offset fuera de rango, sin firma 'PE\\0\\0',
        EOF prematuro...). Eso hacía que análisis posteriores (parseo de
        secciones, imports, etc.) fallaran sobre un archivo que nunca fue
        un PE real. Ahora se exige la firma 'PE\\0\\0' en pe_offset antes
        de tratarlo como ejecutable Windows; si no está, se devuelve
        BINARY (MZ presente pero no es un PE válido)."""
        try:
            with open(file_path, 'rb') as f:
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                if len(pe_offset_bytes) < 4:
                    return RealFileType.BINARY
                pe_offset = struct.unpack('<I', pe_offset_bytes)[0]

                f.seek(pe_offset)
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return RealFileType.BINARY

                f.seek(pe_offset + 4)
                machine = f.read(2)
                if len(machine) < 2:
                    return RealFileType.BINARY
                machine_type = struct.unpack('<H', machine)[0]

                f.seek(pe_offset + 22)
                characteristics = f.read(2)
                if len(characteristics) == 2:
                    char = struct.unpack('<H', characteristics)[0]
                    is_dll = (char & 0x2000) != 0
                    if is_dll:
                        return RealFileType.DLL

                # N-14: ARM64 (0xAA64), ARM64EC (0xA641) e IA64 (0x0200) son
                # PEs de 64 bits; antes caían al else -> PE32 erróneo.
                if machine_type in (0x8664, 0xAA64, 0xA641, 0x0200):
                    return RealFileType.PE64
                return RealFileType.PE32
        except Exception:
            return RealFileType.BINARY

    @classmethod
    def _detect_by_content(cls, file_path: str) -> RealFileType:
        """Detección fallback por análisis de contenido (incluye shebangs)."""
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(4096)

            if not sample:
                return RealFileType.UNKNOWN

            if sample.startswith(b'#!'):
                first_line = sample.split(b'\n', 1)[0].lower()
                if b'python' in first_line:
                    return RealFileType.PYTHON_SCRIPT
                if b'bash' in first_line or b'/sh' in first_line:
                    return RealFileType.SHELL_SCRIPT
                if b'pwsh' in first_line or b'powershell' in first_line:
                    return RealFileType.POWERSHELL

            printable_count = sum(
                1 for b in sample
                if 32 <= b <= 126 or b in (9, 10, 13)
            )
            printable_ratio = printable_count / len(sample)

            if printable_ratio > 0.85:
                text_sample = sample.decode('utf-8', errors='ignore').lower()
                if 'def ' in text_sample and ('import ' in text_sample or 'from ' in text_sample):
                    return RealFileType.PYTHON_SCRIPT
                return RealFileType.TEXT

            return RealFileType.BINARY

        except Exception:
            return RealFileType.UNKNOWN

    @classmethod
    def get_entropy_profile(cls, file_type: RealFileType) -> Optional[Tuple[float, float, str]]:
        return cls.ENTROPY_PROFILES.get(file_type)

    @classmethod
    def is_compressed_container(cls, file_type: RealFileType) -> bool:
        return file_type in {
            RealFileType.ZIP, RealFileType.GZIP, RealFileType.BZIP2,
            RealFileType.XZ, RealFileType.TAR, RealFileType.RAR,
            RealFileType.RAR5, RealFileType.SEVEN_ZIP, RealFileType.MP4,
            RealFileType.MKV, RealFileType.MP3, RealFileType.FLAC,
            RealFileType.PNG, RealFileType.JPEG, RealFileType.GIF,
            RealFileType.WEBP, RealFileType.OOXML, RealFileType.JAR,
            RealFileType.APK
        }

    @classmethod
    def is_executable(cls, file_type: RealFileType) -> bool:
        return file_type in {
            RealFileType.PE32, RealFileType.PE64, RealFileType.DLL,
            RealFileType.ELF, RealFileType.MACH_O
        }


def detect_file_type(file_path: str) -> str:
    """Compatibilidad con código existente que espera un string."""
    ft = FileTypeDetector.detect(file_path)
    type_map = {
        RealFileType.PE32: 'PE',
        RealFileType.PE64: 'PE',
        RealFileType.DLL: 'PE',
        RealFileType.ELF: 'ELF',
        RealFileType.MACH_O: 'MACH-O',
    }
    return type_map.get(ft, 'UNKNOWN')
