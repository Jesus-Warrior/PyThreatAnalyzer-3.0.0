"""
Analizador estático de malware con características avanzadas.

Fusión de:
  - StaticAnalyzer clásico (hashes, PE/ELF, strings, polyglot, whitelist con
    Authenticode REAL vía WinVerifyTrust + paquetes Linux dpkg/rpm + NSRL).
  - AdvancedFeatures (imphash, TLSH, entropía por ventanas deslizantes,
    overlay PE, prueba de compresibilidad).

FIX BUG #1: check_reputation() ahora rellena SIEMPRE imphash_match,
tlsh_match y ssdeep_match (antes risk_scoring.py los leía con .get() y la
capa Similarity quedaba vacía silenciosamente). Incluye comparación fuzzy
real con topes de comparaciones (no solo match exacto).

FIX BUG A: mismatch de mayúsculas en el fuzzy matching TLSH/ssdeep.
_load_hash_set() lowercaseaba TODAS las bases, incluidas TLSH y ssdeep.
El cuerpo de un hash ssdeep ('blocksize:hb:hb') es BASE64 -> case-sensitive:
lowercasear la referencia la corrompe, y con el probe en caso original la
comparación era inconsistente (falsos negativos del fuzzy). Ahora:
  - md5/sha1/sha256/imphash siguen normalizados a minúsculas (hex, sin caso).
  - TLSH/ssdeep se cargan y comparan en SU CASO ORIGINAL por ambos lados.
  IMPORTANTE: si ya poblaste malware_tlsh.txt / malware_ssdeep.txt con
  contenido en minúsculas, REGENERARLOS: los hashes deben guardarse tal cual
  los emiten tlsh.hash() y ssdeep.hash_from_file().
"""

import struct
import zlib
import os
import zipfile
from typing import Optional, Dict, List, Any, Set
import hashlib
import math
import re
import sqlite3
import shutil
import subprocess
from collections import Counter
from analysis_utils import LARGE_FILE_THRESHOLD, SAMPLE_CHUNK_SIZE

try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    _PEFILE_AVAILABLE = False

try:
    import tlsh
    _TLSH_AVAILABLE = True
except ImportError:
    _TLSH_AVAILABLE = False

try:
    import elftools.elf.elffile as elffile
    _ELFTOOLS_AVAILABLE = True
except ImportError:
    elffile = None
    _ELFTOOLS_AVAILABLE = False

try:
    import ssdeep
    _SSDEEP_AVAILABLE = True
except ImportError:
    ssdeep = None
    _SSDEEP_AVAILABLE = False

# Tope de comparaciones fuzzy por archivo: evita que una base de referencias
# grande degrade el rendimiento del análisis (2000 comparaciones TLSH/ssdeep
# ≈ <1s; más allá, solo match exacto por set).
_FUZZY_SCAN_MAX = 2000
# Umbrales de similitud fuzzy (distancia TLSH menor = más parecido;
# score ssdeep mayor = más parecido).
_TLSH_MAX_DISTANCE = 30
_SSDEEP_MIN_SCORE = 80
MAX_SSDEEP_FILE_SIZE = 100 * 1024 * 1024


class StaticAnalyzer:
    def __init__(self, hash_db_path='malware_hashes.txt',
                 whitelist_db_path='known_good_hashes.txt',
                 imphash_db_path='malware_imphashes.txt',
                 nsrl_db_path=None,
                 tlsh_db_path='malware_tlsh.txt',
                 ssdeep_db_path='malware_ssdeep.txt'):
        self.hash_db_path = hash_db_path
        self.whitelist_db_path = whitelist_db_path
        self.imphash_db_path = imphash_db_path
        self.nsrl_db_path = nsrl_db_path
        self.database_status = {}
        self.known_bad_hashes = self._load_hash_set(
            hash_db_path, database_name='malware_hashes')
        self.known_good_hashes = self._load_hash_set(
            whitelist_db_path, database_name='known_good_hashes')
        # Imphashes de malware conocido (base DEDICADA).
        self.known_bad_imphashes = self._load_hash_set(
            imphash_db_path, database_name='malware_imphashes')
        # Bases fuzzy dedicadas (TLSH / ssdeep de referencia).
        # FIX BUG A: se cargan en CASO ORIGINAL (lowercase=False).
        self.known_bad_tlsh = self._load_hash_set(
            tlsh_db_path, lowercase=False, database_name='malware_tlsh')
        self.known_bad_ssdeep = self._load_hash_set(
            ssdeep_db_path, lowercase=False, database_name='malware_ssdeep')
        # NSRL can remain in its source SQLite (multi-GB); query it read-only
        # instead of materializing the full allowlist in process memory.
        self.nsrl_sqlite = None
        self.known_nsrl_hashes = set()
        if nsrl_db_path and os.path.splitext(os.fspath(nsrl_db_path))[1].lower() in {'.sqlite', '.sqlite3', '.db'}:
            self._configure_nsrl_sqlite(nsrl_db_path)
        elif nsrl_db_path:
            self.known_nsrl_hashes = self._load_hash_set(nsrl_db_path, database_name='nsrl')
        else:
            self.database_status['nsrl'] = {'status': 'disabled', 'entries': 0}
        self.entropy_threshold = 7.0

    def _configure_nsrl_sqlite(self, path):
        """Configure a read-only RDSv3 lookup without loading the hashes in RAM."""
        try:
            resolved = os.path.abspath(os.fspath(path))
            with sqlite3.connect(f'file:{resolved}?mode=ro', uri=True, timeout=5) as conn:
                objects = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','view')").fetchall()
                found = None
                for (name,) in objects:
                    qname = '"' + str(name).replace('"', '""') + '"'
                    columns = conn.execute(f'PRAGMA table_info({qname})').fetchall()
                    by_lower = {str(col[1]).lower(): str(col[1]) for col in columns}
                    if 'sha256' in by_lower:
                        found = (str(name), by_lower['sha256'])
                        if str(name).lower() in {'file', 'file2', 'distinct_hash', 'distinct_file'}:
                            break
                if not found:
                    raise ValueError('no se encontró una tabla/vista con columna SHA256')
            table, column = found
            self.nsrl_sqlite = (resolved, table, column)
            self.database_status['nsrl'] = {
                'status': 'ready', 'path': resolved, 'entries': None,
                'storage': 'sqlite', 'table': table, 'column': column,
            }
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            self.database_status['nsrl'] = {
                'status': 'unavailable', 'path': str(path), 'entries': 0,
                'error': str(exc),
            }

    def _nsrl_sqlite_contains(self, sha256):
        if not self.nsrl_sqlite or not sha256:
            return False
        path, table, column = self.nsrl_sqlite
        qtable = '"' + table.replace('"', '""') + '"'
        qcolumn = '"' + column.replace('"', '""') + '"'
        try:
            with sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=5) as conn:
                return conn.execute(
                    f'SELECT 1 FROM {qtable} WHERE {qcolumn} IN (?, ?) LIMIT 1',
                    (sha256.upper(), sha256.lower())).fetchone() is not None
        except sqlite3.Error:
            return False

    def _load_hash_set(self, path, lowercase=True, database_name=None):
        """FIX BUG A: TLSH/ssdeep deben cargarse SIN lowercase (Base64/hex
        case-sensitive). Los hashes de archivo e imphash (hex puro) mantienen
        la normalización a minúsculas. El estado de carga se guarda para
        distinguir una base ausente o vacía de una búsqueda completa sin match."""
        label = database_name or str(path or 'disabled')
        if not path:
            self.database_status[label] = {'status': 'disabled', 'entries': 0}
            return set()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                entries = set()
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    entries.add(line.lower() if lowercase else line)
            self.database_status[label] = {
                'status': 'ready' if entries else 'empty',
                'path': os.fspath(path),
                'entries': len(entries),
            }
            return entries
        except (OSError, TypeError, UnicodeError) as exc:
            self.database_status[label] = {
                'status': 'unavailable', 'path': str(path), 'entries': 0,
                'error': str(exc),
            }
            return set()

    # ---------- Entropía ----------
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def calculate_file_entropy(self, file_path):
        size = os.path.getsize(file_path)
        if size <= LARGE_FILE_THRESHOLD:
            with open(file_path, 'rb') as f:
                return self.calculate_entropy(f.read()), False
        with open(file_path, 'rb') as f:
            start = f.read(SAMPLE_CHUNK_SIZE)
            f.seek(max(0, size // 2))
            middle = f.read(SAMPLE_CHUNK_SIZE)
            f.seek(max(0, size - SAMPLE_CHUNK_SIZE))
            end = f.read(SAMPLE_CHUNK_SIZE)
        return self.calculate_entropy(start + middle + end), True

    # ---------- PE ----------
    def analyze_pe(self, file_path):
        results = {
            'type': 'PE', 'suspicious': [], 'imports': [],
            'sections': [], 'tls_callbacks': False, 'entry_point': None,
        }

        if not _PEFILE_AVAILABLE:
            results['error'] = "pefile no está instalado (pip install pefile)"
            return results

        pe = None
        try:
            pe = pefile.PE(file_path)

            for section in pe.sections:
                name = section.Name.decode(errors='ignore').rstrip('\x00')
                entropy = self.calculate_entropy(section.get_data())
                results['sections'].append({
                    'name': name,
                    'entropy': round(entropy, 2),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                })
                if entropy > self.entropy_threshold:
                    results['suspicious'].append(
                        f"Sección {name} con entropía alta ({entropy:.2f}) - posible empaquetado")

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                suspicious_apis = {
                    'createprocess', 'winexec', 'shellexecute', 'internetopen',
                    'urldownload', 'createremotethread', 'writeprocessmemory',
                    'virtualalloc', 'virtualprotect', 'socket', 'isdebuggerpresent',
                    'checkremotedebuggerpresent',
                }
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore').lower()
                    for func in entry.imports:
                        if func.name:
                            func_name = func.name.decode(errors='ignore')
                            results['imports'].append(f"{dll}:{func_name}")
                            if any(api in func_name.lower() for api in suspicious_apis):
                                results['suspicious'].append(f"API sospechosa: {func_name}")

            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                results['tls_callbacks'] = True
                results['suspicious'].append("TLS Callbacks detectados - posible anti-análisis")

            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            results['entry_point'] = hex(ep)
            ep_section = pe.get_section_by_rva(ep)
            if ep_section and not (ep_section.Characteristics & 0x20000000):
                results['suspicious'].append("Entry point en sección no ejecutable")

        except Exception as e:
            results['error'] = str(e)
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception:
                    pass

        return results

    # ---------- ELF ----------
    def analyze_elf(self, file_path):
        results = {'type': 'ELF', 'suspicious': [], 'symbols': [], 'segments': []}

        if not _ELFTOOLS_AVAILABLE:
            results['error'] = "pyelftools no está instalado (pip install pyelftools)"
            return results

        try:
            with open(file_path, 'rb') as f:
                elf = elffile.ELFFile(f)

                for section in elf.iter_sections():
                    if section.name in ('.upx', '.packed'):
                        results['suspicious'].append(f"Sección de empaquetado detectada: {section.name}")
                    if isinstance(section, elffile.SymbolTableSection):
                        for symbol in section.iter_symbols():
                            results['symbols'].append(symbol.name)

                for segment in elf.iter_segments():
                    results['segments'].append({
                        'type': segment['p_type'],
                        'flags': segment['p_flags'],
                        'size': segment['p_memsz'],
                    })
        except Exception as e:
            results['error'] = str(e)

        return results

    # ---------- Reputación (mala) ----------
    def check_reputation(self, file_path, hashes=None):
        """Reputación completa: hashes exactos + imphash + TLSH + ssdeep.

        FIX BUG #1: rellena SIEMPRE las claves imphash_match / tlsh_match /
        ssdeep_match (la capa Similarity de risk_scoring.py las consume).
        """
        hashes = hashes or self.get_file_hashes(file_path)
        reputation = {
            'md5_match': hashes['md5'] in self.known_bad_hashes,
            'sha1_match': hashes['sha1'] in self.known_bad_hashes,
            'sha256_match': hashes['sha256'] in self.known_bad_hashes,
            'imphash_match': False,
            'tlsh_match': False,
            'ssdeep_match': False,
            'database_status': dict(self.database_status),
        }

        # N-15 residual / M2: avisar cuando el tope _FUZZY_SCAN_MAX deja
        # referencias sin comparar. Se calcula ANTES de cualquier return
        # temprano: con ssdeep instalado y un archivo > MAX_SSDEEP_FILE_SIZE el
        # return de la rama de tamaño saltaba este aviso y el mismo DB grande
        # avisaba a 50 MB y no a 200 MB.
        if (len(self.known_bad_tlsh) > _FUZZY_SCAN_MAX
                or len(self.known_bad_ssdeep) > _FUZZY_SCAN_MAX):
            reputation['fuzzy_scan_limited'] = {
                'limit': _FUZZY_SCAN_MAX,
                'tlsh_refs': len(self.known_bad_tlsh),
                'ssdeep_refs': len(self.known_bad_ssdeep),
            }

        adv = get_advanced_features(self)

        # Cabecera real: el imphash solo tiene sentido en PE (magic bytes MZ,
        # nunca la extensión — reemplaza al _looks_like_pe() inexistente).
        with open(file_path, 'rb') as f:
            is_pe = f.read(2) == b'MZ'

        # --- imphash (solo PE) ---
        reputation['imphash'] = None
        if is_pe and _PEFILE_AVAILABLE:
            try:
                imp = adv.calculate_imphash(file_path)
                reputation['imphash'] = imp
                if imp and imp.lower() in self.known_bad_imphashes:
                    reputation['imphash_match'] = True
            except Exception:
                reputation['imphash'] = None

        # --- TLSH (exacto en set + fuzzy con tope de comparaciones) ---
        try:
            tlsh_val = adv.calculate_tlsh(file_path)
            reputation['tlsh'] = tlsh_val
            if tlsh_val:
                # FIX BUG A: comparación en CASO ORIGINAL (sin .lower());
                # las referencias se cargan raw (ver _load_hash_set).
                if tlsh_val in self.known_bad_tlsh:
                    reputation['tlsh_match'] = True
                elif self.known_bad_tlsh and _TLSH_AVAILABLE:
                    reputation['tlsh_match'] = self._fuzzy_tlsh_match(tlsh_val)
        except Exception:
            reputation['tlsh'] = None

        # --- ssdeep (exacto en set + fuzzy con tope) ---
        if _SSDEEP_AVAILABLE:
            try:
                if os.path.getsize(file_path) > MAX_SSDEEP_FILE_SIZE:
                    reputation['ssdeep'] = None
                    reputation['ssdeep_skipped'] = True
                    reputation['ssdeep_note'] = (
                        f"ssdeep omitido: archivo mayor que {MAX_SSDEEP_FILE_SIZE} bytes"
                    )
                    return reputation
                rep_ssdeep = ssdeep.hash_from_file(file_path)
                reputation['ssdeep'] = rep_ssdeep
                if rep_ssdeep:
                    # FIX BUG A: sin .lower() — el cuerpo ssdeep es Base64
                    # (case-sensitive); refs cargadas en caso original.
                    if rep_ssdeep in self.known_bad_ssdeep:
                        reputation['ssdeep_match'] = True
                    elif self.known_bad_ssdeep:
                        reputation['ssdeep_match'] = self._fuzzy_ssdeep_match(rep_ssdeep)
            except Exception as e:
                reputation['ssdeep_error'] = str(e)
                reputation['ssdeep'] = None
        else:
            reputation['ssdeep'] = None
            reputation['ssdeep_note'] = "ssdeep no está instalado; fuzzy hashing deshabilitado"

        return reputation

    def _ordered_refs(self, attr):
        """N-15 residual: orden DETERMINISTA (lexicográfico) de las referencias.
        Iterar un set con tope dependía de PYTHONHASHSEED: el mismo archivo podía
        coincidir en una ejecución y no en otra con bases > _FUZZY_SCAN_MAX."""
        refs = getattr(self, attr)
        cache = self.__dict__.setdefault('_ordered_refs_cache', {})
        entry = cache.get(attr)
        # B5: la invalidación comparaba solo identidad y longitud; un
        # discard()+add() (misma longitud) dejaba un snapshot obsoleto. Se
        # compara el CONTENIDO contra una copia congelada (igualdad de sets,
        # O(n) y sin reordenar en cada llamada).
        if entry is None or entry[0] is not refs or entry[1] != refs:
            entry = (refs, frozenset(refs), tuple(sorted(refs)))
            cache[attr] = entry
        return entry[2]

    def _fuzzy_tlsh_match(self, value, threshold=_TLSH_MAX_DISTANCE, max_scan=_FUZZY_SCAN_MAX):
        """Escaneo fuzzy TLSH con tope de comparaciones (evita O(n) completo
        en bases grandes). diffxlen tolera longitudes distintas.
        FIX BUG A: NO se lowercasea (ni probe ni refs); solo se recorta."""
        if not _TLSH_AVAILABLE:
            return False
        value = value.strip()
        try:
            for i, ref in enumerate(self._ordered_refs('known_bad_tlsh')):
                if i >= max_scan:
                    break
                try:
                    if tlsh.diffxlen(value, ref) <= threshold:
                        return True
                except Exception:
                    continue
        except Exception:
            return False
        return False

    def _fuzzy_ssdeep_match(self, value, threshold=_SSDEEP_MIN_SCORE, max_scan=_FUZZY_SCAN_MAX):
        """Escaneo fuzzy ssdeep con tope de comparaciones.
        FIX BUG A: NO se lowercasea (Base64 es case-sensitive); solo strip."""
        if not _SSDEEP_AVAILABLE:
            return False
        value = value.strip()
        try:
            for i, ref in enumerate(self._ordered_refs('known_bad_ssdeep')):
                if i >= max_scan:
                    break
                try:
                    score = ssdeep.compare(value, ref)
                except Exception:
                    continue
                if score is not None and score >= threshold:
                    return True
        except Exception:
            return False
        return False

    def check_imphash(self, imphash):
        """Verifica un imphash contra la base DEDICADA de imphashes maliciosos.
        NUNCA contra known_bad_hashes (hashes de archivo)."""
        if not imphash:
            return {'match': False, 'count': 0}
        imp = imphash.strip().lower()
        return {'match': imp in self.known_bad_imphashes,
                'count': 1 if imp in self.known_bad_imphashes else 0}

    # ---------- Whitelist ----------
    def check_whitelist(self, file_path, hashes=None):
        """Legítimo conocido, por orden de certeza:
           1) whitelist local  2) NSRL  3) Authenticode  4) paquete Linux.
        """
        hashes = hashes or self.get_file_hashes(file_path)
        result = {'is_whitelisted': False, 'reason': None, 'method': None}

        if hashes['sha256'] in self.known_good_hashes or hashes['md5'] in self.known_good_hashes:
            result.update(is_whitelisted=True, reason='Hash en whitelist local', method='hash_db')
            return result

        if ((self.known_nsrl_hashes and (
            hashes['sha1'] in self.known_nsrl_hashes
            or hashes['sha256'] in self.known_nsrl_hashes
            or hashes['md5'] in self.known_nsrl_hashes
        )) or self._nsrl_sqlite_contains(hashes.get('sha256'))):
            result.update(is_whitelisted=True,
                          reason='Hash en NSRL (National Software Reference Library)',
                          method='nsrl')
            return result

        if os.name == 'nt':
            sig_result = self._verify_windows_signature(file_path)
            if sig_result.get('valid'):
                result.update(is_whitelisted=True,
                              reason=f"Firma digital Authenticode válida (firmante: {sig_result.get('signer', 'desconocido')})",
                              method='authenticode')
                return result
            elif sig_result.get('present') and not sig_result.get('checked'):
                result['note'] = 'Tiene firma digital, pero no se pudo verificar su validez criptográfica'
        else:
            pkg_result = self._verify_linux_package(file_path)
            if pkg_result.get('verified'):
                result.update(is_whitelisted=True,
                              reason=f"Pertenece al paquete '{pkg_result.get('package')}' e integridad verificada",
                              method='package_manager')
                return result
            elif pkg_result.get('package'):
                result['note'] = f"Pertenece al paquete '{pkg_result['package']}' pero falló la verificación de integridad"

        return result

    def _verify_windows_signature(self, file_path):
        """Verificación CRIPTOGRÁFICA real (WinVerifyTrust). Un fallo NO whitelista."""
        result = {'present': False, 'checked': False, 'valid': False, 'signer': None}

        if _PEFILE_AVAILABLE:
            try:
                pe = pefile.PE(file_path, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
                result['present'] = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
                pe.close()
            except Exception:
                pass

        try:
            import ctypes
            from ctypes import wintypes

            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p),
                ]

            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                ]

            WTD_UI_NONE = 2
            WTD_REVOKE_NONE = 0
            WTD_CHOICE_FILE = 1
            WTD_STATEACTION_VERIFY = 1
            WTD_STATEACTION_CLOSE = 2
            WTD_SAFER_FLAG = 0x100

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            action_guid = GUID(0x00AAC56B, 0xCD44, 0x11d0,
                               (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

            file_info = WINTRUST_FILE_INFO(
                cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath=os.path.abspath(file_path),
                hFile=None, pgKnownSubject=None,
            )
            wintrust_data = WINTRUST_DATA(
                cbStruct=ctypes.sizeof(WINTRUST_DATA),
                pPolicyCallbackData=None, pSIPClientData=None,
                dwUIChoice=WTD_UI_NONE, fdwRevocationChecks=WTD_REVOKE_NONE,
                dwUnionChoice=WTD_CHOICE_FILE, pFile=ctypes.pointer(file_info),
                dwStateAction=WTD_STATEACTION_VERIFY, hWVTStateData=None,
                pwszURLReference=None, dwProvFlags=WTD_SAFER_FLAG, dwUIContext=0,
            )

            wintrust = ctypes.windll.wintrust
            status = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wintrust_data))
            result['checked'] = True
            result['valid'] = (status == 0)
            result['present'] = result['present'] or result['valid']

            wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wintrust_data))

        except Exception:
            pass

        return result

    def _verify_linux_package(self, file_path):
        """Integridad contra dpkg/rpm para archivos de paquetes instalados."""
        result = {'package': None, 'verified': False}
        abs_path = os.path.realpath(file_path)

        if shutil.which('dpkg'):
            try:
                owner = subprocess.run(['dpkg', '-S', abs_path], capture_output=True, text=True, timeout=5)
                if owner.returncode == 0 and ':' in owner.stdout:
                    package = owner.stdout.split(':')[0].strip()
                    result['package'] = package
                    verify = subprocess.run(['dpkg', '--verify', package], capture_output=True, text=True, timeout=10)
                    # N-09(b): fail-closed. Si dpkg --verify falla (returncode != 0)
                    # no se puede afirmar integridad; antes un stdout vacío se
                    # interpretaba como "sin diferencias" => verified=True.
                    result['verified'] = (verify.returncode == 0
                                          and abs_path not in verify.stdout)
                    return result
            except Exception:
                pass

        if shutil.which('rpm'):
            try:
                owner = subprocess.run(['rpm', '-qf', abs_path], capture_output=True, text=True, timeout=5)
                if owner.returncode == 0 and owner.stdout.strip() and 'not owned' not in owner.stdout:
                    package = owner.stdout.strip()
                    result['package'] = package
                    verify = subprocess.run(['rpm', '-V', package], capture_output=True, text=True, timeout=10)
                    # N-09(b): fail-closed. `rpm -V` devuelve != 0 cuando hay
                    # diferencias o no puede verificar; solo se acepta rc==0
                    # y ausencia del archivo en la salida.
                    result['verified'] = (verify.returncode == 0
                                          and abs_path not in verify.stdout)
                    return result
            except Exception:
                pass

        return result

    # ---------- Strings ----------
    def extract_strings(self, file_path, min_length=4):
        size = os.path.getsize(file_path)
        sampled = size > LARGE_FILE_THRESHOLD

        with open(file_path, 'rb') as f:
            if not sampled:
                data = f.read()
            else:
                start = f.read(SAMPLE_CHUNK_SIZE)
                f.seek(max(0, size // 2))
                middle = f.read(SAMPLE_CHUNK_SIZE)
                f.seek(max(0, size - SAMPLE_CHUNK_SIZE))
                end = f.read(SAMPLE_CHUNK_SIZE)
                data = start + middle + end

        # B2: antes re.findall materializaba TODAS las rachas (una entrada
        # adversaria con rachas de 4 B cada 5 B daba cientos de miles) y max_seen
        # era 100 000. Ahora: (1) se itera con finditer sin materializar; (2) la
        # longitud mínima efectiva es 5, porque ningún IOC buscado cabe en menos
        # (el más corto, 'mshta', mide 5; IP >= 7; URL >= 8) y así las rachas de
        # 4 B se descartan en C sin cambiar el resultado; (3) se corta en cuanto
        # las tres listas están llenas; (4) max_seen baja a 10 000.
        effective_min = max(min_length, 5)
        ascii_regex = re.compile(rb'[\x20-\x7E]{' + str(effective_min).encode() + rb',}')

        url_re = re.compile(r'https?://[^\s]+')
        ip_re = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

        found = {'urls': [], 'ips': [], 'suspicious_commands': []}
        seen = set()
        max_seen = 10_000
        for raw_match in ascii_regex.finditer(data):
            match = raw_match.group(0)
            try:
                decoded = match.decode('ascii')
            except UnicodeDecodeError:
                continue
            if len(seen) < max_seen:
                if decoded in seen:
                    continue
                seen.add(decoded)

            url_match = url_re.search(decoded)
            ip_match = ip_re.search(decoded)

            if url_match and len(found['urls']) < 25:
                found['urls'].append(url_match.group(0))
            if ip_match and len(found['ips']) < 25:
                found['ips'].append(ip_match.group(0))
            if (len(found['suspicious_commands']) < 25 and any(
                    k in decoded.lower() for k in ('powershell', 'cmd.exe', 'wscript', 'certutil', 'bitsadmin', 'mshta'))):
                found['suspicious_commands'].append(decoded.strip())
            if (len(found['urls']) >= 25 and len(found['ips']) >= 25
                    and len(found['suspicious_commands']) >= 25):
                break  # nada más puede cambiar el resultado

        found['sampled'] = sampled
        for key in ('urls', 'ips', 'suspicious_commands'):
            found[key] = found[key][:25]

        return found

    # ---------- Polyglot ----------
    # M3: el comentario de un ZIP puede medir hasta 65535 bytes, de modo que su
    # EOCD puede estar hasta 64 KiB + 22 B antes del final (más datos basura
    # posteriores). Antes solo se miraban los últimos 4 KiB.
    _EOCD_TAIL_WINDOW = 65535 + 22

    @staticmethod
    def _find_valid_eocd(data, base_offset=0):
        """Posición (en `data`) del último EOCD ZIP verosímil, o -1.

        Valida que el comentario declarado quepa y que directorio central +
        offset no excedan la posición absoluta del EOCD (los offsets ZIP son
        relativos al inicio del ZIP, nunca mayores que la posición absoluta
        aunque haya datos antepuestos). Reduce coincidencias casuales de la
        firma de 4 bytes 'PK\\x05\\x06' dentro de datos comprimidos.
        """
        pos = data.rfind(b'PK\x05\x06')
        while pos >= 0:
            if pos + 22 <= len(data):
                cd_size, cd_offset, comment_len = struct.unpack_from('<IIH', data, pos + 12)
                absolute = base_offset + pos
                if (pos + 22 + comment_len <= len(data)
                        and (cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF
                             or cd_size + cd_offset <= absolute)):
                    return pos
            pos = data.rfind(b'PK\x05\x06', 0, pos)
        return -1

    def _pe_has_trailing_zip(self, file_path):
        with open(file_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            base = max(0, size - self._EOCD_TAIL_WINDOW)
            f.seek(base)
            tail = f.read(size - base)
        pos = self._find_valid_eocd(tail, base)
        return pos >= 0

    def check_polyglot(self, file_path):
        findings = []

        with open(file_path, 'rb') as f:
            header = f.read(8)

        # R-polyglot: un ZIP VÁLIDO se analiza miembro a miembro (N-01), de modo
        # que un .py/.php almacenado sin comprimir dentro de él ya lo ve el
        # analizador de scripts. Buscar 'import ' en los primeros 2 MiB de
        # cualquier ZIP marcaba POLYGLOT_FILE (MEDIO 25) en zips legítimos con
        # fuentes sin comprimir. Solo se conserva para PK que NO es un ZIP
        # válido (estructura rota/ocultando texto ejecutable).
        if header[:2] == b'PK' and not zipfile.is_zipfile(file_path):
            try:
                with open(file_path, 'rb') as f:
                    tail_sample = f.read(min(os.path.getsize(file_path), SAMPLE_CHUNK_SIZE))
                if b'import ' in tail_sample or (b'from ' in tail_sample and b'def ' in tail_sample):
                    findings.append("Posible polyglot ZIP+Python")
                if b'<?php' in tail_sample:
                    findings.append("Posible polyglot ZIP+PHP")
            except OSError:
                pass

        if header[:2] == b'MZ':
            try:
                if self._pe_has_trailing_zip(file_path):
                    findings.append("Posible polyglot PE+ZIP (estructura ZIP anexada al final del ejecutable)")
            except OSError:
                pass

        return findings

    def get_file_hashes(self, file_path):
        hashers = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
        }
        with open(file_path, 'rb') as f:
            while chunk := f.read(1024 * 1024):  # N-16: 1 MiB (antes 8 KiB)
                for h in hashers.values():
                    h.update(chunk)
        return {k: v.hexdigest() for k, v in hashers.items()}


class AdvancedFeatures:
    """Imphash, TLSH, entropía por ventanas, overlay PE, compresibilidad."""

    def __init__(self, analyzer: StaticAnalyzer):
        self.analyzer = analyzer

    def calculate_imphash(self, file_path):
        if not _PEFILE_AVAILABLE:
            return None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            )
            imphash = pe.get_imphash()
            pe.close()
            return imphash
        except Exception:
            return None

    def calculate_tlsh(self, file_path, max_bytes=10 * 1024 * 1024):
        if not _TLSH_AVAILABLE:
            return None
        try:
            size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                if size <= max_bytes:
                    data = f.read()
                else:
                    half = max_bytes // 2
                    data = f.read(half)
                    f.seek(max(0, size - half))
                    data += f.read(half)
            if len(data) < 256:
                return None
            return tlsh.hash(data)
        except Exception:
            return None

    def analyze_entropy_windows(self, file_path, window_size=4096,
                                max_bytes=50 * 1024 * 1024):
        try:
            size = os.path.getsize(file_path)

            if size <= max_bytes:
                with open(file_path, 'rb') as f:
                    data = f.read()
                sampled = False
            else:
                with open(file_path, 'rb') as f:
                    chunk = max_bytes // 3
                    start = f.read(chunk)
                    f.seek(size // 2)
                    middle = f.read(chunk)
                    f.seek(max(0, size - chunk))
                    end = f.read(chunk)
                    data = start + middle + end
                sampled = True

            if len(data) < window_size * 2:
                return {'error': 'Archivo demasiado pequeño', 'sampled': sampled}

        except OSError as e:
            return {'error': f'No se pudo leer archivo: {e}', 'sampled': False}

        windows = []
        entropies = []

        for i in range(0, len(data) - window_size + 1, window_size):
            window = data[i:i + window_size]
            entropy = self.analyzer.calculate_entropy(window)
            windows.append({
                'offset': i if not sampled else f"sampled_{i}",
                'entropy': round(entropy, 2)
            })
            entropies.append(entropy)

        transitions = []
        for i in range(1, len(entropies)):
            diff = abs(entropies[i] - entropies[i - 1])
            if diff > 2.0:
                transitions.append({
                    'from_offset': (i - 1) * window_size,
                    'to_offset': i * window_size,
                    'entropy_diff': round(diff, 2)
                })

        return {
            'window_size': window_size,
            'window_count': len(windows),
            'global_entropy': round(sum(entropies) / len(entropies), 2) if entropies else 0,
            'min_entropy': round(min(entropies), 2) if entropies else 0,
            'max_entropy': round(max(entropies), 2) if entropies else 0,
            'suspicious_transitions': len(transitions),
            'transitions': transitions[:10],
            'windows_sample': windows[:20],
            'sampled': sampled,
            'original_size': size,
        }

    def test_compression_ratio(self, file_path, sample_size=1024 * 1024, window_size=8192):
        """
        FIX BUG (revisión de integración): un ratio global único se diluye
        cuando el archivo mezcla un header de baja entropía (p.ej. cabecera
        PE legible) con un payload empaquetado/cifrado de alta entropía; el
        promedio puede caer por debajo del umbral 'likely_packed' aunque la
        mayor parte del archivo sea claramente incompresible.

        Se calcula además el ratio por ventanas (mismo espíritu que
        analyze_entropy_windows): 'likely_packed' se basa en la ventana
        MENOS compresible (max_window_ratio), no en el promedio global.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)

            if not data:
                return {'error': 'Archivo vacío'}

            compressed = zlib.compress(data, level=9)
            ratio = len(compressed) / len(data)

            window_ratios = []
            for i in range(0, len(data), window_size):
                chunk = data[i:i + window_size]
                if len(chunk) < 256:
                    continue
                window_ratios.append(len(zlib.compress(chunk, level=9)) / len(chunk))
            max_window_ratio = max(window_ratios) if window_ratios else ratio

            return {
                'original_size': len(data),
                'compressed_size': len(compressed),
                'ratio': round(ratio, 4),
                'max_window_ratio': round(max_window_ratio, 4),
                'compressible': ratio < 0.9,
                'likely_packed': max_window_ratio > 0.95,
            }
        except Exception as e:
            return {'error': str(e)}

    # Relleno máximo (alineación a 8 bytes) tolerado tras la tabla de certificados.
    _CERT_PADDING_TOLERANCE = 8

    def detect_overlay(self, file_path):
        """Overlay PE (datos tras la última sección), EXCLUYENDO la tabla de
        certificados Authenticode.

        N-13: la firma digital vive en el overlay (DataDirectory[SECURITY], cuyo
        VirtualAddress es un OFFSET DE ARCHIVO). Antes un PE firmado legítimo
        aparecía con un overlay "sospechoso" (PKCS#7 de ~7 de entropía). Ahora:
          * el bloque de certificados no cuenta como overlay;
          * los datos ENTRE las secciones y los certificados y los datos DESPUÉS
            de los certificados sí cuentan;
          * datos tras la firma (`appended_after_signature`) son una técnica
            conocida: Authenticode no los cubre, así que la firma sigue siendo
            válida con un payload anexado (N-09a)."""
        if not _PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(file_path, fast_load=True)

            last_section_end = 0
            for section in pe.sections:
                section_end = section.PointerToRawData + section.SizeOfRawData
                if section_end > last_section_end:
                    last_section_end = section_end

            cert_off = cert_size = 0
            try:
                sec_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
                entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
                cert_off, cert_size = int(entry.VirtualAddress), int(entry.Size)
            except (AttributeError, IndexError, KeyError):
                pass
            pe.close()

            file_size = os.path.getsize(file_path)
            ranges = [(last_section_end, file_size)]
            appended_after_signature = 0
            has_cert = bool(cert_off and cert_size
                            and cert_off >= last_section_end
                            and cert_off + cert_size <= file_size)
            if has_cert:
                cert_end = cert_off + cert_size
                ranges = [(last_section_end, cert_off), (cert_end, file_size)]
                appended_after_signature = file_size - cert_end
                if appended_after_signature <= self._CERT_PADDING_TOLERANCE:
                    ranges[1] = (cert_end, cert_end)  # solo relleno de alineación
                    appended_after_signature = 0

            overlay_size = sum(max(0, end - start) for start, end in ranges)
            if overlay_size <= 0 and not has_cert:
                return None
            if overlay_size <= 0:
                # Firmado y sin overlay propio: no hay nada que reportar.
                return None

            overlay_data = b''
            with open(file_path, 'rb') as f:
                for start, end in ranges:
                    if end > start and len(overlay_data) < 1024 * 1024:
                        f.seek(start)
                        overlay_data += f.read(min(end - start, 1024 * 1024 - len(overlay_data)))

            overlay_entropy = self.analyzer.calculate_entropy(overlay_data)
            first_start = next((st for st, en in ranges if en > st), last_section_end)

            return {
                'offset': first_start,
                'size': overlay_size,
                'entropy': round(overlay_entropy, 2),
                'is_pe': overlay_data[:2] == b'MZ',
                # M3: ZIP al inicio del overlay O con EOCD válido dentro de él
                # (PE + relleno + ZIP).
                'is_zip': (overlay_data[:2] == b'PK'
                           or StaticAnalyzer._find_valid_eocd(overlay_data) >= 0),
                'certificate_size': cert_size if has_cert else 0,
                'appended_after_signature': appended_after_signature,
                'is_suspicious': bool(appended_after_signature)
                                 or (overlay_size > 1024 and overlay_entropy > 7.0),
            }

        except Exception:
            return None


def get_advanced_features(analyzer):
    return AdvancedFeatures(analyzer)
    
