"""
Importa hashes de malware conocido hacia la base de datos local
(malware_hashes.txt) que usa StaticAnalyzer.check_reputation().

Este entorno no tiene salida de red hacia bazaar.abuse.ch, así que el
importador trabaja con archivos que tú descargas manualmente. Fuentes
recomendadas (gratuitas, requieren solo un navegador):

  - MalwareBazaar (abuse.ch):
      https://bazaar.abuse.ch/export/#csv     -> full CSV export
      https://bazaar.abuse.ch/export/txt/sha256/full/  -> lista plana SHA256
  - VirusShare:
      https://virusshare.com/hashes  -> listas MD5 en texto plano

Soporta dos formatos de entrada:
  1. Lista plana: un hash por línea (MD5/SHA1/SHA256, se detecta por longitud).
  2. CSV de MalwareBazaar: detecta automáticamente las columnas
     sha256_hash / md5_hash / sha1_hash.

Uso:
    python3 import_hashes.py archivo_descargado.txt
    python3 import_hashes.py malwarebazaar_export.csv
    python3 import_hashes.py archivo1.txt archivo2.csv --db malware_hashes.txt
"""

import argparse
import csv
import os
import re
import sys
import tempfile

HEX_HASH_RE = re.compile(r'^[a-fA-F0-9]+$')
VALID_LENGTHS = {32: 'md5', 40: 'sha1', 64: 'sha256'}


def extract_hashes_from_plain_list(path):
    found = set()
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            token = line.split(',')[0].split()[0] if line else ''
            if HEX_HASH_RE.match(token) and len(token) in VALID_LENGTHS:
                found.add(token.lower())
    return found


def extract_hashes_from_csv(path):
    found = set()
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        # Los exports de MalwareBazaar traen líneas de comentario con '#' antes del header real
        lines = [l for l in f if not l.startswith('#')]
    reader = csv.reader(lines)
    header = next(reader, None)
    if not header:
        return found

    hash_cols = [i for i, col in enumerate(header) if 'hash' in col.lower()]
    if not hash_cols:
        # Puede que no haya header; reintenta tratando cada celda como candidata
        for row in reader:
            for cell in row:
                cell = cell.strip().strip('"')
                if HEX_HASH_RE.match(cell) and len(cell) in VALID_LENGTHS:
                    found.add(cell.lower())
        return found

    for row in reader:
        for idx in hash_cols:
            if idx < len(row):
                cell = row[idx].strip().strip('"')
                if HEX_HASH_RE.match(cell) and len(cell) in VALID_LENGTHS:
                    found.add(cell.lower())
    return found


def import_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == '.csv':
        return extract_hashes_from_csv(path)
    return extract_hashes_from_plain_list(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('files', nargs='+', help='Archivo(s) descargados (lista plana o CSV de MalwareBazaar)')
    parser.add_argument('--db', default='malware_hashes.txt', help='Base de datos local a actualizar (default: malware_hashes.txt)')
    args = parser.parse_args()
    if os.path.basename(os.path.normpath(args.db)) not in {
            'malware_hashes.txt', 'known_good_hashes.txt', 'malware_imphashes.txt',
            'malware_tlsh.txt', 'malware_ssdeep.txt',
            'tweetfeed_sha256.txt', 'malwarebazaar_sha256.txt', 'nsrl_sha256.txt'}:
        print(f"⚠️  Destino no estándar: {args.db}. Verifica que sea la base correcta.", file=sys.stderr)

    existing = set()
    if os.path.exists(args.db):
        with open(args.db, 'r', encoding='utf-8') as f:
            existing = set(line.strip().lower() for line in f if line.strip())

    new_hashes = set()
    for path in args.files:
        if not os.path.exists(path):
            print(f"⚠️  No existe: {path}")
            continue
        found = import_file(path)
        print(f"{path}: {len(found)} hash(es) válidos encontrados")
        new_hashes |= found

    combined = existing | new_hashes
    added = len(combined) - len(existing)

    db_path = os.path.abspath(args.db)
    db_dir = os.path.dirname(db_path)
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix='.hashes-', suffix='.tmp', dir=db_dir)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
            for h in sorted(combined):
                f.write(h + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, db_path)
        temp_path = None
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    print(f"\n✅ Base de datos actualizada: {args.db}")
    print(f"   Hashes previos: {len(existing)}")
    print(f"   Hashes nuevos agregados: {added}")
    print(f"   Total: {len(combined)}")


if __name__ == '__main__':
    main()
