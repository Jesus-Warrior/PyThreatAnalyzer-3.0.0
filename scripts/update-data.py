#!/usr/bin/env python3
"""Import approved threat data into the local data/ tree.

NSRL source SQLite is supplied by the operator after downloading it from NIST.
MalwareBazaar requires ABUSE_CH_KEY and only retrieves the API's recent
window (currently the last 60 minutes); schedule it hourly to reduce gaps.
No malware samples are downloaded.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'
SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
API_URL = 'https://mb-api.abuse.ch/api/v1/'


def atomic_write(path, writer):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as stream:
            result = writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        return result
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def nsrl_columns(db_path):
    """Find the RDSv3 FILE view/table and SHA256 column without assuming case."""
    with sqlite3.connect(f'file:{Path(db_path).resolve()}?mode=ro', uri=True) as conn:
        objects = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
        ).fetchall()
        for (name,) in objects:
            cols = conn.execute(f'PRAGMA table_info("{name.replace(chr(34), chr(34)*2)}")').fetchall()
            by_lower = {str(col[1]).lower(): str(col[1]) for col in cols}
            sha = by_lower.get('sha256')
            if sha and name.lower() in {'file', 'file2', 'distinct_hash', 'distinct_file'}:
                return name, sha
        for (name,) in objects:
            cols = conn.execute(f'PRAGMA table_info("{name.replace(chr(34), chr(34)*2)}")').fetchall()
            by_lower = {str(col[1]).lower(): str(col[1]) for col in cols}
            if 'sha256' in by_lower:
                return name, by_lower['sha256']
    raise ValueError('No se encontró una tabla/vista con columna SHA256 en el SQLite NSRL')


def import_nsrl(db_path):
    table, column = nsrl_columns(db_path)
    qtable = '"' + table.replace('"', '""') + '"'
    qcolumn = '"' + column.replace('"', '""') + '"'
    with sqlite3.connect(f'file:{Path(db_path).resolve()}?mode=ro', uri=True) as conn:
        if not conn.execute(f'SELECT 1 FROM {qtable} WHERE {qcolumn} IS NOT NULL LIMIT 1').fetchone():
            raise ValueError('el SQLite no contiene hashes SHA-256; no se modifica la configuración')
    local_config = ROOT / 'config.local.json'
    try:
        local = json.loads(local_config.read_text(encoding='utf-8')) if local_config.exists() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'config.local.json inválido; no se modifica: {exc}') from exc
    local['nsrl_db'] = str(Path(db_path).resolve())
    atomic_write(local_config, lambda stream: (json.dump(local, stream, indent=2), stream.write('\n')))
    note = DATA / 'allowlist' / 'nsrl_source.json'
    atomic_write(note, lambda stream: json.dump({
        'source': 'NIST NSRL RDSv3', 'source_file': str(Path(db_path).name),
        'table': table, 'column': column, 'storage': 'external read-only SQLite',
        'imported_utc': datetime.now(timezone.utc).isoformat(),
        'redistributable': 'Review current NIST terms before redistribution; attribution retained.',
    }, stream, indent=2) or stream.write('\n'))
    return str(Path(db_path).resolve())


def import_malwarebazaar():
    key = os.environ.get('ABUSE_CH_KEY', '').strip()
    if not key:
        raise ValueError('Define ABUSE_CH_KEY; la clave no se guarda en disco ni en el ZIP')
    request = urllib.request.Request(
        API_URL,
        data=urllib.parse.urlencode({'query': 'get_recent', 'selector': 'time'}).encode(),
        headers={'Auth-Key': key, 'User-Agent': 'PyThreatAnalyzer-data-import/3.0'},
        method='POST')
    with urllib.request.urlopen(request, timeout=45) as response:
        payload = json.loads(response.read().decode('utf-8'))
    status = payload.get('query_status')
    if status != 'ok':
        raise ValueError(f'MalwareBazaar respondió query_status={status!r}')
    records = payload.get('data') or []
    hashes_path = DATA / 'denylist' / 'malwarebazaar_sha256.txt'
    metadata_path = DATA / 'denylist' / 'malwarebazaar_metadata.csv'
    current = set()
    if hashes_path.exists():
        current = {line.strip().lower() for line in hashes_path.read_text(encoding='utf-8').splitlines()
                   if SHA256_RE.fullmatch(line.strip())}
    metadata = {}
    if metadata_path.exists():
        with metadata_path.open(encoding='utf-8', newline='') as stream:
            for row in csv.DictReader(stream):
                if SHA256_RE.fullmatch(row.get('sha256', '')):
                    metadata[row['sha256'].lower()] = row
    stamp = datetime.now(timezone.utc).isoformat()
    added = 0
    for record in records:
        sha = str(record.get('sha256_hash') or '').lower()
        if not SHA256_RE.fullmatch(sha):
            continue
        if sha not in current:
            added += 1
        current.add(sha)
        tags = record.get('tags') or []
        metadata[sha] = {
            'sha256': sha,
            'first_seen': str(record.get('first_seen') or ''),
            'tags': ';'.join(map(str, tags)) if isinstance(tags, list) else str(tags),
            'source': 'MalwareBazaar', 'collected_utc': stamp,
        }
    if not current:
        raise ValueError('La respuesta no produjo SHA-256; no se sobrescriben los datos existentes')
    atomic_write(hashes_path, lambda stream: [stream.write(value + '\n') for value in sorted(current)])
    def write_csv(stream):
        writer = csv.DictWriter(stream, fieldnames=['sha256', 'first_seen', 'tags', 'source', 'collected_utc'])
        writer.writeheader()
        writer.writerows(metadata[key] for key in sorted(metadata))
    atomic_write(metadata_path, write_csv)
    return added, len(current), len(records)


def write_checksums():
    checksums = DATA / 'checksums.txt'
    files = sorted(p for p in DATA.rglob('*') if p.is_file() and p != checksums
                   and p.name != '.gitkeep')
    def write(stream):
        for path in files:
            digest_obj = hashlib.sha256()
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    digest_obj.update(chunk)
            digest = digest_obj.hexdigest()
            stream.write(f'{digest}  {path.relative_to(ROOT).as_posix()}\n')
    atomic_write(checksums, write)
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nsrl-sqlite', help='RDSv3 SQLite modern/minimal descargado manualmente desde NIST')
    parser.add_argument('--malwarebazaar', action='store_true', help='Ingiere el feed horario reciente (requiere ABUSE_CH_KEY)')
    parser.add_argument('--checksums-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.nsrl_sqlite:
            print(f'NSRL: SQLite validado y configurado en lectura directa: {import_nsrl(args.nsrl_sqlite)}')
        if args.malwarebazaar:
            added, total, received = import_malwarebazaar()
            print(f'MalwareBazaar: {received} registros API; {added} nuevos; {total:,} acumulados')
        if not (args.nsrl_sqlite or args.malwarebazaar or args.checksums_only):
            parser.error('indica --nsrl-sqlite, --malwarebazaar o --checksums-only')
        print(f'Checksums: actualizados ({write_checksums()} archivos de datos)')
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
