#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  cat <<'EOF'
Uso: ./setup-data.sh /ruta/al/RDSv3.sqlite

Configura el SQLite RDSv3 de NIST para consultas locales de solo lectura.
Descargue y extraiga el archivo desde la página oficial de NSRL antes de usarlo.
Esta herramienta no descarga ni copia la base, que puede ocupar muchos GB.
La ruta queda en config.local.json, excluido del ZIP y del repositorio.
EOF
  [[ $# -eq 1 ]] || exit 2
  exit 0
fi

project_dir="$(cd "$(dirname "$0")" && pwd)"
sqlite_path="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [[ ! -f "$sqlite_path" ]]; then
  echo "No existe el archivo SQLite: $sqlite_path" >&2
  exit 1
fi

python - "$project_dir" "$sqlite_path" <<'PY'
import json
import os
import hashlib
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

root, db_path = sys.argv[1:]
uri = Path(db_path).as_uri() + '?mode=ro'
try:
    with sqlite3.connect(uri, uri=True, timeout=10) as db:
        objects = db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')").fetchall()
        found = False
        for (name,) in objects:
            escaped = str(name).replace('"', '""')
            columns = db.execute(f'PRAGMA table_info("{escaped}")').fetchall()
            column = next((str(row[1]) for row in columns if str(row[1]).lower() == 'sha256'), None)
            if column:
                escaped_column = column.replace('"', '""')
                if db.execute(f'SELECT 1 FROM "{escaped}" WHERE "{escaped_column}" IS NOT NULL LIMIT 1').fetchone():
                    found = True
                    break
    if not found:
        raise ValueError('No se encontró SHA256 con datos en el SQLite')
except (OSError, sqlite3.Error, ValueError) as exc:
    raise SystemExit(f'NSRL inválido; no se modificó la configuración: {exc}')

download_date = os.environ.get('NSRL_DOWNLOAD_DATE', '').strip()
if download_date and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', download_date):
    raise SystemExit('NSRL_DOWNLOAD_DATE debe tener formato YYYY-MM-DD')

config_path = os.path.join(root, 'config.local.json')
config = {}
if os.path.isfile(config_path):
    with open(config_path, encoding='utf-8') as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise SystemExit('config.local.json debe contener un objeto JSON')
config['nsrl_db'] = db_path
fd, temp_path = tempfile.mkstemp(prefix='.config.local.', dir=root, text=True)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(config, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp_path, config_path)
except Exception:
    try:
        os.unlink(temp_path)
    except OSError:
        pass
    raise

digest = hashlib.sha256()
with open(db_path, 'rb') as source:
    for chunk in iter(lambda: source.read(4 * 1024 * 1024), b''):
        digest.update(chunk)
metadata = {
    'source': 'NIST NSRL RDSv3',
    'source_url': 'https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/nsrl-download-0',
    'license': 'Public domain; retain NIST attribution',
    'database_file': os.path.basename(db_path),
    'database_size_bytes': os.path.getsize(db_path),
    'database_sha256': digest.hexdigest(),
    'download_date': download_date or 'not-recorded; set NSRL_DOWNLOAD_DATE=YYYY-MM-DD when configuring',
    'configured_utc': datetime.now(timezone.utc).isoformat(),
}
metadata_path = os.path.join(root, 'nsrl.local.json')
fd, temp_path = tempfile.mkstemp(prefix='.nsrl.local.', dir=root, text=True)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(metadata, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp_path, metadata_path)
except Exception:
    try:
        os.unlink(temp_path)
    except OSError:
        pass
    raise
print(f'NSRL configurado para consulta local de solo lectura: {db_path}')
print(f'Checksum SHA-256 de la base registrado en nsrl.local.json: {metadata["database_sha256"]}')
print('Reinicia PyThreatAnalyzer para aplicar la configuración.')
PY
