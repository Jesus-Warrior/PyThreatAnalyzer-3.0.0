#!/usr/bin/env python3
"""Import TweetFeed SHA-256 IOCs without retaining other IOC types or samples.

Uses TweetFeed's published full-window CSV endpoint with conditional requests.
The feed has no header row and is refreshed by its publisher every 15 minutes.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DENYLIST = ROOT / 'data' / 'denylist'
CSV_URL = 'https://tweetfeed.live/feeds/{window}.csv'
SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')
MAX_FEED_BYTES = 256 * 1024 * 1024


def atomic_write(path, writer, binary=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        mode = 'wb' if binary else 'w'
        kwargs = {} if binary else {'encoding': 'utf-8', 'newline': ''}
        with os.fdopen(fd, mode, **kwargs) as stream:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _download(window, metadata_path):
    old = {}
    if metadata_path.is_file():
        try:
            old = json.loads(metadata_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            old = {}
    # Do not accept a 304 when the cached IOC list is missing or has drifted.
    hash_path = DENYLIST / 'tweetfeed_sha256.txt'
    if not hash_path.is_file() or not old.get('hashlist_sha256'):
        old = {}
    else:
        digest = hashlib.sha256(hash_path.read_bytes()).hexdigest()
        if digest != old.get('hashlist_sha256'):
            old = {}
    headers = {
        'User-Agent': 'curl/8.1.0 PyThreatAnalyzer-data-import/3.0',
        'Accept': 'text/csv, text/plain;q=0.9, */*;q=0.8',
    }
    if old.get('etag'):
        headers['If-None-Match'] = old['etag']
    if old.get('last_modified'):
        headers['If-Modified-Since'] = old['last_modified']
    request = urllib.request.Request(CSV_URL.format(window=window), headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=90)
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and old:
            return None, None, None, old
        raise
    with response:
        if response.status != 200:
            raise ValueError(f'TweetFeed respondió HTTP {response.status}')
        temp = tempfile.NamedTemporaryFile(prefix='.tweetfeed-download-', dir=DENYLIST,
                                           delete=False)
        digest = hashlib.sha256()
        size = 0
        try:
            with temp:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_FEED_BYTES:
                        raise ValueError(f'CSV supera el límite local de {MAX_FEED_BYTES:,} bytes')
                    digest.update(chunk)
                    temp.write(chunk)
            new_meta = {
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'payload_sha256': digest.hexdigest(),
                'payload_bytes': size,
            }
            return Path(temp.name), digest.hexdigest(), size, new_meta
        except Exception:
            try:
                os.unlink(temp.name)
            except OSError:
                pass
            raise


def parse_sha256(csv_path):
    values = set()
    rows_seen = invalid = 0
    with csv_path.open('r', encoding='utf-8-sig', newline='') as stream:
        reader = csv.reader(stream)
        for row in reader:
            if not row or not any(field.strip() for field in row):
                continue
            # The documented feed has no header and columns:
            # date,user,type,value,tags,tweet_url. Allow a future header row.
            lowered = [field.strip().lower() for field in row]
            if len(lowered) >= 4 and lowered[0] == 'date' and lowered[2] == 'type':
                continue
            rows_seen += 1
            if len(row) < 4 or row[2].strip().lower() != 'sha256':
                continue
            value = row[3].strip().lower()
            if not SHA256_RE.fullmatch(value):
                invalid += 1
                continue
            values.add(value)
    if not values:
        raise ValueError('TweetFeed no produjo hashes SHA-256 válidos; no se reemplaza la lista actual')
    return sorted(values), rows_seen, invalid


def write_checksums():
    checksums = ROOT / 'data' / 'checksums.txt'
    files = sorted(path for path in (ROOT / 'data').rglob('*')
                   if path.is_file() and path != checksums and path.name != '.gitkeep')

    def write(stream):
        for path in files:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            stream.write(f'{digest}  {path.relative_to(ROOT).as_posix()}\n')

    atomic_write(checksums, write)


def import_feed(window):
    DENYLIST.mkdir(parents=True, exist_ok=True)
    metadata_path = DENYLIST / 'tweetfeed_meta.json'
    csv_path, payload_hash, payload_bytes, response_meta = _download(window, metadata_path)
    if csv_path is None:
        print('TweetFeed: sin cambios (respuesta HTTP 304); checksums no modificados')
        return 0
    try:
        hashes, rows_seen, invalid = parse_sha256(csv_path)
    finally:
        try:
            csv_path.unlink()
        except OSError:
            pass
    now = datetime.now(timezone.utc).isoformat()
    hash_path = DENYLIST / 'tweetfeed_sha256.txt'
    meta = {
        'source': 'TweetFeed',
        'source_url': CSV_URL.format(window=window),
        'license': 'CC0-1.0',
        'attribution': 'IOC data from TweetFeed (CC0)',
        'window': window,
        'downloaded_utc': now,
        'payload_sha256': payload_hash,
        'payload_bytes': payload_bytes,
        'etag': response_meta.get('etag'),
        'last_modified': response_meta.get('last_modified'),
        'rows_seen': rows_seen,
        'invalid_sha256_rows': invalid,
        'unique_sha256_count': len(hashes),
        'hashlist_sha256': hashlib.sha256((''.join(value + '\n' for value in hashes)).encode('ascii')).hexdigest(),
    }
    atomic_write(hash_path, lambda stream: [stream.write(value + '\n') for value in hashes])
    atomic_write(metadata_path, lambda stream: (json.dump(meta, stream, indent=2), stream.write('\n')))
    write_checksums()
    return len(hashes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--window', choices=('today', 'week', 'month', 'year'), default='year',
                        help='ventana del snapshot; year mantiene hasta 365 días (default)')
    args = parser.parse_args()
    try:
        count = import_feed(args.window)
        if count:
            print(f'TweetFeed: {count:,} SHA-256 únicos importados; checksums regenerados')
    except Exception as exc:
        print(f'ERROR: no se actualizó TweetFeed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
