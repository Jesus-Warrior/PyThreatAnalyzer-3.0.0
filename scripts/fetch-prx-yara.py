#!/usr/bin/env python3
"""Download only PRX-SD Built-in and ReversingLabs YARA files at a pinned commit.

This never clones the repository or downloads any other PRX-SD data source.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = 'openprx/prx-sd-signatures'
PREFIXES = ('yara/builtin/', 'yara/reversinglabs/')
ROOT_FILES = ('README.md', 'LICENSE')
MAX_FILES = 500
MAX_TOTAL_BYTES = 128 * 1024 * 1024


def get(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'PyThreatAnalyzer-data-import/3.0'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def fetch_one(args):
    commit, base, item = args
    path = item['path']
    target = base / path
    if target.is_file():
        cached = target.read_bytes()
        digest = hashlib.sha1(f'blob {len(cached)}\0'.encode() + cached).hexdigest()
        if digest == item['sha']:
            return 0
    raw = get(f'https://raw.githubusercontent.com/{REPO}/{commit}/{path}')
    digest = hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest()
    if digest != item['sha']:
        raise ValueError(f'Git blob SHA no coincide: {path}')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return len(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True, help='SHA completo de 40 caracteres')
    parser.add_argument('--destination', required=True, help='directorio temporal/local de trabajo')
    args = parser.parse_args()
    commit = args.commit.lower()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        parser.error('--commit debe ser un SHA Git completo de 40 caracteres')
    destination = Path(args.destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    try:
        tree = json.loads(get(f'https://api.github.com/repos/{REPO}/git/trees/{commit}?recursive=1'))
        if tree.get('sha') != commit or tree.get('truncated'):
            raise ValueError('el árbol Git no corresponde al commit o llegó truncado')
        selected = [item for item in tree['tree'] if item.get('type') == 'blob' and
                    (item['path'] in ROOT_FILES or
                     (item['path'].startswith(PREFIXES) and
                      Path(item['path']).suffix.lower() in {'.yar', '.yara'}))]
        if any(not any(item['path'] == root for item in selected) for root in ROOT_FILES):
            raise ValueError('README.md o LICENSE no están presentes en el commit fijado')
        if len(selected) > MAX_FILES:
            raise ValueError(f'se rechaza descargar {len(selected)} archivos (límite {MAX_FILES})')
        if not all(any(item['path'].startswith(prefix) for prefix in PREFIXES) for item in selected
                   if item['path'] not in ROOT_FILES):
            raise ValueError('el árbol contiene una ruta fuera de las subfuentes seleccionadas')
        total = 0
        with ThreadPoolExecutor(max_workers=8) as pool:
            for size in pool.map(fetch_one, ((commit, destination, item) for item in selected)):
                total += size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError(f'descarga supera el límite local de {MAX_TOTAL_BYTES:,} bytes')
        # Keep the official ReversingLabs MIT notice with that sub-source.
        rl_repo = json.loads(get('https://api.github.com/repos/reversinglabs/reversinglabs-yara-rules'))
        rl_branch = rl_repo['default_branch']
        rl_commit = json.loads(get(
            f'https://api.github.com/repos/reversinglabs/reversinglabs-yara-rules/commits/{rl_branch}'))['sha']
        rl_license = get(
            f'https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/{rl_commit}/LICENSE')
        if (b'Permission is hereby granted, free of charge' not in rl_license or
                b'Copyright (c)' not in rl_license or b'ReversingLabs' not in rl_license):
            raise ValueError('la licencia oficial actual de ReversingLabs no coincide con MIT')
        (destination / 'REVERSINGLABS-LICENSE-MIT.txt').write_bytes(rl_license)
        (destination / 'REVERSINGLABS-SOURCE.txt').write_text(
            f'Repository: https://github.com/reversinglabs/reversinglabs-yara-rules\n'
            f'Commit: {rl_commit}\nLicense: MIT\n', encoding='utf-8')
        print(f'Commit {commit}: {len(selected) - 2} archivos YARA seleccionados, {total:,} bytes')
        print(f'Tree: {destination}')
    except (OSError, urllib.error.URLError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f'ERROR: descarga selectiva fallida: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
