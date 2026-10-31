#!/usr/bin/env python3
"""Stage reviewed YARA rules from an already downloaded source tree.

This intentionally does not clone repositories or select a moving branch.
The operator must provide a full immutable commit, source URL, and reviewed
license. Rules that declare a conflicting/non-commercial license are rejected.
"""
import argparse
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'data' / 'yara_rules'
COMMIT_RE = re.compile(r'^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')
LICENSE_RE = re.compile(r"(?im)^\s*license\s*=\s*[\"']([^\"']+)[\"']")


def import_rules(source, source_url, commit, declared_license):
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError('se requiere un commit SHA completo e inmutable')
    if declared_license not in {'MIT', 'DRUL-1.0'}:
        raise ValueError('solo se admiten licencias revisadas MIT o DRUL-1.0')
    source = Path(source).resolve()
    license_file = next((p for p in (source / 'LICENSE', source / 'LICENSE.txt',
                                     source / 'LICENSE.md') if p.is_file()), None)
    if not license_file:
        raise ValueError('el árbol fuente debe incluir el texto LICENSE para atribución')
    license_text = license_file.read_text(encoding='utf-8', errors='replace')
    if declared_license == 'MIT' and 'MIT License' not in license_text:
        raise ValueError('el texto LICENSE no parece corresponder a MIT')
    if declared_license == 'DRUL-1.0' and not re.search(r'Detection Rule License.*1\.0|DRUL\s*1\.0', license_text, re.I | re.S):
        raise ValueError('el texto LICENSE no identifica claramente DRUL 1.0')

    rules = sorted(p for p in source.rglob('*')
                   if p.is_file() and not p.is_symlink()
                   and p.suffix.lower() in {'.yar', '.yara'})
    if not rules:
        raise ValueError('no se encontraron archivos .yar/.yara')
    staged = Path(tempfile.mkdtemp(prefix='.yara-import-', dir=DEST))
    try:
        import yara
        copied = 0
        for path in rules:
            text = path.read_text(encoding='utf-8', errors='replace')
            for license_name in LICENSE_RE.findall(text):
                normalized = license_name.strip().upper().replace('_', '-').replace(' ', '-')
                if any(flag in normalized for flag in ('NC', 'NON-COMMERCIAL', 'PROPRIETARY')):
                    raise ValueError(f'licencia no redistribuible declarada en {path}: {license_name}')
                if declared_license == 'MIT' and normalized not in {'MIT'}:
                    raise ValueError(f'licencia por regla distinta a MIT en {path}: {license_name}')
                if declared_license == 'DRUL-1.0' and normalized not in {'DRUL-1.0', 'DETECTION-RULE-LICENSE-1.0'}:
                    raise ValueError(f'licencia por regla distinta a DRUL 1.0 en {path}: {license_name}')
            relative = path.relative_to(source)
            target = staged / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            try:
                yara.compile(filepath=str(target))
            except yara.Error as exc:
                target.unlink()
                print(f'OMITIDA (no compila): {relative}: {exc}', file=sys.stderr)
                continue
            copied += 1
        if not copied:
            raise ValueError('ninguna regla compiló; el destino existente se conserva')
        shutil.copyfile(license_file, staged / 'LICENSE')
        notice = staged / 'SOURCE.txt'
        notice.write_text(
            f'Source: {source_url}\nCommit: {commit.lower()}\nLicense: {declared_license}\n'
            f'Imported UTC: {__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}\n'
            f'Rules copied and individually compiled: {copied}\n', encoding='utf-8')
        dest = DEST / f'{declared_license.lower()}-{commit[:12].lower()}'
        if dest.exists():
            raise ValueError(f'el destino ya existe: {dest}; no se sobrescribe')
        os.replace(staged, dest)
        return copied
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', required=True, help='árbol fuente ya descargado; no se ejecuta código del repo')
    parser.add_argument('--source-url', required=True)
    parser.add_argument('--commit', required=True, help='SHA completo de 40 o 64 caracteres')
    parser.add_argument('--license', required=True, choices=('MIT', 'DRUL-1.0'))
    args = parser.parse_args()
    DEST.mkdir(parents=True, exist_ok=True)
    try:
        print(f'Reglas importadas: {import_rules(args.source_dir, args.source_url, args.commit, args.license)}')
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
