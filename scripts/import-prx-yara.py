#!/usr/bin/env python3
"""Import only PRX-SD YARA sub-sources declared MIT in its source README.

The script never runs PRX-SD's sync.sh. That script can acquire sources with
non-commercial, GPL, Elastic, or other licenses. Supply a checkout that already
contains the synchronized tree and select builtin and/or reversinglabs.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'data' / 'yara_rules'
COMMIT_RE = re.compile(r'^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')
SOURCE_INFO = {
    'builtin': ('prx-builtin', 'PRX-SD Built-in', 'builtin'),
    'reversinglabs': ('reversinglabs', 'ReversingLabs', 'reversinglabs'),
}


def _checksums():
    data_root = ROOT / 'data'
    target = data_root / 'checksums.txt'
    files = sorted(path for path in data_root.rglob('*')
                   if path.is_file() and path != target and path.name != '.gitkeep')
    tmp = target.with_name('.checksums.txt.tmp')
    with tmp.open('w', encoding='utf-8', newline='') as stream:
        for path in files:
            digest = hashlib.sha256()
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(chunk)
            stream.write(f'{digest.hexdigest()}  {path.relative_to(ROOT).as_posix()}\n')
    os.replace(tmp, target)


def import_source(source_dir, source_name, commit, replace=False):
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError('se requiere SHA completo e inmutable de 40 o 64 caracteres')
    source_dir = Path(source_dir).resolve()
    readme = source_dir / 'README.md'
    license_file = source_dir / 'LICENSE'
    if not readme.is_file() or not license_file.is_file():
        raise ValueError('el checkout PRX-SD debe incluir README.md y LICENSE')
    readme_text = readme.read_text(encoding='utf-8', errors='replace')
    repo_license = license_file.read_text(encoding='utf-8', errors='replace')
    if 'Apache License' not in repo_license or 'Version 2.0' not in repo_license:
        raise ValueError('el LICENSE del repositorio PRX-SD cambió; revisar antes de importar')
    label_dir, source_label, upstream_dir = SOURCE_INFO[source_name]
    # Require a current upstream license-table entry for this exact sub-source.
    license_row = next((line for line in readme_text.splitlines()
                        if source_label.lower() in line.lower() and
                        re.search(r'\|\s*MIT\s*\|', line, re.I)), None)
    if not license_row:
        raise ValueError(f'no se encontró declaración MIT para {source_label} en README.md')
    rl_license = source_dir / 'REVERSINGLABS-LICENSE-MIT.txt'
    rl_source = source_dir / 'REVERSINGLABS-SOURCE.txt'
    if source_name == 'reversinglabs':
        license_text = rl_license.read_text(encoding='utf-8', errors='replace') if rl_license.is_file() else ''
        if ('Permission is hereby granted, free of charge' not in license_text or
                'Copyright (c)' not in license_text or 'ReversingLabs' not in license_text):
            raise ValueError('falta el aviso MIT oficial de ReversingLabs; vuelve a ejecutar el fetcher')
        rl_source_meta = rl_source.read_text(encoding='utf-8', errors='replace') if rl_source.is_file() else ''
        rl_commit_match = re.search(r'(?m)^Commit:\s*([0-9a-f]{40})$', rl_source_meta)
        if not rl_commit_match:
            raise ValueError('falta el commit completo del repositorio oficial ReversingLabs')
    else:
        rl_commit_match = None
    rule_root = source_dir / 'yara' / upstream_dir
    rules = sorted(path for path in rule_root.rglob('*') if path.is_file()
                   and path.suffix.lower() in {'.yar', '.yara'}
                   and not path.is_symlink())
    if not rules:
        raise ValueError(f'no hay reglas en yara/{source_name}; revisa el checkout/sincronización local')
    try:
        import yara
    except ImportError as exc:
        raise ValueError('instala yara-python antes de importar reglas') from exc

    DEST.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix='.prx-yara-import-', dir=DEST))
    try:
        copied, rule_count, failed, normalized = 0, 0, [], {}
        digest_map = {}
        for path in rules:
            rel = path.relative_to(rule_root)
            target = staged / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            try:
                yara.compile(filepath=str(target))
            except yara.Error as exc:
                # Some upstream files declare unused strings, which YARA
                # rejects. Removing only those declarations cannot change a
                # rule's condition or matching behavior; record every edit.
                original = target.read_text(encoding='utf-8', errors='replace')
                candidate = original
                removed = []
                while True:
                    try:
                        yara.compile(source=candidate)
                        break
                    except yara.Error as compile_error:
                        match = re.search(r'unreferenced string ["\'](\$[A-Za-z0-9_]+)["\']',
                                          str(compile_error), re.I)
                        if not match:
                            failed.append(f'{rel}: {compile_error}')
                            break
                        name = re.escape(match.group(1))
                        candidate, count = re.subn(
                            rf'(?m)^[ \t]*{name}[ \t]*=.*(?:\r?\n|$)', '', candidate, count=1)
                        if count != 1:
                            failed.append(f'{rel}: no se pudo localizar la declaración {match.group(1)}')
                            break
                        removed.append(match.group(1))
                else:
                    failed.append(f'{rel}: compilación no convergió')
                if failed and failed[-1].startswith(f'{rel}:'):
                    continue
                if removed:
                    note = (f'// Source: https://github.com/openprx/prx-sd-signatures@{commit.lower()} '
                            f'(yara/{upstream_dir}/{rel.as_posix()})\n'
                            '// Modified by PyThreatAnalyzer: removed unreferenced string declarations '
                            'for compiler compatibility; see META.json.\n'
                            '// Original author metadata is preserved; MIT attribution: prx-sd.\n'
                            '// License: see PRX-SD-BUILTIN-LICENSE-MIT.txt and upstream README.\n\n')
                    target.write_text(note + candidate, encoding='utf-8')
                    normalized[rel.as_posix()] = removed
            digest_map[rel.as_posix()] = hashlib.sha256(target.read_bytes()).hexdigest()
            copied += 1
            rule_count += len(re.findall(r'(?im)^\s*private\s+rule\b|^\s*global\s+rule\b|^\s*rule\b',
                                         target.read_text(encoding='utf-8', errors='replace')))
        if failed:
            raise ValueError('una o más reglas no compilaron: ' + '; '.join(failed[:20]))
        if not copied:
            raise ValueError('ninguna regla compiló')

        shutil.copyfile(license_file, staged / 'PRX-SD-CODE-LICENSE-APACHE-2.0.txt')
        shutil.copyfile(readme, staged / 'PRX-SD-README.md')
        if source_name == 'builtin':
            (staged / 'PRX-SD-BUILTIN-LICENSE-MIT.txt').write_text(
                'Copyright (c) prx-sd\n\n'
                'Permission is hereby granted, free of charge, to any person obtaining a copy of\n'
                'this software and associated documentation files (the "Software"), to deal in\n'
                'the Software without restriction, including without limitation the rights to\n'
                'use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies\n'
                'of the Software, and to permit persons to whom the Software is furnished to do\n'
                'so, subject to the following conditions:\n\n'
                'The above copyright notice and this permission notice shall be included in all\n'
                'copies or substantial portions of the Software.\n\n'
                'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
                'IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n'
                'FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n'
                'AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n'
                'LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n'
                'OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n'
                'SOFTWARE.\n', encoding='utf-8')
        if source_name == 'reversinglabs':
            shutil.copyfile(rl_license, staged / 'REVERSINGLABS-LICENSE-MIT.txt')
            shutil.copyfile(rl_source, staged / 'REVERSINGLABS-SOURCE.txt')
        (staged / 'SOURCE.txt').write_text(
            f'Source repository: https://github.com/openprx/prx-sd-signatures\n'
            f'Sub-source: yara/{source_name}\nCommit: {commit.lower()}\n'
            f'Rule license declared in upstream README: MIT\n'
            f'Upstream repository code license: Apache-2.0 (included separately)\n'
            f'License table row: {license_row.strip()}\n'
            f'Imported UTC: {datetime.now(timezone.utc).isoformat()}\n'
            f'Compiled rule files: {copied}\nCompiled rule declarations: {rule_count}\n', encoding='utf-8')
        target_dir = DEST / f'{label_dir}-{commit[:12].lower()}'
        if target_dir.exists():
            raise ValueError(f'el destino ya existe: {target_dir}')
        meta_path = DEST / 'META.json'
        try:
            metadata = json.loads(meta_path.read_text(encoding='utf-8')) if meta_path.exists() else {'sources': []}
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f'META.json inválido; no se instala el conjunto: {exc}') from exc
        if not isinstance(metadata, dict) or not isinstance(metadata.get('sources'), list):
            raise ValueError('META.json debe contener un arreglo "sources"')
        metadata['sources'] = [entry for entry in metadata['sources']
                               if entry.get('source') != source_label]
        metadata['sources'].append({
            'source': source_label,
            'repository': 'https://github.com/openprx/prx-sd-signatures',
            'subdirectory': f'yara/{source_name}',
            'commit': commit.lower(),
            'license': 'MIT (upstream README source table)',
            'license_notice_commit': rl_commit_match.group(1) if rl_commit_match else None,
            'imported_utc': datetime.now(timezone.utc).isoformat(),
            'rule_count': rule_count,
            'rule_file_count': copied,
            'rules_sha256': digest_map,
            'source_rules_sha256': {path.relative_to(rule_root).as_posix():
                                    hashlib.sha256(path.read_bytes()).hexdigest() for path in rules},
            'removed_unreferenced_strings': normalized,
            'directory': target_dir.name,
        })
        metadata['sources'].sort(key=lambda item: item['source'])
        temp_meta = DEST / '.META.json.tmp'
        temp_meta.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
        os.replace(staged, target_dir)
        staged = None
        os.replace(temp_meta, meta_path)
        _checksums()
        return copied
    finally:
        if staged is not None and staged.exists():
            shutil.rmtree(staged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', required=True, help='checkout/sync tree de prx-sd-signatures')
    parser.add_argument('--source', required=True, choices=tuple(SOURCE_INFO),
                        help='solo builtin o reversinglabs; no sincroniza otras fuentes')
    parser.add_argument('--commit', required=True, help='SHA completo del commit importado')
    args = parser.parse_args()
    try:
        count = import_source(args.source_dir, args.source, args.commit)
        print(f'{SOURCE_INFO[args.source][1]}: {count} archivos de reglas compilados e importados')
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
