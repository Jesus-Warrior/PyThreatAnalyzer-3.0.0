#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python - <<'PY'
import pathlib
import re
import tomllib

with open('pyproject.toml', 'rb') as stream:
    data = tomllib.load(stream)
assert 'version' not in data['project'], 'project.version must be dynamic'
assert data['project'].get('dynamic') == ['version'], 'version must be dynamic'
assert data['tool']['setuptools']['dynamic']['version']['attr'] == 'pythreat_version.__version__'
assert 'pythreat_version' in data['tool']['setuptools']['py-modules']
assert {'malware_hashes.txt', 'malware_imphashes.txt', 'malware_tlsh.txt', 'malware_ssdeep.txt'} <= set(data['tool']['setuptools']['data-files']['.'])
assert pathlib.Path('data/NOTICE').is_file()
assert pathlib.Path('data/checksums.txt').is_file()
version = pathlib.Path('pythreat_version.py').read_text(encoding='utf-8')
assert re.search(r"^__version__\s*=\s*['\"]3\.0\.0['\"]\s*$", version, re.M)

engine = pathlib.Path('analysis_cache.py').read_text(encoding='utf-8')
assert len(re.findall(r'^ENGINE_VERSION\s*=\s*6\s*$', engine, re.M)) == 1, 'expected one ENGINE_VERSION = 6'

schema_allowed = {'report_generator.py', 'cli.py', 'test_pythreatanalyzer.py'}
schema_files = {p.name for p in pathlib.Path('.').rglob('*.py')
                if 'report_schema_version' in p.read_text(encoding='utf-8', errors='replace')}
assert schema_files <= schema_allowed, f'report_schema_version in unexpected files: {schema_files - schema_allowed}'
assert "'file_hash':" not in pathlib.Path('dynamic_analyzer.py').read_text(encoding='utf-8')

changelog = pathlib.Path('CHANGELOG.md').read_text(encoding='utf-8')
found_ids = re.findall(r'\b(?:M[1-5]|B[1-7]|K[1-9](?:\.[12])?|N[1-2])\b', changelog)
ids = set(found_ids)
expected = {*(f'M{i}' for i in range(1, 6)), *(f'B{i}' for i in range(1, 8)),
            *(f'K{i}' for i in range(1, 5)), 'K5.1', 'K5.2',
            *(f'K{i}' for i in range(6, 10)), 'N1', 'N2'}
assert ids == expected, f'changelog IDs mismatch: missing={expected-ids}, extra={ids-expected}'
assert len(found_ids) == 24 and len(set(found_ids)) == 24, 'each of the 24 changelog IDs must appear once'
SKIP_DIRS = {'.git', '.venv', 'venv', 'env', 'dist', 'build', '__pycache__',
             '.pytest_cache', '.mypy_cache', 'node_modules'}
def walk(pattern):
    return (p for p in pathlib.Path('.').rglob(pattern) if not SKIP_DIRS.intersection(p.parts))
for p in walk('*.py'):
    assert 'v2.0.0' not in p.read_text(encoding='utf-8', errors='replace'), f'old version reference in {p}'
for p in walk('*'):
    if not p.is_file() or p.name == 'CHANGELOG.md' or p == pathlib.Path('scripts/check-consistency.sh'):
        continue
    try:
        text = p.read_text(encoding='utf-8')
    except (UnicodeError, OSError):
        continue
    assert 'v2.0.0' not in text, f'historical version reference outside changelog: {p}'
PY

if grep -REn 'SUSPICIOUS_IMPORTS' --exclude-dir=.git --exclude='check-consistency.sh' .; then
    echo 'SUSPICIOUS_IMPORTS remains' >&2
    exit 1
fi
python -c 'from script_analyzer import ScriptAnalyzer'
version_output="$(python cli.py --version)"
test "$version_output" = 'PyThreatAnalyzer 3.0.0'
