#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
python - "$project_dir" "$@" <<'PY'
import argparse
import os
import sys

sys.path.insert(0, sys.argv[1])
from verificar_y_empaquetar import phase_data_coverage

parser = argparse.ArgumentParser(description='Inspecciona las bases locales y reglas YARA.')
group = parser.add_mutually_exclusive_group()
group.add_argument('--strict', '--release', dest='strict', action='store_true',
                    help='exige cobertura real completa para un release')
group.add_argument('--ci', action='store_true',
                    help='valida el dataset sintético incluido, sin red ni datos de producción')
args = parser.parse_args(sys.argv[2:])
if args.ci:
    from pathlib import Path
    import re
    fixture = Path(sys.argv[1]) / 'tests' / 'fixtures' / 'coverage-seed'
    hashes = fixture / 'denylist' / 'seed_sha256.txt'
    rules = fixture / 'yara_rules' / 'seed_rule.yar'
    values = [line.strip() for line in hashes.read_text(encoding='utf-8').splitlines()
              if line.strip() and not line.lstrip().startswith('#')]
    if len(values) < 3 or any(not re.fullmatch(r'[0-9a-fA-F]{64}', value) for value in values):
        raise SystemExit('Dataset CI inválido: se esperan al menos 3 SHA-256 sintéticos')
    try:
        import yara
        yara.compile(filepath=str(rules))
    except Exception as exc:
        raise SystemExit(f'Regla semilla CI inválida: {exc}')
    print(f'Dataset CI válido: {len(values)} hashes sintéticos y regla YARA compilable')
    raise SystemExit(0)
sys.exit(0 if phase_data_coverage(sys.argv[1], strict=args.strict,
                                 distribution=args.strict) else 1)
PY
