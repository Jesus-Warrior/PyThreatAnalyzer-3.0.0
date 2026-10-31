"""
Descarga y cura reglas YARA de la comunidad (Yara-Rules/rules) hacia
yara_rules/community/.

Por qué "cura" y no solo copia: el repositorio incluye reglas que dependen
de módulos que yara-python estándar no trae compilados (ej. `cuckoo`,
`androguard`), lo que rompería la compilación conjunta. Este script prueba
CADA regla individualmente y solo conserva las que compilan, para que
YARAEngine arranque con una base 100% funcional.

Uso:
    python3 update_yara_rules.py                # clona/actualiza y cura
    python3 update_yara_rules.py --skip-clone    # solo re-cura lo ya clonado

Requiere git y la librería yara-python instalada.
"""

import argparse
import os
import shutil
import subprocess
import sys
import json
import tempfile
import hashlib
import re

REPO_URL = "https://github.com/Yara-Rules/rules.git"
CLONE_DIR = os.path.join(os.path.dirname(__file__), '.yara_source_cache')
DEST_DIR = os.path.join(os.path.dirname(__file__), 'yara_rules', 'community')

# Categorías relevantes para análisis general de malware. Se excluyen
# deliberadamente: 'deprecated' (obsoletas), 'email' (poco aplicable aquí),
# 'mobile_malware' (casi todas dependen del módulo androguard, no disponible
# en yara-python estándar), y los archivos index*.yar (usan `include` y
# duplicarían reglas ya cubiertas por las carpetas individuales).
INCLUDE_DIRS = {
    'malware', 'packers', 'maldocs', 'webshells',
    'antidebug_antivm', 'capabilities', 'exploit_kits', 'cve_rules',
}


def resolve_dest_dir(cli_dest=None, cwd=None):
    """Directorio donde dejar las reglas curadas.

    Prioridad: --dest > <yara_rules_path de config.json en el cwd>/community >
    DEST_DIR (junto a este script)."""
    if cli_dest:
        return os.path.abspath(cli_dest)
    cfg_path = os.path.join(cwd or os.getcwd(), 'config.json')
    try:
        with open(cfg_path, encoding='utf-8') as f:
            rules_path = json.load(f).get('yara_rules_path')
        if isinstance(rules_path, str) and rules_path.strip():
            return os.path.abspath(os.path.join(cwd or os.getcwd(), rules_path, 'community'))
    except (OSError, ValueError):
        pass
    return DEST_DIR


def clone_or_update(commit):
    if not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', commit or ''):
        raise ValueError('--commit debe ser un SHA completo de 40 o 64 dígitos hexadecimales')
    if os.path.isdir(CLONE_DIR):
        print(f"Obteniendo commit fijado en {CLONE_DIR} ...")
        subprocess.run(['git', '-C', CLONE_DIR, 'fetch', '--depth', '1', 'origin', commit],
                       check=True, timeout=120)
    else:
        print(f"Clonando {REPO_URL} en el commit solicitado ...")
        subprocess.run(['git', 'clone', '--no-checkout', '--filter=blob:none',
                        REPO_URL, CLONE_DIR], check=True, timeout=120)
        subprocess.run(['git', '-C', CLONE_DIR, 'fetch', '--depth', '1', 'origin', commit],
                       check=True, timeout=120)
    subprocess.run(['git', '-C', CLONE_DIR, 'checkout', '--detach', commit],
                   check=True, timeout=120)


def curate():
    try:
        import yara
    except ImportError:
        print("ERROR: yara-python no está instalado. Ejecuta: pip install yara-python --break-system-packages")
        sys.exit(1)

    valid, invalid, group_compile_errors = [], [], []
    candidates = {}

    for dirpath, _dirnames, filenames in os.walk(CLONE_DIR):
        rel_dir = os.path.relpath(dirpath, CLONE_DIR)
        top = rel_dir.split(os.sep)[0]
        if top not in INCLUDE_DIRS:
            continue
        for fname in filenames:
            if not fname.endswith(('.yar', '.yara')):
                continue
            if fname.startswith('index') or fname.endswith('_index.yar'):
                continue
            candidates.setdefault(top, []).append(os.path.join(dirpath, fname))

    # Compilar cada categoría como grupo conserva reglas que dependen de
    # otras reglas/includes de su misma categoría. Si un grupo falla, se
    # conserva el fallback individual para no perder las reglas válidas.
    for category, files in candidates.items():
        filepaths = {}
        for source in files:
            rel = os.path.relpath(source, CLONE_DIR).replace(os.sep, '/')
            namespace = 'r_' + hashlib.sha256(rel.encode('utf-8')).hexdigest()[:20]
            filepaths[namespace] = source
        try:
            yara.compile(filepaths=filepaths)
            valid.extend(files)
        except yara.Error as group_error:
            group_compile_errors.append({
                'category': category,
                'error': str(group_error),
                'fallback': 'individual',
            })
            for source in files:
                try:
                    yara.compile(filepath=source)
                    valid.append(source)
                except yara.Error as exc:
                    invalid.append({
                        'file': os.path.relpath(source, CLONE_DIR),
                        'error': str(exc),
                    })

    if not valid:
        raise RuntimeError(
            "No se compiló ninguna regla YARA; se conserva el ruleset activo."
        )

    parent = os.path.dirname(DEST_DIR)
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix='.community-rules-', dir=parent)
    backup = DEST_DIR + '.previous'
    moved_old = False
    try:
        for source in valid:
            rel = os.path.relpath(source, CLONE_DIR)
            destination = os.path.join(staging, rel)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.copy2(source, destination)

        revision = subprocess.run(
            ['git', '-C', CLONE_DIR, 'rev-parse', 'HEAD'], check=True,
            capture_output=True, text=True, timeout=10
        ).stdout.strip()
        manifest = {
            'source': REPO_URL,
            'revision': revision,
            'valid_count': len(valid),
            'skipped_count': len(invalid),
            'group_compile_errors': group_compile_errors,
            'skipped': invalid,
        }
        with open(os.path.join(staging, '_manifest.json'), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

        if os.path.isdir(backup):
            shutil.rmtree(backup)
        if os.path.isdir(DEST_DIR):
            os.replace(DEST_DIR, backup)
            moved_old = True
        try:
            os.replace(staging, DEST_DIR)
        except Exception:
            if moved_old and not os.path.exists(DEST_DIR):
                os.replace(backup, DEST_DIR)
                moved_old = False
            raise
        if moved_old:
            shutil.rmtree(backup)
    finally:
        if os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)

    print(f"✅ {len(valid)} reglas válidas copiadas a {DEST_DIR}")
    print(f"⚠️  {len(invalid)} reglas omitidas (módulo no soportado / error de sintaxis) — ver _manifest.json")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Descarga y cura reglas YARA de la comunidad")
    parser.add_argument('--skip-clone', action='store_true', help="No clonar/actualizar, solo re-curar lo existente")
    parser.add_argument('--commit', help='SHA completo fijado a revisar (requerido salvo --skip-clone)')
    parser.add_argument('--dest', help="Directorio destino de las reglas curadas. Por defecto: "
                        "<yara_rules_path de ./config.json>/community si existe config.json en el "
                        "directorio actual (donde YARAEngine las lee); si no, junto a este script.")
    args = parser.parse_args()

    # N-18 residual: el destino por defecto era siempre junto al módulo, pero
    # YARAEngine lee `yara_rules_path` relativo al directorio de trabajo; en una
    # instalación (site-packages) las reglas quedaban donde nadie las busca.
    DEST_DIR = resolve_dest_dir(args.dest)
    print(f"Destino de las reglas: {DEST_DIR}")

    if not args.skip_clone:
        if not args.commit:
            parser.error('--commit es obligatorio para descargar reglas reproducibles')
        try:
            clone_or_update(args.commit)
        except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            parser.error(f'no se pudo fijar el commit solicitado: {exc}')
    elif not os.path.isdir(CLONE_DIR):
        print(f"ERROR: {CLONE_DIR} no existe. Ejecuta sin --skip-clone primero.")
        sys.exit(1)

    curate()
