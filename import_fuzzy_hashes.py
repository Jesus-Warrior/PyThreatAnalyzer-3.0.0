
#!/usr/bin/env python3
"""
import_fuzzy_hashes.py - Puebla las bases fuzzy de PyThreatAnalyzer.

Recorre carpeta(s) de muestras de malware y calcula:
  - TLSH   -> malware_tlsh.txt   (lo consume StaticAnalyzer.check_reputation())
  - ssdeep -> malware_ssdeep.txt

IMPORTANTE (FIX BUG A): los hashes se guardan en su CASO ORIGINAL. El cuerpo
de ssdeep es Base64 (case-sensitive) y TLSH es hex canónico en MAYÚSCULAS:
NUNCA se lowercasean. Al cargar, las entradas que no cumplan el formato se
SALTAN con aviso (protege contra bases legado generadas en minúsculas:
usa --replace).

Consistencia: el TLSH se calcula con AdvancedFeatures (virus_analyzer.py)
usando el MISMO muestreo cabecera+cola de 10 MB que check_reputation(), y el
ssdeep con ssdeep.hash_from_file(). Referencias == probes.

Integración con la suite (test_area7_fuzzy_importer):
  - _importer_main(argv=None) -> int  (parsea argv, ejecuta, retorna 0)
  - IMPORTER_STATE = {} con claves (tipo, ruta absoluta) y valores
    (entradas, cantidad inválida); se conserva entre llamadas in-process.

Uso:
  python import_fuzzy_hashes.py carpeta_muestras/
  python import_fuzzy_hashes.py carpeta1/ carpeta2/ --no-recursive
  python import_fuzzy_hashes.py muestras/ --replace
  python import_fuzzy_hashes.py muestras/ --dry-run
  python import_fuzzy_hashes.py muestras/ --manifest fuzzy_manifest.json

Nota de rendimiento: el fuzzy matching escanea hasta _FUZZY_SCAN_MAX (2000)
referencias por archivo. Bases mucho más grandes solo se comparan parcialmente
(se avisa al superar el tope).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile

try:
    from virus_analyzer import (AdvancedFeatures, _TLSH_AVAILABLE,
                                _SSDEEP_AVAILABLE, _FUZZY_SCAN_MAX)
    _VIRUS_ANALYZER_OK = True
except ImportError:
    _VIRUS_ANALYZER_OK = False
    _TLSH_AVAILABLE = _SSDEEP_AVAILABLE = False
    _FUZZY_SCAN_MAX = 2000

if _SSDEEP_AVAILABLE:
    import ssdeep
else:
    ssdeep = None

# Formatos válidos:
# - TLSH: 'T1' + 70 hex en MAYÚSCULAS (formato canónico de la librería).
#         Se acepta la variante sin prefijo (70 hex mayúsculas) por
#         compatibilidad con bases legadas. FIX #4: NO se aceptan minúsculas
#         — un hash lowercase nunca matchearía contra el probe canónico y
#         silenciosamente haría inútil la base.
# - ssdeep: 'bloque:hb:hb'; componentes vacíos permitidos en muestras pequeñas.
#           Base64 es case-sensitive: NO se normaliza.
TLSH_RE = re.compile(r'^(?:T1)?[0-9A-F]{70}$')
SSDEEP_RE = re.compile(r'^\d+:[A-Za-z0-9+/]*:[A-Za-z0-9+/]*$')

DEFAULT_MIN_SIZE = 256          # TLSH no calcula por debajo de 256 bytes

# Caché in-process para la suite. Clave: (tipo, ruta absoluta normalizada).
# Valor: (entradas, cantidad inválida); evita reparsear la misma base por ruta.
# None = recargar desde disco en la próxima ejecución.
# El CLI no lo usa (cada proceso es fresco).
IMPORTER_STATE = {}


def load_existing(path, kind):
    """Carga la base existente SIN tocar el caso (FIX BUG A). Valida cada
    entrada contra su formato y salta las inválidas con aviso (una base
    generada en minúsculas por una versión vieja no envenena el fuzzy).
    Devuelve (set_entradas, cantidad_invalida). Resultado cacheado en
    IMPORTER_STATE por tipo y ruta absoluta de la base."""
    cache_key = (kind, os.path.normcase(os.path.abspath(os.fspath(path))))
    cached = IMPORTER_STATE.get(cache_key)
    if cached is not None:
        return cached

    entries, invalid = set(), 0
    valid_re = TLSH_RE if kind == 'tlsh' else SSDEEP_RE
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if not valid_re.match(line):
                    invalid += 1
                    print(f"⚠️  {os.path.basename(path)}:{lineno}: entrada inválida "
                          f"salteada ({line[:24]}...) — usa --replace para regenerar")
                    continue
                entries.add(line)

    IMPORTER_STATE[cache_key] = (entries, invalid)
    return IMPORTER_STATE[cache_key]


def collect_files(paths, recursive=True):
    """Recolecta archivos regulares. NO sigue symlinks (evita ciclos)."""
    files = []
    for p in paths:
        if os.path.islink(p):
            print(f"⏭️  symlink ignorado: {p}")
            continue
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            if recursive:
                for root, dirs, names in os.walk(p, followlinks=False):
                    dirs[:] = [d for d in dirs
                               if not os.path.islink(os.path.join(root, d))]
                    for n in names:
                        full = os.path.join(root, n)
                        if not os.path.islink(full):
                            files.append(full)
            else:
                for n in os.listdir(p):
                    full = os.path.join(p, n)
                    if os.path.isfile(full) and not os.path.islink(full):
                        files.append(full)
        else:
            print(f"⚠️  no existe o no accesible: {p}")
    return sorted(files)


def compute_sha256(path):
    try:
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                sha.update(chunk)
        return sha.hexdigest()
    except OSError:
        return None


def write_db(path, entries):
    """Escribe con temporal único y reemplazo atómico, incluso en concurrencia."""
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix='.fuzzy-', suffix='.tmp', dir=directory)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
            for value in sorted(entries):
                f.write(value + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def run(args):
    if not _VIRUS_ANALYZER_OK:
        print("ERROR: virus_analyzer.py debe estar en el mismo directorio.",
              file=sys.stderr)
        return 1
    if not (_TLSH_AVAILABLE or _SSDEEP_AVAILABLE):
        print("ERROR: ni 'tlsh' ni 'ssdeep' están instalados "
              "(pip install python-tlsh ssdeep). Nada que importar.",
              file=sys.stderr)
        return 1

    known = {'malware_tlsh.txt', 'malware_ssdeep.txt'}
    nonstandard = [p for p in (args.tlsh_db, args.ssdeep_db)
                   if os.path.basename(os.path.normpath(p)) not in known]
    for destination in nonstandard:
        print(f"⚠️  Destino no estándar: {destination}. Verifica que sea la base correcta.",
              file=sys.stderr)
    if args.replace and nonstandard and not args.yes:
        try:
            answer = input(f"¿Reemplazar base(s) no estándar {nonstandard}? [y/N] ").strip().lower()
        except EOFError:
            answer = ''
        if answer != 'y':
            print("Operación cancelada; no se modificaron las bases.", file=sys.stderr)
            return 1

    # FIX #1: claves coherentes con load_existing() ('tlsh' / 'ssdeep').
    # Con --replace las bases parten de set() y se sobreescribe el cache.
    if args.replace:
        tlsh_set, ssdeep_set = set(), set()
    else:
        tlsh_set, _ = load_existing(args.tlsh_db, 'tlsh')
        ssdeep_set, _ = load_existing(args.ssdeep_db, 'ssdeep')

    adv = AdvancedFeatures(None)
    manifest = {} if args.manifest else None
    seen_sha = set()

    files = collect_files(args.paths, recursive=not args.no_recursive)
    print(f"Archivos candidatos: {len(files)}")

    processed = skipped_small = skipped_dup = errors = 0
    new_tlsh = new_ssdeep = 0

    for path in files:
        try:
            if os.path.getsize(path) < args.min_size:
                skipped_small += 1
                continue
        except OSError as e:
            errors += 1
            print(f"⚠️  {path}: {e}")
            continue

        sha = compute_sha256(path)
        if sha is None:
            errors += 1
            print(f"⚠️  {path}: no legible")
            continue
        if sha in seen_sha:
            skipped_dup += 1          # copia/hardlink de una ya procesada
            continue
        seen_sha.add(sha)

        tlsh_val = adv.calculate_tlsh(path) if _TLSH_AVAILABLE else None
        try:
            ssdeep_val = ssdeep.hash_from_file(path) if _SSDEEP_AVAILABLE else None
        except Exception as e:
            ssdeep_val = None
            print(f"⚠️  {path}: ssdeep falló ({e})")

        processed += 1
        if manifest is not None:
            manifest[sha] = {'path': path}
        if tlsh_val and TLSH_RE.match(tlsh_val):
            if tlsh_val not in tlsh_set:
                tlsh_set.add(tlsh_val)
                new_tlsh += 1
            if manifest is not None:
                manifest[sha]['tlsh'] = tlsh_val
        if ssdeep_val and SSDEEP_RE.match(ssdeep_val):
            if ssdeep_val not in ssdeep_set:
                ssdeep_set.add(ssdeep_val)
                new_ssdeep += 1
            if manifest is not None:
                manifest[sha]['ssdeep'] = ssdeep_val

    if args.dry_run:
        print(f"DRY-RUN: {processed} procesable(s), {skipped_dup} duplicado(s), "
              f"{skipped_small} pequeño(s), {errors} error(es). Nada escrito.")
        return 0

    # --replace is destructive. An invalid/empty source must never erase a
    # populated database just because no sample could be processed.
    if args.replace and processed == 0:
        print("ERROR: --replace cancelado: no se procesó ninguna muestra; bases intactas.",
              file=sys.stderr)
        return 1
    if args.replace:
        if _TLSH_AVAILABLE and not tlsh_set:
            print("AVISO: TLSH sin resultados; su base existente no se sobrescribirá.")
        if _SSDEEP_AVAILABLE and not ssdeep_set:
            print("AVISO: ssdeep sin resultados; su base existente no se sobrescribirá.")

    if manifest is not None:
        with open(args.manifest, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
        print(f"Manifiesto de auditoría: {args.manifest} ({len(manifest)} entradas)")

    # Solo se escriben las bases cuyas librerías están disponibles (no se
    # toca una base si no se puede recalcular su contenido).
    if _TLSH_AVAILABLE and (not args.replace or tlsh_set):
        write_db(args.tlsh_db, tlsh_set)
        IMPORTER_STATE[('tlsh', os.path.normcase(os.path.abspath(args.tlsh_db)))] = (tlsh_set, 0)
    if _SSDEEP_AVAILABLE and (not args.replace or ssdeep_set):
        write_db(args.ssdeep_db, ssdeep_set)
        IMPORTER_STATE[('ssdeep', os.path.normcase(os.path.abspath(args.ssdeep_db)))] = (ssdeep_set, 0)

    print("\n--- Resumen ---")
    print(f"Procesados: {processed} | duplicados: {skipped_dup} | "
          f"pequeños (<{args.min_size}B): {skipped_small} | errores: {errors}")
    if _TLSH_AVAILABLE:
        print(f"TLSH: {len(tlsh_set)} referencia(s) en {args.tlsh_db} "
              f"(+{new_tlsh} nuevas)")
        if len(tlsh_set) > _FUZZY_SCAN_MAX:
            print(f"⚠️  Supera _FUZZY_SCAN_MAX ({_FUZZY_SCAN_MAX}): el fuzzy "
                  f"solo escaneará las primeras {_FUZZY_SCAN_MAX} refs.")
    if _SSDEEP_AVAILABLE:
        print(f"ssdeep: {len(ssdeep_set)} referencia(s) en {args.ssdeep_db} "
              f"(+{new_ssdeep} nuevas)")
        if len(ssdeep_set) > _FUZZY_SCAN_MAX:
            print(f"⚠️  Supera _FUZZY_SCAN_MAX ({_FUZZY_SCAN_MAX}): el fuzzy "
                  f"solo escaneará las primeras {_FUZZY_SCAN_MAX} refs.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog='import_fuzzy_hashes',
        description='Puebla malware_tlsh.txt y malware_ssdeep.txt desde '
                    'carpetas de muestras de malware.')
    p.add_argument('paths', nargs='+',
                   help='Archivo(s) y/o carpeta(s) de muestras')
    p.add_argument('--tlsh-db', default='malware_tlsh.txt',
                   help='Ruta de la base TLSH (default: malware_tlsh.txt)')
    p.add_argument('--ssdeep-db', default='malware_ssdeep.txt',
                   help='Ruta de la base ssdeep (default: malware_ssdeep.txt)')
    p.add_argument('--no-recursive', action='store_true',
                   help='No descender en subcarpetas')
    p.add_argument('--replace', action='store_true',
                   help='Regenerar bases desde cero (descarta lo existente). '
                        'Úsalo si tus bases viejas están en minúsculas.')
    p.add_argument('--yes', action='store_true', help='Confirmar operaciones destructivas sin interacción')
    p.add_argument('--dry-run', action='store_true',
                   help='Solo reportar; no escribir nada')
    p.add_argument('--min-size', type=int, default=DEFAULT_MIN_SIZE,
                   help=f'Tamaño mínimo en bytes (default: {DEFAULT_MIN_SIZE})')
    p.add_argument('--manifest', default=None,
                   help='Escribir manifiesto JSON {sha256: {tlsh, ssdeep, path}}')
    return p


def _importer_main(argv=None):
    """Punto de entrada importable (contrato de test_area7_fuzzy_importer).
    argv: lista estilo CLI, p. ej. ['muestras/', '--replace']. None = sys.argv.
    Retorna 0 en éxito (el test asierta rc == 0)."""
    args = build_parser().parse_args(argv)
    return run(args)


def main():
    sys.exit(_importer_main())


if __name__ == '__main__':
    main()
