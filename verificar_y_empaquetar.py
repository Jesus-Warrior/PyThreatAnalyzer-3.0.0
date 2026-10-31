
#!/usr/bin/env python3
"""
verificar_y_empaquetar.py - Verificación final + empaquetado de PyThreatAnalyzer.

Ejecuta verificaciones funcionales y SOLO crea el .zip si pasan las fases bloqueantes:
  1. Manifiesto del repositorio: REQUIRED_FILES y REPO_ONLY_FILES existen.
  2. py_compile de cada .py  -> aborta si quedó una versión vieja rota
     (BUG-1 IndentationError en main.py / BUG-2 TabError en cli.py).
  3. Import real de cada módulo (py_compile no detecta imports faltantes).
  4. Pruebas funcionales de los fixes:
       BUG-3: firma RAR5 detectada como RAR5 (no RAR4).
       BUG-4: un ZIP renombrado a .exe se analiza como 'zip'.
       BUG-5: tlsh_match=True genera capa 'similarity' con score > 0.
  5. Marcadores textuales de los demás fixes (solo avisan).
  6. Cobertura de datos: informa de bases YARA/reputación ausentes; --strict-data-coverage bloquea.
  7. ZIP atómico con raíz única PyThreatAnalyzer/ e inventario C4, seguido de
     verificación importando desde el zip extraído:
     esa verificación es la única que detecta un archivo presente en disco y
     ausente de REQUIRED_FILES (la fase 3 resuelve contra el árbol fuente y
     pasa en verde). Si falla, se elimina el zip. --tests ejecuta además la
     suite completa.

Uso:
  python verificar_y_empaquetar.py
  python verificar_y_empaquetar.py --tests
  python verificar_y_empaquetar.py --zip-name PyThreatAnalyzer_v3.0.0.zip
"""

import argparse
import hashlib
import importlib
import json
import os
import py_compile
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile

# ------------------------------------------------------------------
# Manifiesto de distribución (la cantidad se calcula desde REQUIRED_FILES)
# ------------------------------------------------------------------
REQUIRED_FILES = [
    # Corregidos en la auditoría
    'main.py', 'cli.py', 'virus_analyzer.py', 'risk_scoring.py',
    # K4: niveles/pesos de riesgo centralizados
    'risk_levels.py',
    'file_type_detector.py', 'archive_analyzer.py',
    # N-17: motor único de análisis compartido por CLI y GUI
    'analysis_engine.py',
    # Nuevos
    'import_fuzzy_hashes.py', 'test_pythreatanalyzer.py',
    'verificar_y_empaquetar.py', 'config_loader.py',
    # Mejoras v2 (mañana.txt)
    'analysis_cache.py', 'explanation_engine.py',
    # Originales sin cambios
    'ai_detector.py', 'analysis_utils.py', 'app_logging.py',
    'document_analyzer.py', 'dynamic_analyzer.py', 'import_hashes.py',
    'ml_detector.py', 'report_generator.py', 'script_analyzer.py',
    'threat_intel.py', 'train_ml_model.py', 'update_yara_rules.py',
    'yara_engine.py',
    'requirements.in', 'requirements.txt', 'requirements-dev.in',
    'requirements-dev.txt', 'requirements-fuzzy.in', 'README.md',
    'SECURITY.md', 'pyproject.toml', 'profile_analysis.py',
    'MANIFEST.in', 'config.json', 'malware_hashes.txt',
    'malware_imphashes.txt', 'malware_tlsh.txt', 'malware_ssdeep.txt',
    'pythreat_version.py', 'CHANGELOG.md', 'setup-data.sh',
    'docs/data-sources.md', 'docs/cache-engine-version.md', 'docs/tests.md',
]
OPTIONAL_FILES = [
    'requirements-o1-tested.txt', 'o1_test_results.json',
]
REPO_ONLY_FILES = [
    '.github/workflows/ci.yml', '.github/workflows/release.yml', '.gitignore',
    'scripts/check-consistency.sh', 'scripts/check-data-coverage.sh',
]
DATA_ROOT = 'data'
CHECKSUMS_PATH = 'data/checksums.txt'
ZIP_ROOT = 'PyThreatAnalyzer/'
IMPORTABLE = [f[:-3] for f in REQUIRED_FILES if f.endswith('.py')]

# M4: main.py importa tkinter al tope. En contenedores headless (donde pytest
# sí corre, con _require_tkinter) el import fallaba y el release se abortaba y
# borraba el zip. Solo se omite el CHECK DE IMPORT de main; main.py sigue
# empaquetándose (REQUIRED_FILES) y compilándose (fase 2).
def _detect_tkinter():
    try:
        import tkinter  # noqa: F401
        return True
    except (ImportError, OSError):
        return False


_TKINTER_AVAILABLE = _detect_tkinter()


def _skip_import_check(mod):
    if mod == 'main' and not _TKINTER_AVAILABLE:
        warn("import main omitido: tkinter no disponible")
        return True
    return False

# Marcadores textuales (solo avisan; la validación real es la fase 4).
# OJO: la firma RAR5 va como raw string porque en el source es un literal b'...'.
MARKERS = {
    'virus_analyzer.py': ['FIX BUG A'],
    'import_fuzzy_hashes.py': ['_importer_main', 'IMPORTER_STATE'],
    'analysis_cache.py': ['trust_decay_days', 'ENGINE_VERSION = 6'],
    'test_pythreatanalyzer.py': ['test_area7_fuzzy_importer',
                                 'test_area1_magic_bytes_and_type_mismatch'],
    'file_type_detector.py': [r"Rar!\x1a\x07\x01\x00"],
    # N-17: el pipeline (antes duplicado en main.py) vive ahora en el motor
    # único; el marcador verifica que TLSH se consume sin recalcular.
    'analysis_engine.py': ["'tlsh': reputation.get('tlsh')"],
    'risk_scoring.py': ['TLSH_SIMILARITY_MATCH', 'SSDEEP_SIMILARITY_MATCH'],
    'archive_analyzer.py': ['_sniff_format'],
    'cli.py': ['FIX BUG #2', 'FIX BUG D'],
}

FAILED, WARNED = [], []


def fail(msg):
    FAILED.append(msg); print(f"❌ {msg}")


def warn(msg):
    WARNED.append(msg); print(f"⚠️  {msg}")


def ok(msg):
    print(f"✅ {msg}")


# ------------------------------------------------------------------
# Fase 1: manifiesto
# ------------------------------------------------------------------
def phase_manifest_repo(project_dir):
    print("\n--- FASE 1: manifiesto ---")
    missing = [f for f in REQUIRED_FILES + REPO_ONLY_FILES
               if not os.path.isfile(os.path.join(project_dir, f))]
    if missing:
        for f in missing:
            fail(f"Falta archivo obligatorio: {f}")
        return False
    ok(f"{len(REQUIRED_FILES)}/{len(REQUIRED_FILES)} archivos obligatorios presentes")
    for f in OPTIONAL_FILES:
        if not os.path.isfile(os.path.join(project_dir, f)):
            warn(f"Opcional ausente: {f}")
    return True


def phase_manifest_zip(names, project_dir=None, full=False):
    """Validate the distributable inventory (C4) and its single root."""
    expected = {ZIP_ROOT + f for f in REQUIRED_FILES}
    project_dir = project_dir or os.path.dirname(os.path.abspath(__file__))
    expected.update(ZIP_ROOT + f for f in OPTIONAL_FILES
                    if os.path.isfile(os.path.join(project_dir, f)))
    if full:
        expected.update(n for n in names if n.startswith(ZIP_ROOT + 'data/yara_rules/'))
    expected.update(ZIP_ROOT + rel for rel in _data_files(project_dir, full=full))
    actual = set(names)
    missing = sorted(expected - actual)
    forbidden = sorted(n for n in actual if n.startswith((ZIP_ROOT + '.github/',
                           ZIP_ROOT + 'scripts/')) or n in
                       (ZIP_ROOT + '.gitignore', ZIP_ROOT + 'config.local.json',
                        ZIP_ROOT + 'nsrl.local.json'))
    roots = {n.split('/', 1)[0] for n in actual if n}
    allowed = expected | {ZIP_ROOT}
    extra = sorted(actual - allowed)
    if missing:
        fail('Inventario C4 incompleto: ' + ', '.join(missing))
    if forbidden:
        fail('Archivos de repositorio dentro del ZIP: ' + ', '.join(forbidden))
    if extra:
        fail('Entradas ajenas al inventario C4: ' + ', '.join(extra))
    if roots != {'PyThreatAnalyzer'}:
        fail(f'Estructura ZIP inválida; raíces encontradas: {sorted(roots)}')
    if not missing and not forbidden and not extra:
        ok('Inventario C4 y raíz única validados')
    return not missing and not forbidden and not extra and roots == {'PyThreatAnalyzer'}


def _data_files(project_dir, full=False):
    root = os.path.join(project_dir, DATA_ROOT)
    members = []
    for current, _dirs, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(os.path.join(current, name), project_dir)
            if not full and rel.startswith('data/yara_rules/') and name.endswith(('.yar', '.yara')):
                continue
            members.append(rel)
    return sorted(members)


# ------------------------------------------------------------------
# Fase 2: compilación
# ------------------------------------------------------------------
def phase_compile(project_dir, tmp):
    print("\n--- FASE 2: py_compile ---")
    bad = False
    for f in REQUIRED_FILES:
        if not f.endswith('.py'):
            continue
        try:
            py_compile.compile(os.path.join(project_dir, f),
                               cfile=os.path.join(tmp, 'out.pyc'), doraise=True)
            ok(f"compila: {f}")
        except py_compile.PyCompileError as e:
            fail(f"NO compila {f}: {e}")
            bad = True
    return not bad


# ------------------------------------------------------------------
# Fase 3: importación real
# ------------------------------------------------------------------
def phase_import(project_dir):
    """Importa contra el árbol fuente (sys.path.insert(0, project_dir)).

    Conoce solamente los archivos de REQUIRED_FILES: un .py que exista en
    disco y no esté en el manifiesto ni se importa ni se detecta. Ese hueco
    lo cubre phase_zip_import, que importa desde el zip ya empaquetado.
    """
    print("\n--- FASE 3: importación de módulos ---")
    sys.path.insert(0, project_dir)
    bad = False
    for mod in IMPORTABLE:
        if mod == 'verificar_y_empaquetar':
            continue  # este script ya está corriendo
        if _skip_import_check(mod):
            continue
        try:
            importlib.import_module(mod)
            ok(f"importa: {mod}")
        except Exception as e:
            fail(f"NO importa {mod}: {type(e).__name__}: {e}")
            bad = True
    return not bad


# ------------------------------------------------------------------
# Fase 4: pruebas funcionales de los fixes
# ------------------------------------------------------------------
def phase_functional(tmp):
    print("\n--- FASE 4: pruebas funcionales (BUG-3 / BUG-4 / BUG-5) ---")
    good = True

    # BUG-3: RAR5 antes que RAR4
    try:
        from file_type_detector import FileTypeDetector, RealFileType
        p = os.path.join(tmp, 'fake.rar5')
        with open(p, 'wb') as f:
            f.write(b'Rar!\x1a\x07\x01\x00' + b'\x00' * 64)
        if FileTypeDetector.detect(p) == RealFileType.RAR5:
            ok("BUG-3: firma RAR5 detectada como RAR5")
        else:
            fail("BUG-3: firma RAR5 NO clasificada como RAR5")
            good = False
    except Exception as e:
        fail(f"BUG-3: {e}")
        good = False

    # BUG-4: ZIP renombrado a .exe se analiza
    try:
        from archive_analyzer import analyze_compressed_file
        zsrc = os.path.join(tmp, 'real.zip')
        with zipfile.ZipFile(zsrc, 'w') as zf:
            zf.writestr('inner.txt', 'contenido de prueba')
        zexe = os.path.join(tmp, 'disfrazado.exe')
        shutil.copy(zsrc, zexe)
        res = analyze_compressed_file(zexe, member_analyzer=None) or {}
        if res.get('format') == 'zip':
            ok("BUG-4: ZIP renombrado a .exe analizado como 'zip'")
        else:
            fail(f"BUG-4: ZIP renombrado devolvió format={res.get('format')!r}")
            good = False
    except Exception as e:
        fail(f"BUG-4: {e}")
        good = False

    # BUG-5: capa similarity activa con tlsh_match
    try:
        from risk_scoring import calculate_layered_risk
        score, level, findings, layers = calculate_layered_risk(
            {'reputation': {'tlsh_match': True}})
        sim = layers.get('similarity')
        if sim and sim.score > 0:
            ok(f"BUG-5: capa 'similarity' activa (score {sim.score})")
        else:
            fail("BUG-5: tlsh_match=True no produjo capa 'similarity'")
            good = False
    except Exception as e:
        fail(f"BUG-5: {e}")
        good = False

    return good


# ------------------------------------------------------------------
# Fase 5: marcadores textuales (solo advertencias)
# ------------------------------------------------------------------
def phase_markers(project_dir):
    print("\n--- FASE 5: marcadores de fixes (aviso, no abortan) ---")
    for fname, markers in MARKERS.items():
        try:
            with open(os.path.join(project_dir, fname), 'r',
                      encoding='utf-8', errors='ignore') as f:
                src = f.read()
        except OSError as e:
            warn(f"No pude leer {fname}: {e}")
            continue
        for m in markers:
            if m in src:
                ok(f"marcador en {fname}: {m[:45]!r}")
            else:
                warn(f"marcador NO encontrado en {fname}: {m[:45]!r} "
                     f"(¿versión vieja del archivo?)")


def phase_data_coverage(project_dir, strict=False, distribution=False):
    """Advierte si las fuentes de reputación/YARA configuradas no aportan cobertura.

    El paquete base puede distribuirse sin bases comunitarias; los releases
    que exijan esas fuentes deben activar --strict-data-coverage.
    """
    print("\n--- FASE 6: cobertura de datos ---")
    config_path = os.path.join(project_dir, 'config.json')
    try:
        with open(config_path, encoding='utf-8') as stream:
            config = json.load(stream)
        local_config_path = os.path.join(project_dir, 'config.local.json')
        if os.path.isfile(local_config_path):
            with open(local_config_path, encoding='utf-8') as stream:
                local_config = json.load(stream)
            if isinstance(local_config, dict):
                config.update(local_config)
    except (OSError, json.JSONDecodeError) as exc:
        warn(f"No se pudo leer config.json ({exc}); la aplicación usará valores predeterminados.")
        return not strict

    missing = []
    def valid_hash_file(key):
        value = config.get(key)
        path = os.path.join(project_dir, value) if value else ''
        try:
            with open(path, encoding='utf-8') as stream:
                entries = [line.strip() for line in stream
                           if line.strip() and not line.lstrip().startswith('#')]
        except OSError:
            entries = []
        return any(re.fullmatch(r'[0-9a-fA-F]{64}', item) for item in entries)

    def valid_nsrl_sqlite(path):
        if not path:
            return False
        if not os.path.isabs(path):
            path = os.path.join(project_dir, path)
        if not os.path.isfile(path):
            return False
        try:
            with sqlite3.connect(f'file:{os.path.abspath(path)}?mode=ro', uri=True, timeout=5) as conn:
                for (name,) in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type IN ('table','view')"):
                    qname = '"' + str(name).replace('"', '""') + '"'
                    columns = conn.execute(f'PRAGMA table_info({qname})').fetchall()
                    column = next((str(c[1]) for c in columns if str(c[1]).lower() == 'sha256'), None)
                    if column:
                        qcolumn = '"' + column.replace('"', '""') + '"'
                        if conn.execute(f'SELECT 1 FROM {qname} WHERE {qcolumn} IS NOT NULL LIMIT 1').fetchone():
                            return True
        except (OSError, sqlite3.Error):
            return False
        return False

    nsrl_text_ready = valid_hash_file('known_good_hashes_db')
    nsrl_distribution_omitted = False
    if not nsrl_text_ready and (distribution or not valid_nsrl_sqlite(config.get('nsrl_db'))):
        if distribution:
            # The complete NIST RDS is intentionally installed per-user after
            # extracting the small application ZIP. setup-data.sh documents
            # this opt-in local setup; never bundle a multi-GB SQLite file.
            warn('allowlist NSRL no incluida en el ZIP; el usuario puede configurar su SQLite local con ./setup-data.sh')
            nsrl_distribution_omitted = True
        else:
            missing.append('allowlist NSRL SHA-256: requiere una lista válida o un SQLite RDSv3 configurado')
    if not valid_hash_file('malware_hashes_db'):
        missing.append(f"denylist SHA-256 ({config.get('malware_hashes_db') or 'sin ruta'}) ausente, vacía o inválida")

    # Validate the explicitly selected release sources and their provenance.
    tweet_meta_path = os.path.join(project_dir, 'data', 'denylist', 'tweetfeed_meta.json')
    try:
        with open(tweet_meta_path, encoding='utf-8') as stream:
            tweet_meta = json.load(stream)
        feed_path = os.path.join(project_dir, config.get('malware_hashes_db', ''))
        with open(feed_path, encoding='utf-8') as stream:
            feed_count = sum(1 for line in stream if re.fullmatch(r'[0-9a-fA-F]{64}', line.strip()))
        feed_digest = hashlib.sha256()
        with open(feed_path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                feed_digest.update(chunk)
        if (tweet_meta.get('source') != 'TweetFeed' or tweet_meta.get('license') != 'CC0-1.0'
                or tweet_meta.get('unique_sha256_count') != feed_count or feed_count == 0
                or tweet_meta.get('hashlist_sha256') != feed_digest.hexdigest()
                or not str(tweet_meta.get('source_url', '')).startswith('https://tweetfeed.live/feeds/')):
            missing.append('metadatos TweetFeed ausentes o no coinciden con el feed SHA-256')
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        missing.append('data/denylist/tweetfeed_meta.json ausente o inválido')

    rules_path = config.get('yara_rules_path')
    if rules_path:
        resolved = os.path.join(project_dir, rules_path)
        rule_files = []
        if os.path.isdir(resolved):
            for root, _dirs, files in os.walk(resolved):
                rule_files.extend(os.path.join(root, name) for name in files
                                  if name.endswith(('.yar', '.yara')))
        if not rule_files:
            missing.append(f"ruleset YARA ({rules_path}) ausente o vacío")
        else:
            try:
                from yara_engine import YARAEngine
                engine = YARAEngine(resolved)
                if not engine.rules or not engine.loaded_rule_count:
                    missing.append(f"ruleset YARA ({rules_path}) no produjo reglas compiladas")
                elif engine.skipped_rules:
                    missing.append(
                        f"ruleset YARA compiló parcialmente: {len(engine.skipped_rules)} regla(s) omitida(s)"
                    )
            except Exception as exc:
                missing.append(f"no se pudo validar el ruleset YARA: {exc}")

    yara_meta_path = os.path.join(project_dir, 'data', 'yara_rules', 'META.json')
    try:
        with open(yara_meta_path, encoding='utf-8') as stream:
            yara_meta = json.load(stream)
        sources = {entry.get('source'): entry for entry in yara_meta.get('sources', [])
                   if isinstance(entry, dict)}
        for source_name in ('PRX-SD Built-in', 'ReversingLabs'):
            entry = sources.get(source_name)
            if (not entry or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', entry.get('commit', ''))
                    or entry.get('rule_count', 0) < 1 or 'MIT' not in entry.get('license', '')):
                missing.append(f'metadatos de fuente YARA incompletos: {source_name}')
                continue
            if source_name == 'ReversingLabs':
                notice_commit = entry.get('license_notice_commit', '')
                notice_path = os.path.join(project_dir, 'data', 'yara_rules',
                                           entry.get('directory', ''), 'REVERSINGLABS-LICENSE-MIT.txt')
                if not re.fullmatch(r'[0-9a-f]{40}', notice_commit) or not os.path.isfile(notice_path):
                    missing.append('aviso MIT oficial de ReversingLabs o su commit no está incluido')
            elif source_name == 'PRX-SD Built-in':
                notice_path = os.path.join(project_dir, 'data', 'yara_rules',
                                           entry.get('directory', ''), 'PRX-SD-BUILTIN-LICENSE-MIT.txt')
                if not os.path.isfile(notice_path):
                    missing.append('aviso MIT de PRX-SD Built-in no está incluido')
            directory = os.path.join(project_dir, 'data', 'yara_rules', entry.get('directory', ''))
            actual_rules = [os.path.join(root, name) for root, _dirs, names in os.walk(directory)
                            for name in names if name.endswith(('.yar', '.yara'))]
            if len(actual_rules) != entry.get('rule_file_count', entry['rule_count']):
                missing.append(f"conteo de reglas no coincide con META.json: {source_name}")
            actual_digests, declaration_count = {}, 0
            for rule_path in actual_rules:
                relative = os.path.relpath(rule_path, directory).replace(os.sep, '/')
                digest = hashlib.sha256()
                with open(rule_path, 'rb') as rule_stream:
                    for chunk in iter(lambda: rule_stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                actual_digests[relative] = digest.hexdigest()
                with open(rule_path, encoding='utf-8', errors='replace') as rule_stream:
                    declaration_count += len(re.findall(
                        r'(?im)^\s*(?:private\s+|global\s+)?rule\b', rule_stream.read()))
            if actual_digests != entry.get('rules_sha256'):
                missing.append(f"hashes de reglas no coinciden con META.json: {source_name}")
            if declaration_count != entry.get('rule_count'):
                missing.append(f"cantidad de declaraciones YARA no coincide con META.json: {source_name}")
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        missing.append('data/yara_rules/META.json ausente o inválido')

    # Validate the data inventory against a deterministic SHA-256 manifest.
    checksum_file = os.path.join(project_dir, CHECKSUMS_PATH)
    listed, checksum_errors = {}, []
    try:
        with open(checksum_file, encoding='utf-8') as stream:
            for line_no, line in enumerate(stream, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = re.fullmatch(r'([0-9a-fA-F]{64})  (data/.+)', line)
                if not match:
                    checksum_errors.append(f"formato inválido en {CHECKSUMS_PATH}:{line_no}")
                    continue
                rel = match.group(2)
                if os.path.isabs(rel) or '..' in rel.split('/') or rel in listed:
                    checksum_errors.append(f"ruta insegura o duplicada en {CHECKSUMS_PATH}:{line_no}")
                    continue
                listed[rel] = match.group(1).lower()
    except OSError:
        checksum_errors.append(f"{CHECKSUMS_PATH} ausente")
    actual_files = {rel for rel in _data_files(project_dir, full=True)
                    if rel != CHECKSUMS_PATH and not rel.endswith('/.gitkeep')}
    for rel in sorted(actual_files):
        if os.path.islink(os.path.join(project_dir, rel)):
            checksum_errors.append(f'no se aceptan symlinks en data/: {rel}')
    if not listed:
        checksum_errors.append(f"{CHECKSUMS_PATH} no contiene checksums")
    if set(listed) != actual_files:
        checksum_errors.append('el inventario de checksums no coincide con los archivos de data/')
    for rel in sorted(set(listed) & actual_files):
        digest = hashlib.sha256()
        with open(os.path.join(project_dir, rel), 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != listed[rel]:
            checksum_errors.append(f'checksum incorrecto: {rel}')
    missing.extend(checksum_errors)
    if not os.path.isfile(os.path.join(project_dir, 'data', 'NOTICE')):
        missing.append('data/NOTICE ausente')

    for issue in missing:
        message = f"Cobertura de datos incompleta: {issue}"
        if strict:
            fail(message)
        else:
            warn(message)
    if not missing:
        if nsrl_distribution_omitted:
            ok('Cobertura de datos incluida validada; NSRL se configura después de instalar el ZIP')
        else:
            ok("Bases de reputación y reglas YARA configuradas con cobertura")
    return not (strict and missing)


# ------------------------------------------------------------------
# Suite completa (opcional)
# ------------------------------------------------------------------
def run_tests(project_dir):
    print("\n--- SUITE COMPLETA (test_pythreatanalyzer.py) ---")
    try:
        r = subprocess.run([sys.executable, 'test_pythreatanalyzer.py'],
                           cwd=project_dir, capture_output=True, text=True,
                           timeout=900)
        tail = (r.stdout or '').strip().splitlines()[-12:]
        print('\n'.join(tail))
        if r.returncode != 0:
            fail(f"La suite falló (exit {r.returncode})")
            return False
        ok("Suite completa: PASS")
        return True
    except Exception as e:
        fail(f"No se pudo ejecutar la suite: {e}")
        return False


# ------------------------------------------------------------------
# Empaquetado atómico
# ------------------------------------------------------------------
def make_zip(project_dir, zip_name, full=False, strict_data_coverage=False,
             include_community_feed=False):
    if strict_data_coverage:
        if not full:
            fail('--strict-data-coverage exige --full para incluir las reglas YARA')
            return False
        if not phase_data_coverage(project_dir, strict=True, distribution=True):
            return False
    feed_path = os.path.join(project_dir, 'data', 'denylist', 'malwarebazaar_sha256.txt')
    try:
        with open(feed_path, encoding='utf-8') as stream:
            has_community_feed = any(re.fullmatch(r'[0-9a-fA-F]{64}', line.strip())
                                     for line in stream)
    except OSError:
        has_community_feed = False
    if has_community_feed and not include_community_feed:
        fail('MalwareBazaar contiene datos; revisa data/NOTICE y usa --include-community-feed solo si autorizas la redistribución')
        return False
    tmp_zip = zip_name + '.tmp'
    members = REQUIRED_FILES + [f for f in OPTIONAL_FILES
                                if os.path.isfile(os.path.join(project_dir, f))]
    members += _data_files(project_dir, full=full)
    with zipfile.ZipFile(tmp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(ZIP_ROOT, '')
        if full:
            zf.writestr(ZIP_ROOT + 'data/yara_rules/', '')
        for name in members:
            arc = ZIP_ROOT + name
            parts = arc.split('/')
            if (not arc.startswith('PyThreatAnalyzer/') or
                    any(part in ('', '.', '..') for part in parts) or
                    os.path.isabs(arc)):
                raise ValueError(f"arcname sospechoso: {arc}")
            zf.write(os.path.join(project_dir, name), arc)

    # Verificación del propio zip
    with zipfile.ZipFile(tmp_zip) as zf:
        bad = zf.testzip()
        names = zf.namelist()
        n = len(names)
        inventory_ok = phase_manifest_zip(names, project_dir, full=full)
    if bad:
        fail(f"El zip temporal contiene una entrada corrupta: {bad}")
        os.remove(tmp_zip)
        return False
    if not inventory_ok:
        os.remove(tmp_zip)
        return False
    os.replace(tmp_zip, zip_name)  # sustituir solo después de validar
    size_kb = os.path.getsize(zip_name) / 1024
    ok(f"ZIP creado y verificado: {zip_name} ({n} archivos, {size_kb:.1f} KB)")
    return True


# ------------------------------------------------------------------
# Fase 7: importación desde el zip extraído
# ------------------------------------------------------------------
def phase_zip_import(tmp, zip_name):
    """Importa cada módulo desde la copia extraída del zip, no desde el árbol fuente.

    La fase 3 hace sys.path.insert(0, project_dir): resuelve contra el árbol
    fuente, así que un archivo que exista en disco pero no esté en
    REQUIRED_FILES pasa desapercibido. El fallo solo aparece después de
    empaquetar y descomprimir (p. ej. config_loader.py faltaba en el zip y
    la fase 3 seguía en verde). Esta es la única fase que detecta esa clase.
    """
    print("\n--- FASE 7: importación desde el zip extraído ---")
    dest = os.path.join(tmp, 'zip_extract')
    with zipfile.ZipFile(zip_name) as zf:
        zf.extractall(dest)
    root = os.path.join(dest, 'PyThreatAnalyzer')
    if not os.path.isdir(root):
        fail(f"El zip no contiene el directorio PyThreatAnalyzer/ (extraído en {dest})")
        return False

    # PYTHONPATH fuera para que el subprocess no vea el árbol fuente por accidente.
    # El cwd = directorio extraído mete ese directorio como sys.path[0].
    env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
    bad = False
    for mod in IMPORTABLE:
        if mod == 'verificar_y_empaquetar':
            continue  # ya está corriendo en este proceso
        if _skip_import_check(mod):
            continue
        try:
            r = subprocess.run([sys.executable, '-c', f'import {mod}'],
                               cwd=root, capture_output=True, text=True,
                               timeout=120, env=env)
        except Exception as e:
            fail(f"NO se pudo probar {mod} desde el zip: {type(e).__name__}: {e}")
            bad = True
            continue
        if r.returncode:
            lines = (r.stderr or '').strip().splitlines()
            cause = lines[-1] if lines else f"exit {r.returncode} sin stderr"
            fail(f"NO importa {mod} desde el zip: {cause}")
            bad = True
        else:
            ok(f"importa desde el zip: {mod}")
    return not bad


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--tests', action='store_true',
                    help='ejecutar también test_pythreatanalyzer.py')
    ap.add_argument('--strict-data-coverage', action='store_true',
                    help='bloquear empaquetado si faltan bases de reputación o reglas YARA')
    ap.add_argument('--zip-name', default='PyThreatAnalyzer_v3.0.0.zip')
    ap.add_argument('--full', action='store_true', help='incluir data/yara_rules/ en el ZIP')
    ap.add_argument('--include-community-feed', action='store_true',
                    help='incluir MalwareBazaar en el ZIP (solo tras revisar y autorizar sus términos)')
    args = ap.parse_args()

    project_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Proyecto: {project_dir}")

    with tempfile.TemporaryDirectory() as tmp:
        step1 = phase_manifest_repo(project_dir)
        step2 = step1 and phase_compile(project_dir, tmp)
        step3 = step2 and phase_import(project_dir)
        step4 = step3 and phase_functional(tmp)
        phase_markers(project_dir)
        step_data = phase_data_coverage(project_dir, strict=args.strict_data_coverage,
                                        distribution=args.strict_data_coverage)
        step_tests = True
        if args.tests:
            step_tests = run_tests(project_dir)

        print("\n" + "=" * 60)
        if not (step1 and step2 and step3 and step4 and step_data and step_tests):
            print("🚫 VERIFICACIÓN FALLIDA: NO se creó el zip.")
            print(f"   Críticos: {len(FAILED)} | Avisos: {len(WARNED)}")
            sys.exit(1)

        if not make_zip(project_dir, args.zip_name, full=args.full,
                        strict_data_coverage=args.strict_data_coverage,
                        include_community_feed=args.include_community_feed):
            sys.exit(1)

        if not phase_zip_import(tmp, args.zip_name):
            try:
                os.remove(args.zip_name)
            except OSError:
                pass
            print("\n🚫 EL ZIP NO PASA LA VERIFICACIÓN: se eliminó el paquete.")
            print(f"   Críticos: {len(FAILED)} | Avisos: {len(WARNED)}")
            sys.exit(1)

        print("\n✅ PROYECTO VERIFICADO Y EMPAQUETADO")
        print(f"   Críticos fallidos: 0 | Avisos: {len(WARNED)}")
        print(f"   Paquete: {args.zip_name} (extrae y ejecuta la suite dentro)")
        sys.exit(0)


if __name__ == '__main__':
    main()
