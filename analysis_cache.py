
"""
Caché local en SQLite con Trust Decay (expiración de entradas whitelist).

FIX BUG #2: set() preserva whitelist_expiry al re-guardar (antes, el
INSERT OR REPLACE sin esa columna la destruía, acortando la confianza).
"""

import json
import os
import shutil
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict

# Incrementar cuando cambie la lógica o el resultado del análisis para evitar
# reutilizar reportes almacenados por una versión anterior del motor.
# v5: R-01..R-06 y fixes posteriores cambian la puntuación/forma del reporte
# (antes v4/N-17: pipeline CLI/GUI unificado en analysis_engine.py); los
# reportes cacheados con una versión anterior serían inconsistentes.
# ENGINE_VERSION = 6 invalida resultados de motores anteriores.
# Cambios de veredicto o forma del reporte: M1, M3, B1, B3, B4, K5.1, K6.
ENGINE_VERSION = 6


def cache_report_matches_schema(report, expected_schema):
    """La GUI y la CLI no deben consumir reportes cacheados con forma ajena."""
    return isinstance(report, dict) and report.get('_cache_schema') == expected_schema


def expire_whitelist_hash_if_needed(cache, analyzer, file_hash, lock=None, logger=None):
    """Trust decay: retira de la whitelist un hash cuya fecha ya venció.

    Compartido por la GUI (main.py) y la CLI (cli.py). Antes esto solo vivía
    en la GUI: en la CLI el trust decay quedaba derogado de facto porque
    `get_with_trust_decay()` invalidaba la caché, pero el hash seguía en
    `known_good_hashes` (en memoria) y en `known_good_hashes.txt` en disco,
    así que el siguiente scan volvía a whitelistarlo. Si falla la escritura
    del archivo, se retira en memoria y se conserva la fecha vencida para
    reintentarlo en el siguiente análisis.
    """
    if lock is not None:
        return _expire_locked(cache, analyzer, file_hash, lock, logger)
    return _expire_locked(cache, analyzer, file_hash, threading.RLock(), logger)


def _expire_locked(cache, analyzer, file_hash, lock, logger):
    with lock:
        if not cache or not cache.is_whitelist_expired(file_hash):
            return False

        normalized = file_hash.lower()
        analyzer.known_good_hashes.discard(normalized)
        path = analyzer.whitelist_db_path
        temp_path = None
        try:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except FileNotFoundError:
                lines = []

            kept = [line for line in lines if line.strip().lower() != normalized]
            if len(kept) != len(lines):
                directory = os.path.dirname(os.path.abspath(path))
                fd, temp_path = tempfile.mkstemp(
                    prefix='.whitelist-', suffix='.tmp', dir=directory)
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.writelines(kept)
                    f.flush()
                    os.fsync(f.fileno())
                # R-09: mkstemp crea el archivo con modo 0600 y el propietario
                # del proceso; se conservan los permisos/propietario originales.
                if os.path.exists(path):
                    try:
                        shutil.copymode(path, temp_path)
                        st = os.stat(path)
                        os.chown(temp_path, st.st_uid, st.st_gid)
                    except (AttributeError, OSError):
                        pass  # best effort (Windows / sin privilegios)
                os.replace(temp_path, path)
                temp_path = None
            cache.remove_whitelist_expiry(normalized)
            # Residual N-17: la entrada cacheada conservaba el veredicto
            # "whitelisted" anterior; se descarta para forzar re-análisis.
            cache.invalidate(normalized)
            if logger is not None:
                logger.info(
                    "Trust decay vencido; hash retirado de whitelist: %s",
                    normalized[:16])
            return True
        except OSError as e:
            if logger is not None:
                logger.warning(
                    "No se pudo persistir la expiración de whitelist (%s): %s",
                    normalized[:16], e)
            return True
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass


class AnalysisCache:
    """Caché local SQLite.

    Contrato de cierre: cada hilo cierra SU conexión con
    close_thread_connection() (ver nota B7 más abajo); no hay __del__.
    """

    def __init__(self, db_path='analysis_cache.db', ttl_days=30, trust_decay_days=90):
        self.db_path = db_path
        self.ttl_days = ttl_days
        self.trust_decay_days = trust_decay_days
        self._local = threading.local()
        self._init_db()
        # Startup cleanup runs TTL first, then removes old engine versions. This
        # keeps expiry independent of engine bumps and preserves future versions.
        # K1: purga al arrancar entradas vencidas por TTL y de versiones viejas
        # del motor; sin esto la BD crecía monótonamente. Es best-effort: una
        # BD bloqueada por otro proceso no debe impedir arrancar.
        try:
            self.clear_expired()
        except sqlite3.Error:
            pass

    # B7 (C.4): sin __del__. Las conexiones sqlite3 tienen afinidad de hilo y
    # un __del__ solo puede cerrar la del hilo que destruye el objeto (casi
    # nunca la del creador): daba una falsa sensación de limpieza. Contrato:
    # cada hilo que obtuvo una conexión llama close_thread_connection() en su
    # finally (los workers de la GUI ya lo hacen); la conexión restante la
    # libera sqlite3 al recolectarse el threading.local.

    def _get_conn(self):
        if not hasattr(self._local, 'conn'):
            conn = sqlite3.connect(self.db_path)
            self._local.conn = conn
        return self._local.conn

    def close_thread_connection(self):
        """Cierra la conexión del hilo actual.

        Debe llamarse en el mismo hilo que obtuvo la conexión. Los workers
        llaman este método en su finally; la GUI solo cierra su propia conexión.
        """
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            return
        try:
            conn.close()
        finally:
            try:
                del self._local.conn
            except AttributeError:
                pass

    def close_all(self):
        """Compatibilidad: cierra solo la conexión del hilo llamador.

        No es seguro cerrar aquí conexiones de workers por la afinidad de hilo
        de sqlite3. Cada worker es responsable de cerrar la suya al terminar.
        """
        self.close_thread_connection()

    def _init_db(self):
        conn = self._get_conn()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                file_hash TEXT PRIMARY KEY,
                file_path TEXT,
                analysis_date TEXT,
                engine_version INTEGER,
                risk_level TEXT,
                report_json TEXT
            )
        ''')
        try:
            conn.execute('ALTER TABLE analysis_results ADD COLUMN whitelist_expiry TEXT')
        except sqlite3.OperationalError:
            pass
        conn.execute('''
            CREATE TABLE IF NOT EXISTS whitelist_expirations (
                file_hash TEXT PRIMARY KEY,
                expiry TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        ''')
        migration_id = 'whitelist_expirations_v1'
        migrated = conn.execute(
            'SELECT 1 FROM schema_migrations WHERE migration_id = ?',
            (migration_id,)
        ).fetchone()
        if not migrated:
            # Migración no destructiva de expiraciones de versiones previas.
            conn.execute('''
                INSERT OR IGNORE INTO whitelist_expirations (file_hash, expiry)
                SELECT file_hash, whitelist_expiry
                FROM analysis_results
                WHERE whitelist_expiry IS NOT NULL AND whitelist_expiry != ''
            ''')
            conn.execute(
                'INSERT INTO schema_migrations (migration_id, applied_at) VALUES (?, ?)',
                (migration_id, datetime.now().isoformat())
            )
        conn.commit()

    def get(self, file_hash):
        conn = self._get_conn()
        cursor = conn.execute(
            'SELECT file_path, analysis_date, engine_version, risk_level, report_json '
            'FROM analysis_results WHERE file_hash = ?',
            (file_hash,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        file_path, analysis_date, engine_version, risk_level, report_json = row

        if engine_version != ENGINE_VERSION:
            return None

        try:
            cached_dt = datetime.fromisoformat(analysis_date)
            if datetime.now() - cached_dt > timedelta(days=self.ttl_days):
                return None
        except ValueError:
            return None

        try:
            report = json.loads(report_json)
        except json.JSONDecodeError:
            return None

        return {
            'file_path': file_path,
            'analysis_date': analysis_date,
            'risk_level': risk_level,
            'report': report,
        }

    def set(self, file_hash, file_path, risk_level, report):
        conn = self._get_conn()
        # Un solo UPSERT actualiza el resultado sin leer ni sobrescribir la
        # columna legacy whitelist_expiry. El vencimiento autoritativo vive
        # en whitelist_expirations y no participa en esta operación.
        conn.execute('''
            INSERT INTO analysis_results
            (file_hash, file_path, analysis_date, engine_version, risk_level,
             report_json, whitelist_expiry)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(file_hash) DO UPDATE SET
                file_path = excluded.file_path,
                analysis_date = excluded.analysis_date,
                engine_version = excluded.engine_version,
                risk_level = excluded.risk_level,
                report_json = excluded.report_json
        ''', (file_hash, file_path, datetime.now().isoformat(), ENGINE_VERSION,
              risk_level, json.dumps(report, default=str)))
        conn.commit()

    def invalidate(self, file_hash):
        conn = self._get_conn()
        # N-10: invalidar también whitelist_expirations. Antes el DELETE solo
        # borraba analysis_results y la fecha de confianza quedaba huérfana:
        # el hash seguía "dentro de la ventana de confianza" aunque ya no
        # perteneciera (p.ej.) a la whitelist.
        normalized = file_hash.lower()
        conn.execute('DELETE FROM analysis_results WHERE file_hash = ?', (normalized,))
        conn.execute('DELETE FROM whitelist_expirations WHERE file_hash = ?', (normalized,))
        conn.commit()

    def clear_all(self):
        conn = self._get_conn()
        conn.execute('DELETE FROM analysis_results')
        conn.commit()

    def clear_stale_versions(self):
        """Borra resultados de versiones anteriores del motor.

        get() ya los ignora, pero con fecha reciente permanecían para siempre.
        No toca whitelist_expirations (el trust decay sobrevive).
        """
        conn = self._get_conn()
        conn.execute('DELETE FROM analysis_results WHERE engine_version < ?',
                     (ENGINE_VERSION,))
        conn.commit()

    def clear_expired(self):
        """Purga resultados por TTL y de versiones viejas del motor, sin
        borrar fechas de trust decay."""
        conn = self._get_conn()
        cutoff = (datetime.now() - timedelta(days=self.ttl_days)).isoformat()
        conn.execute('DELETE FROM analysis_results WHERE analysis_date < ?', (cutoff,))
        conn.commit()
        self.clear_stale_versions()

    def stats(self):
        conn = self._get_conn()
        total = conn.execute('SELECT COUNT(*) FROM analysis_results').fetchone()[0]
        current_version = conn.execute(
            'SELECT COUNT(*) FROM analysis_results WHERE engine_version = ?', (ENGINE_VERSION,)
        ).fetchone()[0]
        return {'total_entries': total,
                'current_version_entries': current_version,
                'db_path': os.path.abspath(self.db_path)}

    def set_whitelist_with_expiry(self, file_hash: str, expiry_days: Optional[int] = None):
        days = expiry_days if expiry_days is not None else self.trust_decay_days
        expiry_date = (datetime.now() + timedelta(days=days)).isoformat()
        conn = self._get_conn()
        conn.execute('''
            INSERT OR REPLACE INTO whitelist_expirations (file_hash, expiry)
            VALUES (?, ?)
        ''', (file_hash.lower(), expiry_date))
        # Mantener el campo antiguo actualizado durante la transición; la
        # fuente de verdad es whitelist_expirations y sobrevive al TTL de caché.
        try:
            conn.execute('''
                UPDATE analysis_results SET whitelist_expiry = ? WHERE file_hash = ?
            ''', (expiry_date, file_hash.lower()))
        except sqlite3.OperationalError:
            pass
        conn.commit()

    def is_whitelist_expired(self, file_hash: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            'SELECT expiry FROM whitelist_expirations WHERE file_hash = ?',
            (file_hash.lower(),)
        ).fetchone()
        if not row:
            return False
        try:
            return datetime.now() >= datetime.fromisoformat(row[0])
        except (TypeError, ValueError):
            # Una fecha inválida debe fallar cerrada: no conservar confianza.
            return True

    def remove_whitelist_expiry(self, file_hash: str):
        conn = self._get_conn()
        normalized = file_hash.lower()
        conn.execute('DELETE FROM whitelist_expirations WHERE file_hash = ?',
                     (normalized,))
        # Evita que el campo legado vuelva a migrarse al arrancar.
        conn.execute('UPDATE analysis_results SET whitelist_expiry = NULL WHERE file_hash = ?',
                     (normalized,))
        conn.commit()

    def get_with_trust_decay(self, file_hash: str) -> Optional[Dict]:
        # Comprobar vencimiento antes del TTL: get() puede rechazar una
        # entrada antigua, pero su fecha de confianza debe seguir vigente.
        if self.is_whitelist_expired(file_hash):
            self.invalidate(file_hash)
            return None
        return self.get(file_hash)
        
