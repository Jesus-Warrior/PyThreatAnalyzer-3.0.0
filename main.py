# main.py


"""
PyThreatAnalyzer - Análisis de malware 100% local (sin VirusTotal / sin red,
sin ejecución del archivo analizado bajo ninguna circunstancia).

GUI integrada con el motor v2: FileTypeDetector (magic bytes),
AdvancedFeatures (imphash/TLSH/entropía por ventanas/overlay),
ArchiveAnalyzer (ZIP/RAR/7z anti-zip-bomb) y ExplanationEngine
(Explainable AI con MITRE ATT&CK).
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading
import queue
import time
import tempfile
import os
import json
import logging
import platform
from typing import Dict

from virus_analyzer import StaticAnalyzer
from yara_engine import YARAEngine
from script_analyzer import ScriptAnalyzer
from ai_detector import AIDetector
from ml_detector import MLDetector
from document_analyzer import DocumentAnalyzer
from dynamic_analyzer import DynamicAnalyzer
from report_generator import ReportGenerator
from analysis_utils import (
    is_analyzable_as_text, is_script_code, coverage_gap_messages,
)
from threat_intel import (classify_malware_type, describe_script_findings,
                           describe_document_findings, describe_behavior_findings)
from risk_scoring import calculate_risk_score
from analysis_cache import AnalysisCache, cache_report_matches_schema, expire_whitelist_hash_if_needed
from app_logging import setup_logging, log_detection
from config_loader import load_config
# --- Motor v2 ---
from file_type_detector import FileTypeDetector
# N-17: pipeline único compartido con la GUI (ver AnalysisEngine).
from analysis_engine import AnalysisEngine
from archive_analyzer import ArchiveLimits
from pythreat_version import __version__

GUI_CACHE_SCHEMA = 'gui-report-v1'

logger = logging.getLogger('PyThreatAnalyzer')


class AnalysisCancelled(Exception):
    """Cooperative cancellation requested from the GUI."""
    _pythreat_cancelled = True

_EXTENSION_FILE_TYPES = {
    '.zip': {'ZIP', 'OOXML', 'JAR', 'APK'},
    '.docx': {'OOXML'}, '.docm': {'OOXML'}, '.xlsx': {'OOXML'},
    '.xlsm': {'OOXML'}, '.pptx': {'OOXML'}, '.pptm': {'OOXML'},
    '.doc': {'OLE2'}, '.xls': {'OLE2'}, '.ppt': {'OLE2'}, '.rtf': {'TEXT'},
    '.jar': {'JAR'}, '.apk': {'APK'}, '.rar': {'RAR', 'RAR5'},
    '.7z': {'SEVEN_ZIP'}, '.pdf': {'PDF'}, '.elf': {'ELF'},
    '.tar': {'TAR'}, '.gz': {'GZIP'}, '.bz2': {'BZIP2'}, '.xz': {'XZ'},
    '.dylib': {'MACH_O'}, '.so': {'ELF'},
    '.exe': {'PE32', 'PE64', 'DLL'}, '.dll': {'PE32', 'PE64', 'DLL'},
    '.py': {'PYTHON_SCRIPT'}, '.sh': {'SHELL_SCRIPT'},
    '.ps1': {'POWERSHELL'}, '.psm1': {'POWERSHELL'}, '.psd1': {'POWERSHELL'},
    '.js': {'JAVASCRIPT'},
    '.mp4': {'MP4'}, '.mkv': {'MKV'}, '.avi': {'AVI'},
    '.mp3': {'MP3'}, '.flac': {'FLAC'}, '.png': {'PNG'},
    '.jpg': {'JPEG'}, '.jpeg': {'JPEG'}, '.gif': {'GIF'},
    '.bmp': {'BMP'}, '.webp': {'WEBP'}, '.ico': {'ICO'},
}
_RECOGNIZED_WARNING_TYPES = {
    'ZIP', 'GZIP', 'BZIP2', 'XZ', 'TAR', 'OOXML', 'JAR', 'APK', 'RAR', 'RAR5', 'SEVEN_ZIP', 'PDF', 'ELF', 'MACH_O',
    'PE32', 'PE64', 'DLL', 'MP4', 'MKV', 'AVI', 'MP3', 'FLAC', 'PNG',
    'JPEG', 'GIF', 'BMP', 'WEBP', 'ICO', 'OLE2', 'PYTHON_SCRIPT',
    'SHELL_SCRIPT', 'POWERSHELL', 'JAVASCRIPT',
}


def format_size(num_bytes):
    size = abs(float(num_bytes))
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class PyThreatAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"PyThreatAnalyzer v{__version__} (100% Local, sin ejecución)")
        self.root.geometry("900x780")

        self.config = self._load_config()
        setup_logging(log_format=self.config.get('log_format', 'text'))

        self.static_analyzer = StaticAnalyzer(
            self.config.get('malware_hashes_db', 'malware_hashes.txt'),
            self.config.get('known_good_hashes_db', 'known_good_hashes.txt'),
            self.config.get('malware_imphashes_db', 'malware_imphashes.txt'),
            self.config.get('nsrl_db', None),
            # N-08: las bases fuzzy TLSH/ssdeep ahora son configurables.
            tlsh_db_path=self.config.get('malware_tlsh_db', 'malware_tlsh.txt'),
            ssdeep_db_path=self.config.get('malware_ssdeep_db', 'malware_ssdeep.txt'),
        )
        self.yara_engine = YARAEngine(
            self.config.get('yara_rules_path', 'yara_rules/'),
            timeout_seconds=self.config.get('yara_timeout_seconds', 30))
        self.script_analyzer = ScriptAnalyzer()
        self.ml_detector = MLDetector(
            self.config.get('ml_model_path'), self.config.get('trusted_ml_model_sha256'))
        self.ai_detector = AIDetector()
        self.document_analyzer = DocumentAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer()
        # N-17: el análisis (tipo, PE/ELF, YARA, contenedores, documentos,
        # strings, comportamiento, ML, scripts, IA, puntuación con capas y
        # resumen) vive en el motor único compartido con la CLI (cli.py).
        # Los checkpoints de cancelación/progreso se conectan a la GUI.
        self.engine = AnalysisEngine(
            self.static_analyzer, self.yara_engine, self.document_analyzer,
            self.dynamic_analyzer, self.ml_detector, self.script_analyzer,
            self.ai_detector, on_checkpoint=self._analysis_checkpoint,
            archive_limits=ArchiveLimits(
                max_member_analysis_seconds=self.config.get(
                    'max_member_analysis_seconds',
                    ArchiveLimits().max_member_analysis_seconds)))
        self.report_generator = ReportGenerator()
        self.cache = AnalysisCache(self.config.get('cache_db_path', 'analysis_cache.db'),
                                    self.config.get('cache_ttl_days', 30),
                                    self.config.get('trust_decay_days', 90)) if self.config.get('use_cache', True) else None

        self.last_results_lock = threading.Lock()
        # Serializa modificaciones al archivo y al conjunto en memoria de la whitelist.
        self._whitelist_lock = threading.RLock()
        self._analysis_running = False
        self._cancel_event = threading.Event()
        self._analysis_thread = None
        self._shutdown = False
        self._ui_queue = queue.Queue()

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # La cola se procesa siempre en el hilo Tk. Los workers nunca llaman
        # root.after() ni acceden directamente a widgets.
        self.root.after(self._UI_POLL_MS, self._process_ui_queue)
        self._log_engine_status()
        logger.info("PyThreatAnalyzer v%s iniciado en %s (modo 100%% local)", __version__, platform.system())

    def _load_config(self):
        # Los valores por defecto viven solo en config_loader: así la GUI y la
        # CLI no pueden volver a divergir (la CLI llegó a ignorar use_cache
        # durante años por tener su propia copia de la lista).
        return load_config('config.json')

    # M5 (E.1): segundos que el cierre espera a que el worker atienda la
    # cancelación antes de forzar la salida. La cancelación es COOPERATIVA
    # entre fases (_analysis_checkpoint): no interrumpe una llamada nativa ya
    # iniciada (pefile.PE() sobre un PE malformado, ssdeep.hash_from_file...).
    _CLOSE_GRACE_SECONDS = 10.0
    # K2 (E.3): intervalo de sondeo de la cola de UI (antes 25 ms fijos).
    _UI_POLL_MS = 50
    _closed = False
    _close_deadline = None

    def _on_close(self):
        if self._shutdown:
            return
        self._shutdown = True
        # El worker comprueba este evento en cada checkpoint. Sin esto, cerrar
        # la ventana esperaba a que terminara el escaneo COMPLETO.
        self._cancel_event.set()
        thread = self._analysis_thread
        if thread is not None and thread.is_alive():
            # Mantiene vivo el loop Tk mientras termina el trabajo actual;
            # no hace join bloqueante ni destruye widgets bajo el worker.
            self._close_deadline = time.monotonic() + self._CLOSE_GRACE_SECONDS
            self._show_force_close()
            self.root.after(50, self._finish_close_when_idle)
            return
        self._finalize_close()

    def _show_force_close(self):
        try:
            self.progress_label.set('Cerrando: esperando a que el análisis atienda la cancelación…')
            self.btn_force_close.pack(side=tk.LEFT, padx=(8, 0))
        except (AttributeError, tk.TclError):
            pass

    def _force_close(self):
        logger.warning("Cierre forzado: worker bloqueado")
        self._finalize_close()

    def _finish_close_when_idle(self):
        if self._closed:
            return
        thread = self._analysis_thread
        if thread is not None and thread.is_alive():
            if (self._close_deadline is not None
                    and time.monotonic() >= self._close_deadline):
                # El worker es daemon: al destruir la ventana y salir el
                # proceso no queda retenido por un parser nativo bloqueado.
                self._force_close()
                return
            self.root.after(100, self._finish_close_when_idle)
            return
        self._finalize_close()

    def _finalize_close(self):
        if self._closed:
            return
        self._closed = True
        if self.cache:
            try:
                # El worker cierra la conexión que creó en su propio finally.
                # Aquí solo se cierra la conexión del hilo Tk.
                self.cache.close_all()
            except Exception as e:
                logger.warning("No se pudo cerrar la conexión local de caché: %s", e)
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def _queue_ui(self, callback, *args):
        if not self._shutdown:
            self._ui_queue.put((callback, args))

    def _process_ui_queue(self):
        if self._shutdown:
            return
        while True:
            try:
                callback, args = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*args)
            except tk.TclError:
                # Una ventana puede estar cerrándose entre un evento y otro.
                if not self._shutdown:
                    logger.debug("Se descartó un callback Tk durante el cierre.", exc_info=True)
            except Exception:
                logger.exception("Error procesando una actualización de la interfaz")
            if self._shutdown:
                return
        self.root.after(self._UI_POLL_MS, self._process_ui_queue)

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(main_frame, text="📂 Archivo a analizar:").grid(row=0, column=0, sticky=tk.W)
        self.file_path_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.file_path_var, width=60).grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Examinar...", command=self.select_file).grid(row=0, column=2)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10)

        self.btn_full = ttk.Button(button_frame, text="🔍 Analizar Todo", command=self.run_full_analysis)
        self.btn_full.pack(side=tk.LEFT, padx=5)
        self.btn_virus = ttk.Button(button_frame, text="🦠 Solo Virus", command=self.run_virus_analysis)
        self.btn_virus.pack(side=tk.LEFT, padx=5)
        self.btn_script = ttk.Button(button_frame, text="📜 Solo Script", command=self.run_script_analysis)
        self.btn_script.pack(side=tk.LEFT, padx=5)
        self.btn_ai = ttk.Button(button_frame, text="🤖 Solo IA", command=self.run_ai_analysis)
        self.btn_ai.pack(side=tk.LEFT, padx=5)
        self._analysis_buttons = [self.btn_full, self.btn_virus, self.btn_script, self.btn_ai]

        options_frame = ttk.Frame(main_frame)
        options_frame.grid(row=2, column=0, columnspan=3, pady=(0, 5), sticky=tk.W)
        self.force_rescan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Ignorar caché (forzar re-análisis)",
                         variable=self.force_rescan_var).pack(side=tk.LEFT, padx=(0, 15))
        self.btn_whitelist = ttk.Button(options_frame,
                                         text="✅ Marcar como confiable (whitelist, 90 días)",
                                         command=self.add_current_file_to_whitelist)
        self.btn_whitelist.pack(side=tk.LEFT)
        self._analysis_buttons.append(self.btn_whitelist)

        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        progress_controls = ttk.Frame(main_frame)
        progress_controls.grid(row=4, column=0, columnspan=3, sticky=tk.W)
        self.progress_label = tk.StringVar(value='Listo')
        ttk.Label(progress_controls, textvariable=self.progress_label).pack(side=tk.LEFT, padx=(0, 8))
        self.btn_cancel = ttk.Button(progress_controls, text='⏹ Cancelar',
                                     command=self.cancel_analysis, state='disabled')
        self.btn_cancel.pack(side=tk.LEFT)
        # M5: solo se muestra (pack) cuando el cierre está esperando al worker.
        self.btn_force_close = ttk.Button(progress_controls, text='Forzar cierre',
                                          command=self._force_close)

        ttk.Label(main_frame, text="📋 Resultados:").grid(row=4, column=0, sticky=tk.W, pady=(10, 0))
        self.result_text = scrolledtext.ScrolledText(main_frame, width=100, height=25)
        self.result_text.grid(row=5, column=0, columnspan=3, pady=5)

        for tag, color in (('blue', '#1565C0'), ('green', '#2E7D32'),
                            ('purple', '#6A1B9A'), ('red', '#C62828')):
            self.result_text.tag_configure(tag, foreground=color)

        ttk.Button(main_frame, text="📄 Generar Reporte", command=self.generate_report).grid(row=6, column=0, pady=10)
        ttk.Button(main_frame, text="🗑️ Limpiar", command=self.clear_results).grid(row=6, column=2, pady=10)

    def _log_engine_status(self):
        n_rules = self.yara_engine.loaded_rule_count
        n_skipped = len(self.yara_engine.skipped_rules)
        n_hashes = len(self.static_analyzer.known_bad_hashes)
        n_whitelist = len(self.static_analyzer.known_good_hashes)
        n_imphashes = len(self.static_analyzer.known_bad_imphashes)
        n_nsrl = len(self.static_analyzer.known_nsrl_hashes)
        model_status = "modelo entrenado" if self.ml_detector.model is not None else "heurístico (sin modelo)"

        self.log("ℹ️  Estado de los motores locales:", 'blue')
        self.log(f"   Sistema operativo: {platform.system()}")
        self.log(f"   YARA: {n_rules} regla(s) cargada(s)" +
                 (f" ({n_skipped} omitida(s))" if n_skipped else ""))
        self.log(f"   Hashes maliciosos: {n_hashes} | Imphashes: {n_imphashes}")
        self.log(f"   Whitelist: {n_whitelist} hash(es)" + (f" | NSRL: {n_nsrl}" if n_nsrl else ""))
        self.log(f"   Motor ML: {model_status}")
        # K8: avisar al arrancar de cobertura vacía en lugar de esperar al
        # primer escaneo.
        db_status = self.static_analyzer.database_status
        for gap in coverage_gap_messages(
                known_bad_count=n_hashes, yara_rule_count=n_rules,
                tlsh_status=db_status.get('malware_tlsh', {}).get('status'),
                ssdeep_status=db_status.get('malware_ssdeep', {}).get('status'),
                nsrl_status=db_status.get('nsrl', {}).get('status'),
                known_good_status=db_status.get('known_good_hashes', {}).get('status')):
            logger.warning("Cobertura reducida: %s", gap)
            self.log(f"   ⚠️ {gap}", 'red')
        self.log("   Tipos de archivo: magic bytes (FileTypeDetector, nunca por extensión)")
        self.log("   Comportamiento: 100% estático, el archivo NUNCA se ejecuta")
        if self.cache:
            stats = self.cache.stats()
            self.log(f"   Caché: {stats['current_version_entries']} resultado(s) en {stats['db_path']}"
                     f" (trust decay: {self.cache.trust_decay_days} días)")
        self.log("")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)

    def log(self, message, color='black'):
        tag = color if color in ('blue', 'green', 'purple', 'red') else None
        if tag:
            self.result_text.insert(tk.END, message + "\n", tag)
        else:
            self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)

    def ui_log(self, message, color='black'):
        self._queue_ui(self.log, message, color)

    def ui_progress_start(self):
        self._queue_ui(self._show_progress_start)

    def _show_progress_start(self):
        self.progress.configure(mode='determinate', maximum=self._progress_total, value=0)
        self.progress_label.set('Preparando análisis')
        self.btn_cancel.configure(state='normal')

    def cancel_analysis(self):
        self._cancel_event.set()
        self.progress_label.set('Cancelando al terminar la fase actual…')

    def _analysis_checkpoint(self, completed, label):
        if self._cancel_event.is_set():
            raise AnalysisCancelled('Análisis cancelado por el usuario')
        self._queue_ui(self._update_progress, completed, label)

    def _update_progress(self, completed, label):
        self.progress.configure(mode='determinate', maximum=self._progress_total, value=completed)
        self.progress_label.set(label)

    def ui_progress_stop(self):
        self._queue_ui(self._show_progress_stop)

    def _show_progress_stop(self):
        self.progress.stop()
        self.btn_cancel.configure(state='disabled')
        self.progress_label.set('Listo')

    def ui_clear_results(self):
        self._queue_ui(self.result_text.delete, 1.0, tk.END)

    def _set_buttons_state(self, state):
        for b in self._analysis_buttons:
            b.configure(state=state)

    def _check_file_selected(self):
        if not self.file_path_var.get():
            messagebox.showerror("Error", "Selecciona un archivo primero")
            return False
        return True

    def _start_analysis_thread(self, target):
        if self._analysis_running:
            messagebox.showwarning("Análisis en curso", "Ya hay un análisis en ejecución.")
            return
        self._analysis_running = True
        self._cancel_event.clear()
        self._progress_total = 8 if getattr(target, '__name__', '') == '_run_full_analysis' else 6
        self._set_buttons_state('disabled')

        def wrapped_target():
            try:
                target()
            except AnalysisCancelled:
                self._queue_ui(self.log, '⏹ Análisis cancelado.', 'red')
            except Exception as e:
                logger.error("Error en análisis: %s", e, exc_info=True)
                self._queue_ui(self._handle_analysis_error, str(e))
            finally:
                if self.cache:
                    try:
                        self.cache.close_thread_connection()
                    except Exception:
                        logger.exception("No se pudo cerrar la conexión de caché del worker")
                self._queue_ui(self._on_analysis_finished)

        self._analysis_thread = threading.Thread(target=wrapped_target, daemon=True)
        self._analysis_thread.start()

    def _on_analysis_finished(self):
        self._analysis_running = False
        self._set_buttons_state('normal')
        self._show_progress_stop()

    def _handle_analysis_error(self, error_msg):
        self.progress.stop()
        self.log(f"❌ Error durante análisis: {error_msg}", 'red')
        messagebox.showerror("Error de Análisis",
                             f"Ocurrió un error inesperado:\n{error_msg}")

    def _expire_whitelist_hash_if_needed(self, file_hash):
        """Retira una whitelist local cuyo trust decay ya venció.

        La fecha de expiración vive en una tabla separada de la caché de
        análisis. N-10/2.3: lógica compartida con la CLI (la GUI ya la
        llamaba; la CLI no, así que el trust decay estaba derogado en CLI).
        """
        return expire_whitelist_hash_if_needed(
            self.cache, self.static_analyzer, file_hash,
            lock=self._whitelist_lock, logger=logger)

    def add_current_file_to_whitelist(self):
        if not self._check_file_selected():
            return
        file_path = self.file_path_var.get()
        try:
            hashes = self.static_analyzer.get_file_hashes(file_path)
        except OSError as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo: {e}")
            return

        self._expire_whitelist_hash_if_needed(hashes['sha256'])
        if hashes['sha256'] in self.static_analyzer.known_good_hashes:
            messagebox.showinfo("Whitelist", "Este archivo ya está en la whitelist.")
            return

        confirmed = messagebox.askyesno(
            "Confirmar whitelist",
            f"¿Marcar este archivo como confiable?\n\n{file_path}\n\n"
            f"Trust decay: la confianza expira a los {self.config.get('trust_decay_days', 90)} días."
        )
        if not confirmed:
            return

        if not self.cache:
            messagebox.showerror(
                "Trust Decay no disponible",
                "Activa la caché para guardar esta whitelist con fecha de expiración. "
                "No se agregó el hash para evitar una confianza permanente inesperada."
            )
            return

        # Registrar primero la expiración independiente del TTL de análisis;
        # solo añadir el hash local si ambas operaciones se completan.
        with self._whitelist_lock:
            if hashes['sha256'].lower() in self.static_analyzer.known_good_hashes:
                messagebox.showinfo("Whitelist", "Este archivo ya está en la whitelist.")
                return
            try:
                self.cache.set_whitelist_with_expiry(hashes['sha256'])
                with open(self.static_analyzer.whitelist_db_path, 'a', encoding='utf-8') as f:
                    f.write(hashes['sha256'] + '\n')
            except Exception as e:
                try:
                    self.cache.remove_whitelist_expiry(hashes['sha256'])
                except Exception:
                    logger.exception("No se pudo revertir una expiración de whitelist incompleta")
                logger.warning("No se pudo agregar archivo a whitelist: %s", e, exc_info=True)
                messagebox.showerror("Error de whitelist", f"No se pudo guardar la whitelist: {e}")
                return

            self.static_analyzer.known_good_hashes.add(hashes['sha256'].lower())
        logger.info("Archivo agregado a whitelist: %s (%s)", file_path, hashes['sha256'][:16])
        messagebox.showinfo("Whitelist", "Archivo agregado a la whitelist local.")

    def run_full_analysis(self):
        if self._check_file_selected():
            self._start_analysis_thread(self._run_full_analysis)

    def run_virus_analysis(self):
        if self._check_file_selected():
            self._start_analysis_thread(self._run_virus_only)

    def run_script_analysis(self):
        if self._check_file_selected():
            self._start_analysis_thread(self._run_script_only)

    def run_ai_analysis(self):
        if self._check_file_selected():
            self._start_analysis_thread(self._run_ai_only)

    def _log_virus_summary(self, virus_results, score, risk_level, indicators):
        malware_types = classify_malware_type(virus_results)

        self.ui_log("\n🦠 ANÁLISIS DE VIRUS:", 'purple')
        self.ui_log(f"  Nivel de riesgo: {risk_level} (score: {score}/100)")
        self.ui_log(f"  Indicadores: {', '.join(indicators) if indicators else 'ninguno'}")
        if virus_results.get('analysis_status') == 'INCOMPLETE':
            self.ui_log("  ⚠️ ANÁLISIS INCOMPLETO: el resultado no confirma ausencia de amenazas.", 'red')
            for warning in virus_results.get('analysis_warnings', []):
                self.ui_log(f"    - {warning}", 'red')

        file_type = virus_results.get('file_type')
        if file_type:
            self.ui_log(f"  Tipo real (magic bytes): {file_type}")
            extension = os.path.splitext(str(virus_results.get('file') or ''))[1].lower()
            declared = extension.lstrip('.').upper()
            expected_types = _EXTENSION_FILE_TYPES.get(extension)
            mismatch = (
                file_type not in expected_types if expected_types is not None
                else declared != file_type
            )
            if declared and file_type in _RECOGNIZED_WARNING_TYPES and mismatch:
                self.ui_log(f"  ⚠️ Extensión .{declared} NO coincide con tipo real ({file_type}) "
                            f"- posible malware renombrado", 'red')

        whitelist = virus_results.get('whitelist', {})
        if whitelist.get('is_whitelisted'):
            self.ui_log(f"  ✅ Legítimo: {whitelist.get('reason')}", 'green')
        elif whitelist.get('note'):
            self.ui_log(f"  ℹ️  {whitelist['note']}")

        if virus_results.get('imphash'):
            match = (virus_results.get('reputation', {}) or {}).get('imphash_match')
            self.ui_log(f"  Imphash: {virus_results['imphash']}"
                        + ("  ⚠️ COINCIDE con muestra conocida" if match else ""),
                        'red' if match else 'black')

        ent = virus_results.get('entropy_windows') or {}
        if ent and not ent.get('error'):
            self.ui_log(f"  Entropía/ventanas: global={ent.get('global_entropy')}, máx={ent.get('max_entropy')}, "
                        f"transiciones={ent.get('suspicious_transitions', 0)}")
            for t in (ent.get('transitions') or [])[:3]:
                if isinstance(t, dict) and 'from_offset' in t and 'entropy_diff' in t:
                    self.ui_log(f"    ⚠️ Salto de entropía en offset {t['from_offset']} (Δ {t['entropy_diff']})", 'red')

        overlay = virus_results.get('overlay')
        if overlay and all(key in overlay for key in ('size', 'offset', 'entropy')):
            self.ui_log(f"  Overlay PE: {overlay['size']} bytes @ {overlay['offset']} (entropía {overlay['entropy']})"
                        + (" [PE embebido]" if overlay.get('is_pe') else "")
                        + (" [ZIP embebido]" if overlay.get('is_zip') else ""))
            if overlay.get('is_suspicious'):
                self.ui_log("    ⚠️ Overlay sospechoso: posible payload oculto", 'red')

        arch = virus_results.get('archive_analysis')
        if arch:
            self.ui_log(f"  📦 Comprimido [{arch.get('format', '?')}]: "
                        f"{arch.get('files_analyzed', 0)} interno(s), riesgo={arch.get('risk_level', 'N/A')}")
            if arch.get('is_password_protected'):
                self.ui_log("    ⚠️ Protegido con contraseña - SOSPECHOSO", 'red')
            for sp in (arch.get('suspicious_patterns') or [])[:5]:
                self.ui_log(f"    ⚠️ {sp}", 'red')

        explanation = virus_results.get('explanation') or {}
        if explanation.get('detailed_explanations'):
            self.ui_log("  🧠 Explicabilidad (qué / dónde / MITRE):")
            for det in explanation['detailed_explanations'][:5]:
                mitre = f" [{det['mitre']}]" if det.get('mitre') else ""
                self.ui_log(f"    • {det['indicator']}: {det['description']} ({det['location']}){mitre}")

        self.ui_log("  Tipo de amenaza:")
        for t in malware_types:
            self.ui_log(f"    • {t}")

        doc = virus_results.get('document_analysis')
        if doc:
            self.ui_log("  Documento (macros/PDF):")
            if doc.get('truncated'):
                self.ui_log(f"    ⚠️ {doc.get('analysis_note', 'El análisis del documento fue parcial por el límite de lectura.')}", 'red')
            for f in describe_document_findings(doc):
                self.ui_log(f"    • {f}")

        behavior = virus_results.get('behavior_analysis')
        if behavior:
            self.ui_log("  Comportamiento simulado (estático):")
            for f in describe_behavior_findings(behavior):
                self.ui_log(f"    • {f}")

        strings_info = virus_results.get('strings', {})
        if strings_info.get('urls') or strings_info.get('ips'):
            self.ui_log(f"  Strings: {len(strings_info.get('urls', []))} URL(s), "
                        f"{len(strings_info.get('ips', []))} IP(s)")

        if virus_results.get('polyglot'):
            self.ui_log("  ⚠️ Polyglot: " + '; '.join(virus_results['polyglot']))

    def _log_script_summary(self, script_results):
        self.ui_log("\n📜 ANÁLISIS DE SCRIPT:", 'purple')
        self.ui_log(f"  Nivel: {script_results.get('risk_level', 'N/A')}")
        if script_results.get('truncated'):
            self.ui_log(f"  ⚠️ {script_results.get('analysis_note', 'El análisis del script fue parcial por el límite de lectura.')}", 'red')
        for f in describe_script_findings(script_results):
            self.ui_log(f"    • {f}")

    def _log_ai_summary(self, ai_results):
        self.ui_log("\n🤖 DETECCIÓN DE IA:", 'purple')
        if ai_results.get('skipped'):
            self.ui_log(f"  {ai_results.get('reason', 'No analizado')}")
            return
        prob = ai_results.get('ai_probability')
        self.ui_log(f"  Probabilidad de IA: {f'{prob}%' if prob is not None else 'N/D'}")
        self.ui_log(f"  Prompt embebido: {'Sí' if ai_results.get('prompt_detected') else 'No'}")

    def _run_virus_only(self):
        self.ui_progress_start()
        self.ui_clear_results()
        file_path = self.file_path_var.get()
        self.ui_log("🚀 Analizando virus (local)...\n", 'blue')
        virus_results, from_cache = self._analyze_virus_cached(file_path)
        self._analysis_checkpoint(6, 'Análisis de virus completado')
        if from_cache:
            self.ui_log("♻️  Resultado de caché.\n", 'blue')
        score = virus_results.get('risk_score')
        risk_level = virus_results.get('risk_level')
        indicators = virus_results.get('indicators')
        if score is None or risk_level is None or indicators is None:
            score, risk_level, indicators = calculate_risk_score(virus_results)
        self.ui_log("\n" + "=" * 60, 'green')
        self.ui_log("📊 RESULTADOS", 'green')
        self._log_virus_summary(virus_results, score, risk_level, indicators)
        with self.last_results_lock:
            self.last_results = {'virus': virus_results, 'script': {}, 'ai': {}}
        self.ui_progress_stop()
        self.ui_log("\n✅ Completado.", 'green')

    def _run_script_only(self):
        self.ui_progress_start()
        self.ui_clear_results()
        file_path = self.file_path_var.get()
        self.ui_log("🚀 Analizando script...\n", 'blue')
        file_type = FileTypeDetector.detect(file_path)
        script_results = self._analyze_script(file_path, file_type)
        self._analysis_checkpoint(6, 'Análisis de script completado')
        self._log_script_summary(script_results)
        with self.last_results_lock:
            self.last_results = {'virus': {}, 'script': script_results, 'ai': {}}
        self.ui_progress_stop()
        self.ui_log("\n✅ Completado.", 'green')

    def _run_ai_only(self):
        self.ui_progress_start()
        self.ui_clear_results()
        file_path = self.file_path_var.get()
        self.ui_log("🚀 Detectando IA...\n", 'blue')
        file_type = FileTypeDetector.detect(file_path)
        ai_results = self._analyze_ai(file_path, file_type)
        self._analysis_checkpoint(6, 'Análisis de IA completado')
        self._log_ai_summary(ai_results)
        with self.last_results_lock:
            self.last_results = {'virus': {}, 'script': {}, 'ai': ai_results}
        self.ui_progress_stop()
        self.ui_log("\n✅ Completado.", 'green')

    def _run_full_analysis(self):
        self.ui_progress_start()
        self.ui_clear_results()
        file_path = self.file_path_var.get()
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            raise OSError(f"No se pudo obtener el tamaño del archivo '{file_path}': {e}") from e
        self.ui_log(f"🚀 Análisis completo. Tamaño: {format_size(file_size)}\n", 'blue')

        self.ui_log("🔍 [1/3] Virus...", 'blue')
        virus_results, from_cache = self._analyze_virus_cached(file_path)
        self._analysis_checkpoint(6, 'Virus completado')
        if from_cache:
            self.ui_log("   ♻️  (de caché)", 'blue')
        file_type = virus_results.get('file_type')
        self.ui_log("🔍 [2/3] Script...", 'blue')
        # N-17: el motor ya calculó script/IA dentro del pipeline, así que
        # se reutilizan (también desde caché). Solo los reportes viejos sin
        # esas claves se recalculan en el frontal.
        script_results = virus_results.get('script_results')
        if script_results is None:
            script_results = self._analyze_script(file_path, file_type)
        self._analysis_checkpoint(7, 'Script completado')
        self.ui_log("🔍 [3/3] IA...", 'blue')
        ai_results = virus_results.get('ai_results')
        if ai_results is None:
            ai_results = self._analyze_ai(file_path, file_type)
        self._analysis_checkpoint(8, 'IA completada')

        score, risk_level, indicators = calculate_risk_score(virus_results, script_results, ai_results)
        self.ui_log("\n" + "=" * 60, 'green')
        self.ui_log("📊 RESULTADOS", 'green')
        self._log_virus_summary(virus_results, score, risk_level, indicators)
        self._log_script_summary(script_results)
        self._log_ai_summary(ai_results)
        log_detection(logger, file_path, risk_level, score, indicators)

        with self.last_results_lock:
            self.last_results = {'virus': virus_results, 'script': script_results, 'ai': ai_results}
        self.ui_progress_stop()
        self.ui_log("\n✅ Completado. Presiona 'Generar Reporte'.", 'green')

    def _analyze_virus_cached(self, file_path):
        try:
            hashes = self.static_analyzer.get_file_hashes(file_path)
        except OSError as e:
            # R-11: antes se devolvía {'file','error'} y el flujo lo puntuaba
            # como 'SIN RIESGO DETECTADO'. Un archivo ilegible NO es limpio:
            # se propaga para que el wrapper del worker muestre el error.
            raise OSError(f"No se pudo leer '{file_path}': {e}") from e
        file_hash = hashes['sha256']
        # Fix N-17 #1: la expiración de trust decay se evalúa en CADA análisis,
        # también con force_rescan o caché desactivada. Antes vivía dentro del
        # antiguo _analyze_virus y se perdió al delegar todo al motor, así que
        # el camino "Ignorar caché" volvía a tratar como whitelisted un hash
        # cuyo trust decay ya había vencido.
        whitelist_expired = False
        if self.cache:
            whitelist_expired = bool(self._expire_whitelist_hash_if_needed(file_hash))
        force = self.force_rescan_var.get()
        # Residual N-17: si la whitelist acaba de expirar, la entrada cacheada
        # conserva el veredicto "whitelisted" anterior; hay que re-analizar.
        if self.cache and not force and not whitelist_expired:
            cached = self.cache.get_with_trust_decay(file_hash)
            if cached and cache_report_matches_schema(cached.get('report'), GUI_CACHE_SCHEMA):
                # N-05(b) en GUI: la clave de caché es el SHA256; el reporte
                # cacheado apuntaba a la ruta ORIGINAL y se devolvía tal cual.
                # Escanear una copia con el mismo hash reportaba el archivo
                # equivocado. Se sobreescribe con la ruta realmente escaneada.
                result = dict(cached['report'])
                result['file'] = file_path
                result['_cached'] = True
                return result, True
        # Fix N-17 #4: se reutilizan los hashes ya calculados (una sola lectura
        # en el cache-miss), igual que hace la CLI.
        results = self._analyze_virus(file_path, hashes=hashes)
        results['_cache_schema'] = GUI_CACHE_SCHEMA
        # R-08: un re-escaneo forzado también REFRESCA la caché (como en la
        # CLI); antes dejaba viva la entrada vieja hasta el TTL.
        if self.cache:
            risk_level = results.get('risk_level')
            if risk_level is None:
                _score, risk_level, _indicators = calculate_risk_score(results)
            self.cache.set(file_hash, file_path, risk_level, results)
        return results, False

    def _analyze_virus(self, file_path, hashes=None):
        """Análisis 100% local y de solo-lectura con motor v2 integrado.

        N-17: el pipeline completo vive en el motor único compartido con la
        CLI (analysis_engine.py). Antes este cuerpo (~160 líneas) duplicaba
        cli.py:scan_file (~270 líneas) con divergencias reales: la GUI no
        registraba explicaciones fuzzy TLSH/ssdeep (N-19) ni de empaquetado,
        puntuaba sin script/IA y sin capas, y re-analizaba los miembros de
        contenedores de forma distinta. Aquí solo queda el contrato GUI
        (caché y progreso/cancelación los gestionan los callers).
        """
        return self.engine.analyze_file(file_path, hashes=hashes)

    def _scan_member(self, file_path: str) -> Dict:
        """Miembro de contenedor: mismo pipeline del motor y sin caché
        (antes esto dejaba un camino divergente respecto a cli.py, que
        re-analizaba los miembros con scan_file y con caché). N-17."""
        return self.engine.scan_member(file_path)

    def _analyze_script(self, file_path, file_type=None):
        if file_type is None:
            file_type = FileTypeDetector.detect(file_path)
        # N-04: solo código real; no textos de datos (Markdown/TXT/JSON...).
        if not is_script_code(file_path, file_type):
            return {'skipped': True, 'reason': 'No es código/script; se omite.'}
        return self.script_analyzer.analyze_script(file_path, file_type)

    def _analyze_ai(self, file_path, file_type=None):
        if file_type is None:
            file_type = FileTypeDetector.detect(file_path)
        if not is_analyzable_as_text(file_path, file_type):
            return {'skipped': True, 'reason': 'No es texto; se omite.'}
        return self.ai_detector.analyze_file(file_path)

    def generate_report(self):
        if not hasattr(self, 'last_results'):
            messagebox.showwarning("Advertencia", "Primero realiza un análisis")
            return
        with self.last_results_lock:
            last_results = dict(self.last_results)
        report = self.report_generator.generate_report(
            self.file_path_var.get(),
            last_results['virus'], last_results['script'], last_results['ai'],
        )
        try:
            json_file = self.report_generator.save_json(report)
            html_file = self.report_generator.save_html(report)
        except OSError as e:
            logger.error("No se pudo guardar el reporte: %s", e, exc_info=True)
            messagebox.showerror("Error al guardar reporte", str(e))
            return
        logger.info("Reporte generado: %s / %s", json_file, html_file)
        messagebox.showinfo("Reporte Generado", f"Guardados:\n- {json_file}\n- {html_file}")

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        if hasattr(self, 'last_results'):
            del self.last_results


def main():
    root = tk.Tk()
    PyThreatAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
    
    
