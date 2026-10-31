"""
Logging centralizado con rotación (evita que pythreatanalyzer.log /
detections.log crezcan sin límite en uso prolongado):
  - pythreatanalyzer.log : todo (DEBUG+), rota a los 10MB, conserva 5 backups.
  - detections.log       : solo WARNING+ (hallazgos concretos: hash malo,
                            riesgo ALTO/CRÍTICO), rota a los 10MB, 10 backups
                            (se prioriza retener más historial de detecciones
                            que de logs operativos generales).
"""

import logging
import logging.handlers
import json
import os
import stat
import sys
import threading

_configured = False
_configure_lock = threading.Lock()


class JsonLineFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            'timestamp': self.formatTime(record, '%Y-%m-%dT%H:%M:%S'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }, ensure_ascii=False)


def _reject_symlinked_log_path(log_dir):
    """B6: rechaza symlinks en log_dir y en sus directorios padre.

    Solo comprobar el fichero hoja no basta: si log_dir o un padre es un
    symlink escribible por otro usuario, los logs se redirigen. La comprobación
    se hace sobre la ruta SIN resolver (tras os.path.realpath ya no quedaría
    ningún symlink que detectar).

    - log_dir en sí: cualquier symlink se rechaza.
    - Ancestros: se toleran los symlinks propiedad de root (p. ej. /tmp, /var,
      /lib en distros o macOS); solo root puede redirigirlos, así que no
      amplían el modelo de amenaza. Un symlink de un usuario no privilegiado se
      rechaza. En Windows st_uid es siempre 0 y no hay forma de distinguirlo.
    """
    absolute = os.path.abspath(log_dir)
    parts = []
    head = absolute
    while True:
        head, tail = os.path.split(head)
        if not tail:
            break
        parts.append(tail)
    current = head  # raíz ('/' o 'C:\\')
    for index, part in enumerate(reversed(parts)):
        current = os.path.join(current, part)
        is_log_dir = index == len(parts) - 1
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return  # el resto aún no existe; makedirs lo creará sin symlinks
        if stat.S_ISLNK(st.st_mode):
            if is_log_dir or st.st_uid != 0:
                raise OSError(
                    f"Se rechaza directorio de logs con enlace simbólico: {current}")


def setup_logging(log_dir='.', log_format='text'):
    global _configured
    with _configure_lock:
        if _configured:
            return logging.getLogger('PyThreatAnalyzer')

        _reject_symlinked_log_path(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        # Refuse pre-planted symlinks for log files; opening a symlink could
        # otherwise overwrite an arbitrary user-writable target.
        for log_name in ('pythreatanalyzer.log', 'detections.log'):
            log_path = os.path.join(log_dir, log_name)
            try:
                if stat.S_ISLNK(os.lstat(log_path).st_mode):
                    raise OSError(f"Se rechaza archivo de log enlazado simbólicamente: {log_path}")
            except FileNotFoundError:
                pass

        logger = logging.getLogger('PyThreatAnalyzer')
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        if log_format not in ('text', 'json'):
            log_format = 'text'
        fmt = (JsonLineFormatter() if log_format == 'json' else
               logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
                                 datefmt='%Y-%m-%d %H:%M:%S'))

        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, 'pythreatanalyzer.log'),
            maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)

        # Keep stdout machine-readable for `--output json`; diagnostics remain
        # visible on the terminal and are sent to stderr.
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(fmt)

        detection_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, 'detections.log'),
            maxBytes=10 * 1024 * 1024, backupCount=10, encoding='utf-8')
        detection_handler.setLevel(logging.WARNING)
        detection_handler.setFormatter(fmt)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.addHandler(detection_handler)

        _configured = True
        return logger


def log_detection(logger, file_path, risk_level, score, indicators):
    """Registra un hallazgo de riesgo medio o superior en detections.log."""
    # Keep attacker-controlled paths and indicators on one log line.
    safe_path = ''.join(ch if ch >= ' ' and ch not in '\x7f\x1b' else '?' for ch in str(file_path))
    safe_indicators = [str(item).replace('\r', '?').replace('\n', '?') for item in (indicators or [])]
    if risk_level in ('MEDIO', 'ALTO', 'CRÍTICO'):
        logger.warning(
            "Riesgo %s (score=%d) en '%s' — indicadores: %s",
            risk_level, score, safe_path, ', '.join(safe_indicators) if safe_indicators else 'ninguno'
        )
    else:
        logger.info("Riesgo %s en '%s'", risk_level, safe_path)
