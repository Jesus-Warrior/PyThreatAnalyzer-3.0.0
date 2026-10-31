"""Carga y validación única de config.json para la CLI y la GUI.

Por qué un validador en vez de `config.update(json.load(f))`
------------------------------------------------------------
Antes, main.py y cli.py tenían cada una su propia lista de defaults y ambas
hacían `config.update(json.load(f))` sin validar nada. Eso producía tres
problemas reales:

  1. Las listas divergían: `use_cache` solo existía en la GUI, así que la
     CLI siempre creaba la caché aunque el usuario la hubiera desactivado.
  2. Un valor con el tipo equivocado (p.ej. "cache_ttl_days": "treinta")
     reventaba más tarde, lejos de su causa, con un TypeError o ValueError
     dentro de timedelta().
  3. Un typo en una clave ("cache_ttl_day") se ignoraba en silencio: el
     usuario creía haber configurado 60 días y tenía 30. Es la misma clase
     de bug que A-6 (un estado que afirma algo que no se midió).

Filosofía: fallback + warning, nunca hard-fail
----------------------------------------------
El proyecto ya degrada en todas partes en vez de abortar: ml_detector cae a
heurístico si el modelo no carga, StaticAnalyzer devuelve database_status
'unavailable' si falta la base, YARAEngine compila archivo por archivo si
la compilación conjunta falla. Un config inválido que impide arrancar sería
incoherente con todo lo demás, y el caso real es un usuario editando el JSON
a mano que quiere saber qué está mal, no quedarse sin herramienta.

  - clave ausente            -> default, en silencio (el caso normal)
  - tipo/rango inválido      -> default + warning visible
  - clave deprecada          -> info, con el motivo
  - clave desconocida        -> warning + sugerencia por similitud

Los avisos se acumulan y se emiten en un único log al final: cinco typos
producen cinco líneas y se lee como cinco fallos de arranque distintos.
"""

import difflib
import importlib
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger('PyThreatAnalyzer')

DEFAULT_CONFIG = {
    "yara_rules_path": "data/yara_rules/",
    "malware_hashes_db": "data/denylist/tweetfeed_sha256.txt",
    "known_good_hashes_db": "data/allowlist/nsrl_sha256.txt",
    "malware_imphashes_db": "malware_imphashes.txt",
    "malware_tlsh_db": "malware_tlsh.txt",
    "malware_ssdeep_db": "malware_ssdeep.txt",
    "nsrl_db": None,
    "ml_model_path": None,
    "trusted_ml_model_sha256": None,
    "log_format": "text",
    "yara_timeout_seconds": 30,
    "cache_db_path": "analysis_cache.db",
    "cache_ttl_days": 30,
    "trust_decay_days": 90,
    "use_cache": True,
    # R-05: presupuesto (segundos) para analizar los miembros de un
    # contenedor y de todos los anidados. Al agotarse, los miembros restantes
    # no se analizan y el resultado queda INCOMPLETE/SOSPECHOSO.
    "max_member_analysis_seconds": 120.0,
}

# Claves que existieron y ya no hacen nada. Se distinguen de los typos para
# que quien migra desde una versión anterior entienda por qué se ignora.
DEPRECATED_KEYS = {
    'dynamic_analysis_timeout': (
        'eliminado; el análisis dinámico es 100% estático y no usa timeout'
    ),
}

# Rangos máximos. Los ceilings no son arbitrarios: acotan recursos (un TTL de
# 99999 días en caché local es una fuga de disco silenciosa).
TTL_DAYS_RANGE = (1, 3650)
YARA_TIMEOUT_RANGE = (1, 300)
MEMBER_ANALYSIS_SECONDS_RANGE = (1.0, 3600.0)

_BOOL_TRUE = {'true', 'yes', '1', 'on'}
_BOOL_FALSE = {'false', 'no', '0', 'off'}


class _Invalid(Exception):
    """Valor presente pero no utilizable; el llamador usa el default."""


def _as_bool(value):
    # bool(algo) convierte "false" y "0" en True: jamás usar coerción
    # implícita en una bandera que decide si se lee la caché.
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _BOOL_TRUE:
            return True
        if normalized in _BOOL_FALSE:
            return False
    raise _Invalid(f"se esperaba booleano (true/false), llegó {value!r} "
                   f"de tipo {type(value).__name__}")


def _as_int_in_range(value, name, low, high):
    # bool es subclase de int: True no vale como 1 en un campo numérico.
    if isinstance(value, bool):
        raise _Invalid(f"se esperaba entero, llegó booleano {value!r}")
    if isinstance(value, str):
        # Aceptar "60" escrito a mano es más útil que rechazarlo; cualquier
        # otra cosa ("treinta", "30d", "") cae al default con warning.
        text = value.strip()
        try:
            value = int(text, 10)
        except ValueError:
            raise _Invalid(f"se esperaba entero, llegó {value!r}") from None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if not isinstance(value, int):
        raise _Invalid(f"se esperaba entero, llegó {type(value).__name__}")
    if not low <= value <= high:
        raise _Invalid(f"{value} fuera de rango [{low}, {high}]")
    return value


def _as_float_in_range(value, name, low, high):
    # Mismo criterio que _as_int_in_range: bool no vale como número, y
    # "60" escrito a mano se acepta; cualquier otra cosa cae al default.
    if isinstance(value, bool):
        raise _Invalid(f"se esperaba número, llegó booleano {value!r}")
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            raise _Invalid(f"se esperaba número, llegó {value!r}") from None
    if not isinstance(value, (int, float)):
        raise _Invalid(f"se esperaba número, llegó {type(value).__name__}")
    value = float(value)
    # NaN/inf no cumplen low <= v <= high, así que también se rechazan aquí.
    if not low <= value <= high:
        raise _Invalid(f"{value} fuera de rango [{low:g}, {high:g}]")
    return value


def _as_nonempty_str(value):
    if not isinstance(value, str):
        raise _Invalid(f"se esperaba texto, llegó {type(value).__name__}")
    text = value.strip()
    if not text:
        raise _Invalid("cadena vacía")
    return text


def _as_optional_str(value):
    if value is None:
        return None
    return _as_nonempty_str(value)


def _as_choice(value, allowed):
    text = _as_nonempty_str(value).lower()
    if text not in allowed:
        raise _Invalid(f"{value!r} no es válido; opciones: {', '.join(sorted(allowed))}")
    return text


def _as_sha256_hex(value):
    if value is None:
        return None
    text = _as_nonempty_str(value).lower()
    if len(text) != 64 or any(c not in '0123456789abcdef' for c in text):
        raise _Invalid("se esperaba un hash SHA-256 de 64 caracteres hexadecimales")
    return text


# (clave, validador). El default sale de DEFAULT_CONFIG: una sola fuente.
_SCHEMA = (
    ("yara_rules_path", _as_nonempty_str),
    ("malware_hashes_db", _as_nonempty_str),
    ("known_good_hashes_db", _as_nonempty_str),
    ("malware_imphashes_db", _as_nonempty_str),
    ("malware_tlsh_db", _as_nonempty_str),
    ("malware_ssdeep_db", _as_nonempty_str),
    ("nsrl_db", _as_optional_str),
    ("ml_model_path", _as_optional_str),
    ("trusted_ml_model_sha256", _as_sha256_hex),
    ("log_format", lambda v: _as_choice(v, {'text', 'json'})),
    ("yara_timeout_seconds",
     lambda v: _as_int_in_range(v, 'yara_timeout_seconds', *YARA_TIMEOUT_RANGE)),
    ("cache_db_path", _as_nonempty_str),
    ("cache_ttl_days",
     lambda v: _as_int_in_range(v, 'cache_ttl_days', *TTL_DAYS_RANGE)),
    ("trust_decay_days",
     lambda v: _as_int_in_range(v, 'trust_decay_days', *TTL_DAYS_RANGE)),
    ("use_cache", _as_bool),
    ("max_member_analysis_seconds",
     lambda v: _as_float_in_range(v, 'max_member_analysis_seconds',
                                  *MEMBER_ANALYSIS_SECONDS_RANGE)),
)

KNOWN_KEYS = frozenset(key for key, _ in _SCHEMA)


def load_config(path='config.json'):
    """Devuelve la configuración validada; nunca lanza por un valor inválido.

    El fichero ausente o ilegible no es un error: se usa el default entero y
    se avisa solo si había algo que leer y no se pudo leer.
    """
    raw = None
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                raw = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("No se pudo leer %s (%s); se usan los valores por defecto.",
                           path, exc)
    elif os.path.isdir(path):
        logger.warning("%s es un directorio, no un fichero de configuración; "
                       "se usan los valores por defecto.", path)

    # Operational overrides (e.g. a locally stored, multi-GB NSRL SQLite)
    # stay out of the tracked config and release ZIP.
    local_path = os.path.join(os.path.dirname(os.path.abspath(path)), 'config.local.json')
    if os.path.isfile(local_path):
        try:
            with open(local_path, 'r', encoding='utf-8') as handle:
                local_raw = json.load(handle)
            if isinstance(raw, dict) and isinstance(local_raw, dict):
                raw = {**raw, **local_raw}
            elif isinstance(local_raw, dict):
                raw = local_raw
            else:
                logger.warning("%s no contiene un objeto JSON; se ignora.", local_path)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("No se pudo leer %s (%s); se ignora.", local_path, exc)

    config = dict(DEFAULT_CONFIG)
    if not isinstance(raw, dict):
        if raw is not None:
            logger.warning("%s no contiene un objeto JSON; se usan los valores "
                           "por defecto.", path)
        _resolve_installed_data_defaults(config, set())
        return config

    problems = []
    notes = []

    for key, raw_value in raw.items():
        if key in DEPRECATED_KEYS:
            notes.append(f"'{key}': {DEPRECATED_KEYS[key]}")
            continue
        if key not in KNOWN_KEYS:
            # Un typo no debe fallar, pero sí ser visible: si no, el usuario
            # cree haber configurado algo que en realidad se ignora.
            suggestion = difflib.get_close_matches(key, sorted(KNOWN_KEYS), n=1, cutoff=0.6)
            hint = f" ¿Quiso decir '{suggestion[0]}'?" if suggestion else ""
            problems.append(f"clave desconocida '{key}' (ignorada).{hint}")
            continue

        validator = next(v for k, v in _SCHEMA if k == key)
        try:
            config[key] = validator(raw_value)
        except _Invalid as exc:
            default = DEFAULT_CONFIG[key]
            problems.append(f"'{key}' inválido: {exc}; se usa el valor por defecto "
                            f"{default!r}")

    # Un único aviso por categoría en vez de uno por incidencia: cinco typos
    # deben leerse como un problema de configuración, no como cinco fallos.
    if notes:
        logger.info("Configuración: %s", '; '.join(notes))
    if problems:
        logger.warning("Configuración inválida en %s -> %s",
                       path, ' | '.join(problems))

    _resolve_installed_data_defaults(config, set(raw))
    return config


def _resolve_installed_data_defaults(config, explicit_keys):
    """Resolve bundled data paths for wheel installs outside the source tree."""
    try:
        package = importlib.import_module('pythreatanalyzer_data')
    except ImportError:
        return
    root = Path(package.__file__).resolve().parent
    packaged_paths = {
        'yara_rules_path': ('yara_rules',),
        'malware_hashes_db': ('denylist', 'tweetfeed_sha256.txt'),
        'known_good_hashes_db': ('allowlist', 'nsrl_sha256.txt'),
    }
    for key, parts in packaged_paths.items():
        if key not in explicit_keys:
            config[key] = str(root.joinpath(*parts))
