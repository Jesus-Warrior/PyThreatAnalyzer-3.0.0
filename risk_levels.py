"""risk_levels.py — K4: fuente única de niveles, pesos y umbrales de riesgo.

Antes estas constantes vivían copiadas: _LEVEL_RANK en archive_analyzer.py y
en explanation_engine.py, _LEVEL_RANK_LAYERED en risk_scoring.py (claves
idénticas hoy, pero una deriva futura habría hecho que un mismo nivel pesara
distinto según el módulo). No importa nada del proyecto para evitar ciclos.
"""

# Orden de severidad; los alias (BENIGNO / SIN RIESGO DETECTADO, SOSPECHOSO /
# MEDIO) comparten rango.
LEVEL_RANK = {
    'BENIGNO': 0, 'SIN RIESGO DETECTADO': 0, 'BAJO': 1,
    'SOSPECHOSO': 2, 'MEDIO': 2, 'ALTO': 3, 'CRÍTICO': 4,
}

# Peso de un contenedor según su nivel agregado (N-12: cada peso alcanza el
# umbral de su propio nivel en level_for_score).
ARCHIVE_LEVEL_WEIGHT = {
    'BENIGNO': 0, 'SIN RIESGO DETECTADO': 0, 'BAJO': 5,
    'SOSPECHOSO': 25, 'MEDIO': 25, 'ALTO': 50, 'CRÍTICO': 100,
}

# Mapa de severidad YARA (meta.severity) -> puntuación.
SEVERITY_MAP = {
    'critical': 50, 'high': 40, 'medium': 20, 'low': 10,
}

WHITELIST_SCORE_CAP = 15
# R-01: tope de puntos por patrones de dropper (descarga+ejecución).
DROPPER_MAX_POINTS = 45


def level_for_score(score):
    """Nivel de riesgo para un score 0-100."""
    if score >= 80:
        return 'CRÍTICO'
    if score >= 50:
        return 'ALTO'
    if score >= 25:
        return 'MEDIO'
    if score >= 1:
        return 'BAJO'
    return 'SIN RIESGO DETECTADO'
