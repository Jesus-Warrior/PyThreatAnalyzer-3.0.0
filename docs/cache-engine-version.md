# Versión del motor y caché de análisis

PyThreatAnalyzer 3.0.0 usa `ENGINE_VERSION = 6` en `analysis_cache.py`. La versión
del motor forma parte de la validez de cada resultado guardado en SQLite.

La caché de la versión 5 queda obsoleta porque 3.0.0 cambia puntuaciones y
veredictos de riesgo, el orden de las fases y campos del informe. Reutilizar esos
resultados podría mostrar un análisis hecho con reglas anteriores. Al iniciar,
la aplicación elimina las entradas caducadas y las de versiones inferiores a la
actual; los resultados marcados con una versión futura se conservan.

Se debe incrementar `ENGINE_VERSION` cuando cambie la lógica que puede alterar
un veredicto, una puntuación o la forma semántica del resultado. Los cambios
puramente visuales que no afectan los datos guardados no requieren por sí solos
una nueva versión de caché.
