# Changelog

## [3.0.0] — Seguridad, consistencia y empaquetado

### Breaking
- K5.1: `sample_sha256` identifica el prefijo de bytes leído por el analizador dinámico; no sustituye al hash completo.
- K5.2: los informes JSON de GUI y CLI incluyen `report_schema_version: 1` como primer campo.

### Added
- M1: límite configurable de tiempo para analizar miembros de contenedores.
- M2: detección estructural y límites adicionales para contenedores anidados.
- M3: detección de archivos polyglot PE+ZIP con EOCD extendido.
- M4: importación de Tkinter tolerante a entornos sin la extensión nativa.
- M5: cierre cooperativo y cancelación de la GUI.
- B2: JWT y datos de texto/hex no se confunden con blobs Base64 ofuscados.
- B5: las referencias ordenadas se recalculan después de mutaciones de igual tamaño.
- B6: las rutas de logs con enlaces simbólicos no confiables se rechazan.
- Reportes JSON de CLI, directorio y GUI publican el esquema v1 como primer campo.
- Avisos de cobertura visibles cuando las bases fuzzy TLSH/ssdeep están vacías.
- K1: purga de caché por TTL y versión del motor.
- K2: sondeo y cierre de GUI con límites seguros.
- K3: estado derivado del análisis se mantiene consistente tras cambios de referencias.
- K4: niveles de riesgo con una única fuente de verdad.
- K8: avisos explícitos cuando las fuentes de datos no cubren el análisis.
- K9: reintento de errores transitorios al recorrer directorios.
- N1: motor de análisis unificado para CLI y GUI.
- N2: informes locales con estado, capas y explicaciones de análisis.

### Changed
- Se eliminaron de `MANIFEST.in` y del empaquetador las referencias a `REPORTE_*.md`, archivos de notas que no existían; las notas vigentes están en `docs/`.
- `MANIFEST.in` se documenta como manifiesto para sdist del repositorio; el ZIP mantiene su lista de distribución independiente.
- El aviso de instalación local de NSRL ahora apunta a `./setup-data.sh`, ubicado en la raíz del ZIP.
- Se aclara que el importador heredado de MalwareBazaar permanece como utilidad opcional; sus datos y metadatos no forman parte del feed activo.
- B1: `sys.exit` y `os.fork` legítimos ya no cuentan como imports sospechosos.
- B3: Base64 decodificado a texto o valores hex no se trata como payload binario sospechoso.
- B4: detección contextual de firmas de ejecutables embebidas en PDF.
- B7: conexiones SQLite se cierran desde el hilo que las creó.
- K6: los IOC de red aislados en PE se consideran señales de baja confianza.
- Versión centralizada en `pythreat_version.py`; `ENGINE_VERSION` pasa a 6.

### Fixed
- K7: tamaño declarado de contenedores se conserva si se alcanza un límite.
- Se purgan entradas de caché con versiones anteriores y se conservan versiones futuras.
- La cobertura de datos estricta se valida antes de crear el ZIP.

## [2.0.0] — Baseline

- CLI y GUI comparten el motor local de análisis y su caché SQLite.
- Análisis estático de archivos, scripts, documentos y contenedores con reglas e indicadores configurables.
- Informes JSON/HTML y operación local sin ejecutar los archivos analizados.
