# PyThreatAnalyzer

PyThreatAnalyzer performs local static analysis of files. It does not execute scanned files. The GUI and CLI can inspect hashes, file structure, scripts, Office documents, archives, YARA rules, and optional ML features. Detection coverage depends on the installed optional data sources and dependencies; a clean result is not proof that a file is safe.

## Requirements and installation

Use Python 3.11–3.13. The committed locks include transitive dependencies and hashes. `ssdeep` is a separately locked optional feature because its source distribution needs native `libfuzzy` headers on Linux. Install it in a clean virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt -r requirements-fuzzy.in
```

For development and tests, run `python -m pip install --require-hashes -r requirements-dev.txt -r requirements-fuzzy.in`. On Debian/Ubuntu, `ssdeep` also needs `libfuzzy-dev` (`sudo apt-get install libfuzzy-dev`). `requirements.in` is the reviewed core dependency input; regenerate the lock with `uv pip compile --universal --generate-hashes requirements.in -o requirements.txt`. The `ssdeep` source is pinned by version and the SHA-256 hash recorded in `requirements-fuzzy.in`; review dependency changes before committing them.

## Use

```sh
python cli.py scan FILE --output json > report.json
python cli.py scan FILE --progress
python cli.py scan-directorio DIRECTORY --recursive --output json --output-file report.json
python main.py
```

Both JSON CLI forms and GUI report files use `report_schema_version: 1` as their first object key. Directory JSON is an object with a `results` array.

### Documentation

- [Data sources, licensing, and coverage](docs/data-sources.md)
- [Cache engine migration](docs/cache-engine-version.md)
- [Tests and expected skips](docs/tests.md)

The GUI requires a working Tk installation. Scan directories sequentially; use `--max-files` and `--max-time` to bound work. Ctrl+C stops a directory scan after the current file and preserves results completed so far.

After installing the hash-locked dependencies, install the local package without resolving a second unpinned dependency set using `python -m pip install --no-deps --no-build-isolation .`. This exposes `pythreatanalyzer` and `pythreatanalyzer-gui`; the development lock includes the build backend needed by `--no-build-isolation`.

## Packaging and headless CI

`verificar_y_empaquetar.py` checks that every module imports. `main.py` imports `tkinter` at module level, so in headless CI (no Tk) the `import main` check is skipped with a warning (`import main omitido: tkinter no disponible`); `main.py` is still included in the generated package.

## Engine and report versions

PyThreatAnalyzer 3.0.0 uses analysis engine version **6**. The SQLite cache serves results only when their engine version matches; startup removes expired entries and entries from older engines, while preserving entries tagged with a future engine version. See the [cache migration note](docs/cache-engine-version.md) for why v5 results are invalidated. JSON reports use `report_schema_version: 1` as their first field so consumers can identify the report format.

Las pruebas headless y sus omisiones esperadas, incluidos los requisitos TLSH/ssdeep, están descritos en [docs/tests.md](docs/tests.md).

The default `source` ZIP contains the required application and data files but omits repository workflows and scripts. Commands under `scripts/` and `verificar_y_empaquetar.py` are repository-maintainer tools: run them from a source checkout, not from an installed ZIP. `python verificar_y_empaquetar.py --full` includes the selected TweetFeed denylist and YARA rules. Run `./scripts/check-data-coverage.sh --ci` to validate offline synthetic fixtures or `./scripts/check-data-coverage.sh --release` to require real data and provenance. The equivalent `--strict-data-coverage` option makes packaging fail before writing a ZIP.

Threat data lives separately under `data/allowlist/`, `data/denylist/`, and `data/yara_rules/`. NSRL is the known-good allowlist; TweetFeed supplies recent community-reported SHA-256 indicators; the selected PRX-SD Built-in and ReversingLabs MIT rules provide YARA coverage. These sources are complementary and a match is an analysis signal, not a final verdict. Fuzzy databases remain separate and optional.

El paquete de datos se actualiza con las instrucciones de [fuentes y cobertura](docs/data-sources.md), ejecutadas desde un checkout del repositorio. TweetFeed no requiere clave; ejecuta `python scripts/import-tweetfeed.py --window year` para importar solo SHA-256 y guardar procedencia. El importador aplica ETag y respeta el límite recomendado de una consulta cada 15 minutos. Para importar reglas, sigue el flujo de fuentes YARA documentado, que limita PRX-SD a las subfuentes MIT seleccionadas y no ejecuta su sincronizador global. **Paso 0 tras instalar:** si tienes un SQLite RDSv3 de NSRL, ejecuta `NSRL_DOWNLOAD_DATE=YYYY-MM-DD ./setup-data.sh /path/to/RDS.sqlite` desde la raíz del proyecto para consultas locales de solo lectura. El helper registra origen, licencia, fecha declarada, tamaño y SHA-256 en `nsrl.local.json`, ignorado por Git y excluido del ZIP. Sin NSRL, el análisis continúa con un aviso visible de cobertura reducida. NIST no descarga la base automáticamente; revisa publicación, espacio y checksum oficial antes de configurarla. VirusShare queda excluido por su restricción no comercial.

After each authorized import, the importers regenerate `data/checksums.txt`. These maintenance commands require a source checkout; they are not present in the installed ZIP. Run `scripts/check-data-coverage.sh --release` to validate real feed contents, provenance, MIT notices, YARA compilability, and checksums. It accepts NSRL when a valid SQLite is configured in `config.local.json`; without a local NSRL it records the post-install setup step, because the SQLite is intentionally excluded from the ZIP. For release, use `python verificar_y_empaquetar.py --full --strict-data-coverage`; the ZIP includes TweetFeed and both selected YARA sources. Legacy MalwareBazaar ingestion is not enabled in the shipped configuration; review its current terms and data notice before using its maintenance script. `data/NOTICE` and `docs/data-sources.md` record source scope and redistribution decisions. Empty fuzzy files do not block release. For locally held, authorized samples, create fuzzy databases with:

```sh
python import_fuzzy_hashes.py /path/to/authorized-samples \
  --tlsh-db malware_tlsh.txt --ssdeep-db malware_ssdeep.txt
```

The existing YARA updater sources [Yara-Rules/rules](https://github.com/Yara-Rules/rules); that upstream ruleset is GPL-2.0, so review license compatibility before bundling its rules. Keep the source revision pinned and review the generated `_manifest.json`. Dispatching `release.yml` manually against a tag runs the signing and verification jobs but skips GitHub release publication; a tag push publishes after those checks pass.

## GUI close and cancellation

Closing the window sets the cancel event. Cancellation is cooperative between analysis phases: it does not interrupt a native call already in progress (for example `pefile` on a malformed PE or `ssdeep`). If the worker has not stopped after 10 seconds the close is forced (the worker is a daemon thread); a "Forzar cierre" button appears to force it immediately.

## Configuration notes

`max_member_analysis_seconds` (default 120.0, range 1-3600) bounds the time spent analysing members of a container and its nested containers. When exhausted, the remaining members are skipped and the result is `INCOMPLETE`/`SOSPECHOSO`.

## Updating YARA rules

Rule updates use a reviewed, locally downloaded source tree. Pin the full upstream commit, review its root license and any per-rule license metadata, then stage it with:

```sh
python scripts/import-yara-rules.py --source-dir /path/to/reviewed/source \
  --source-url https://github.com/OWNER/REPOSITORY \
  --commit FULL_40_HEX_COMMIT_SHA --license MIT
```

Only MIT or DRUL-1.0 are accepted by this importer. Every included rule must compile individually; rules declaring NC or proprietary terms are rejected. A commit SHA pins content but does not authenticate the publisher, so verify it through an independent source. Follow the trust guidance in [SECURITY.md](SECURITY.md).

GUI-dependent tests require Tkinter; the tests that open a real window also require a usable display. The runner reports each omitted test and its reason, so the skip count varies by environment. The optional fuzzy importer test is omitted only when neither TLSH nor ssdeep is installed; install the `fuzzy` extra to cover ssdeep as well as the core TLSH backend.

## Limitations

- Results depend on local hash databases, YARA rules, parser availability, and heuristics. Empty or missing data sources reduce coverage.
- Resource caps limit individual work, but no static analyzer can guarantee a fixed runtime for every malformed input.
- GUI cancellation is cooperative between analysis phases; a native parser or hash operation already in progress cannot always be interrupted immediately.
- An `INCOMPLETE` analysis status describes missing analysis coverage, not a higher or lower malware probability.
- Read [SECURITY.md](SECURITY.md) before loading an external ML model or updating rules.
