# Pruebas y omisiones esperadas

## Instalación para desarrollo

Instala las dependencias de desarrollo y ambos backends fuzzy:

```sh
python -m pip install -e '.[dev,fuzzy]'
```

`requirements-dev.txt` incluye `pefile`, requerido por las pruebas de overlay
PE. Sin esa dependencia, las pruebas correspondientes fallarán; instala el
conjunto de desarrollo antes de ejecutar la suite.

En Linux, `ssdeep` requiere la biblioteca nativa antes de instalar el paquete:

```sh
sudo apt-get install libfuzzy-dev build-essential
```

`ssdeep` 3.4 solo se distribuye como código fuente y su `setup.py` importa
`pkg_resources`, que las versiones recientes de `setuptools` ya no incluyen.
Por eso se instala en dos pasos, con `setuptools<81` y sin aislamiento de
compilación (CI y release hacen lo mismo):

```sh
python -m pip install --require-hashes -r requirements-dev.txt
python -m pip install "setuptools<81"
python -m pip install --no-build-isolation --require-hashes -r requirements-fuzzy.in
```

Esto deja `setuptools` en la serie 80 en ese entorno (el lock de desarrollo
fija 84.0.0). Es solo una herramienta de compilación y no afecta al análisis.
El extra `fuzzy` tiene la misma limitación.

TLSH (`python-tlsh`) forma parte de las dependencias principales del proyecto;
el extra `fuzzy` agrega ssdeep. Comprueba ambos imports con
`python -c 'import tlsh, ssdeep'` y ejecuta `python -m pytest`.

## Omisiones GUI y fuzzy

El número de omisiones depende de Tkinter, del display disponible y de los
backends fuzzy instalados. Con Tk instalado pero sin display se esperan 2
omisiones GUI; si Tkinter no está disponible, pueden omitirse las 7 pruebas
GUI. La suite omite cada prueba GUI que no puede iniciar Tk. Los conteos
observados son dependientes del entorno; el runner imprime el nombre y el
motivo concreto de cada omisión.

| Prueba | Motivo | Resolución |
|---|---|---|
| `test_gui_open_close_with_display`, `test_gui_visible_with_display` | No hay display gráfico; Tkinter responde `couldn't connect to display`. | Ejecutar bajo una sesión gráfica o un servidor virtual X como Xvfb. |
| Pruebas GUI adicionales: `test_verification_32_cache_hit_uses_scanned_path`, `test_verification_34_cli_gui_delegate_to_engine`, `test_verification_35_force_rescan_expires_whitelist`, `test_verification_38_expired_whitelist_invalidates_cached_hit`, `test_e01_on_close_cancels_and_forces_after_grace` | También requieren Tkinter; pueden omitirse sin Tk. | Instalar Tk y ejecutar bajo una sesión gráfica o Xvfb. |
| `test_area7_fuzzy_importer` | Solo se omite si no está disponible ni TLSH ni ssdeep. Si está TLSH pero falta ssdeep, ejecuta las partes TLSH y no cubre el backend ssdeep. | Instalar el extra `fuzzy` y las dependencias nativas de ssdeep en Linux para cubrir ambos backends. |

La prueba fuzzy es adaptativa: ejecuta las partes disponibles si al menos uno de
los backends está presente; solo se omite cuando faltan ambos. Por eso TLSH
instalado sin ssdeep no significa que la cobertura de ambos backends esté
completa. El workflow CI y
el de release instalan las dependencias fijadas y comprueban ambos imports antes
de correr la suite. Así una ausencia accidental de TLSH o ssdeep hace fallar el
job en vez de dejar que la prueba se omita.

La suite usa opciones de cobertura configuradas en `pyproject.toml`; por eso
`pytest-cov` está incluido en el extra `dev`. Si se ejecuta pytest en un entorno
que solo tiene pytest y no pytest-cov, puede usarse
`python -m pytest -o addopts=` para una ejecución local sin cobertura.

## Resultados de referencia de la distribución 3.0.0

La última verificación registrada obtuvo estos resultados; pueden variar según
Tkinter, el display y las dependencias opcionales disponibles:

| Contexto | Resultado | Omisiones conocidas |
|---|---:|---|
| Checkout del proyecto | 70 pasadas / 3 omitidas / 0 fallidas | 2 GUI sin display y 1 fuzzy cuando faltan ambos backends. |
| ZIP extraído | 69 pasadas / 4 omitidas / 0 fallidas | Las anteriores y la prueba del manifiesto, que requiere el árbol del repositorio. |

Si Tkinter no está instalado, pueden omitirse 7 pruebas GUI en lugar de 2.
La ausencia de `pefile` puede hacer fallar las pruebas de overlay PE; instala
`requirements-dev.txt` antes de ejecutar la suite.

## Cobertura de datos en CI

CI valida los fixtures offline con `scripts/check-data-coverage.sh --ci` y
después valida las fuentes reales con `--release`. El segundo modo es estricto,
devuelve un código distinto de cero si falta el feed, sus metadatos, las reglas,
su procedencia o un checksum. GitHub Actions ejecuta cada paso `run` con
`bash -e`; un código fallido detiene el job.

La allowlist NSRL se instala localmente después de extraer el ZIP, por lo que su
ausencia en el repositorio no hace fallar la validación de distribución.

## EICAR

Las reglas YARA incluidas contienen una firma de prueba EICAR marcada con
`severity = "test"`. Un match debe aparecer como `YARA_MATCH`; el nivel final
puede seguir siendo `BAJO` porque las reglas de prueba usan el peso YARA bajo.
EICAR es una cadena inocua para probar respuestas antivirus. `signals_level`
es un resumen explicativo y puede diferir del nivel final de scoring; consulta
`risk_level` para el resultado que usa la CLI y la GUI.
