# Fuentes de datos y cobertura

## Fuentes seleccionadas para PyThreatAnalyzer 3.0.0

| Fuente | Uso y alcance | Licencia y conservación | Actualización |
|---|---|---|---|
| [TweetFeed](https://github.com/0xDanielLopez/TweetFeed) | Denylist de hashes SHA-256 reportados públicamente. Se importa únicamente `type=sha256`; es inteligencia reciente y colaborativa, no un corpus histórico exhaustivo ni una confirmación por sí sola de malware. | El proyecto declara CC0-1.0. Se conservan URL, ventana, fecha, ETag, checksum del CSV y cantidad en `data/denylist/tweetfeed_meta.json`. Atribución recomendada: “IOC data from TweetFeed (CC0)”. | El proveedor refresca los datos cada 15 minutos. El importador utiliza ETag/Last-Modified; se recomienda actualizar semanalmente y no consultar más seguido que cada 15 minutos. |
| [PRX-SD Built-in](https://github.com/openprx/prx-sd-signatures) | Reglas YARA curadas de la subfuente `yara/builtin`. No se importan otras subfuentes del agregador. | La tabla del README de PRX-SD declara MIT; el repositorio agregado declara Apache-2.0. Se conservan la LICENSE Apache y el README originales, además de un aviso MIT usando la atribución `prx-sd` presente en las reglas. El upstream no aporta copyright separado para esta subfuente; revisar esta condición antes de actualizar o redistribuir. | Mensual, con revisión del diff y compilación de todas las reglas. |
| [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | Reglas YARA complementarias seleccionadas por el proyecto. | El repositorio oficial declara MIT. Conservar el aviso de copyright y el texto MIT de la fuente junto a las reglas, además del commit completo y checksums. | Mensual, con revisión del diff y compilación de todas las reglas. |
| [NIST NSRL RDS](https://www.nist.gov/itl/csd/secure-systems-and-applications/national-software-reference-library-nsrl/nsrl-download-0) | Allowlist local de software conocido; una coincidencia no demuestra que un archivo sea seguro. | No se distribuye el SQLite. NIST indica dominio público y redistribución gratuita; conservar atribución e identificar cambios. Configurar con `NSRL_DOWNLOAD_DATE=YYYY-MM-DD ./setup-data.sh /ruta/al/RDS.sqlite`; verificar el checksum de la publicación directamente contra NIST. | Instalación y actualización manual local. |

### Aclaración de licencia PRX-SD

En el commit fijado, el `LICENSE` raíz del repositorio declara Apache-2.0 y la
tabla de fuentes de su `README.md` declara MIT para `PRX-SD Built-in`. Los
archivos Built-in no contienen un aviso de copyright/licencia en su encabezado;
las reglas sí conservan el campo `author = "prx-sd"`. Por ello se conservan el
LICENSE y README Apache originales, se registra la declaración MIT específica
de la fuente y no se atribuye a terceros. La atribución de la licencia MIT usa
el nombre `prx-sd` visible en las reglas; upstream no proporciona un año ni un
aviso de copyright separado. Confirmar esta interpretación con upstream antes
de cambiar de commit o redistribuir fuera de los términos indicados.

## Importación y validación

Los comandos de importación, validación y empaquetado de esta sección son para
mantenedores y deben ejecutarse desde un checkout completo del repositorio.
El ZIP instalado omite `scripts/` y los workflows; no contiene esos comandos.

TweetFeed se descarga desde el CSV completo de la ventana elegida, sin clonar el repositorio ni guardar otros tipos de IOC:

```sh
python scripts/import-tweetfeed.py --window year
```

El CSV documentado no tiene cabecera y usa las columnas `date,user,type,value,tags,tweet_url`. El importador valida SHA-256, deduplica, registra metadatos y actualiza `data/checksums.txt`. Una respuesta HTTP 304 conserva el snapshot local solo si sus metadatos y contenido coinciden.

Para PRX-SD, descargar las dos subfuentes aprobadas desde un commit completo. El fetcher solo solicita `yara/builtin/`, `yara/reversinglabs/`, el README y la licencia; también conserva el aviso MIT oficial de ReversingLabs en su commit:

```sh
python scripts/fetch-prx-yara.py --commit <SHA_COMPLETO> \
  --destination /ruta/al/prx-sd-seleccionado
python scripts/import-prx-yara.py --source-dir /ruta/al/prx-sd-seleccionado \
  --source builtin --commit <SHA_COMPLETO>
python scripts/import-prx-yara.py --source-dir /ruta/al/prx-sd-seleccionado \
  --source reversinglabs --commit <SHA_COMPLETO>
```

El importador compila cada archivo antes de instalarlo y conserva `SOURCE.txt`, licencia del agregador, README, el aviso MIT de ReversingLabs, `data/yara_rules/META.json` y checksums. Si una regla contiene una declaración de string sin uso que el compilador rechaza, elimina solo esa declaración inerte; el SHA-256 original y la lista de eliminaciones quedan en `META.json`. Cualquier otro error de compilación detiene la importación. Nunca importar automáticamente `signature-base` (CC-BY-NC), `yara-rules` (GPL), `elastic` u otras fuentes. Si la tabla de licencias, licencia o estructura upstream cambia, detener la importación y revisar.

```sh
./scripts/check-data-coverage.sh --ci       # Fixtures sintéticos, sin red
./scripts/check-data-coverage.sh --release  # Datos reales y procedencia completos
python verificar_y_empaquetar.py --full --strict-data-coverage
```

El modo estricto exige una denylist TweetFeed con metadatos coherentes, reglas compilables de ambas fuentes YARA MIT, sus commits y conteos, y checksums completos. NSRL puede permanecer fuera del ZIP: el usuario lo instala localmente después de extraerlo. Sin NSRL, el análisis continúa con un aviso visible de cobertura reducida. El ZIP completo contiene `data/denylist/` y `data/yara_rules/`, pero excluye configuraciones locales y SQLite NSRL.

## Indicador de prueba EICAR

La regla upstream `EICAR_Test_File` se marca `severity = "test"`; el motor
la registra como `YARA_MATCH`, pero no la clasifica como una firma de malware
con severidad alta. Por eso un archivo EICAR puede mostrar `risk_level: BAJO`
(por ejemplo, score 20 cuando coinciden dos reglas de prueba) y aun así estar
detectado. EICAR es una cadena de prueba antivirus inocua, no una muestra de
malware real. `risk_level` es el nivel final de scoring; `signals_level` es
informativo y puede reflejar señales explicativas distintas.

## Avisos

`data/NOTICE` conserva licencias y atribuciones. `data/checksums.txt` identifica los archivos de datos distribuidos y se regenera después de cada importación. Al ejecutar `release.yml` manualmente sobre un tag, deja `publish_release` desactivado para generar y verificar ZIP y firmas sin publicar; actívalo solo cuando quieras crear la publicación. Un push de tag sigue el flujo automático de publicación. Ambos requieren los secretos y variables GPG del repositorio.
