# Backlog

Una línea por cosa encontrada y no arreglada, con la fase que la posee. No es
una lista de deseos: solo entra aquí lo que una pasada real encontró y decidió
no tocar, y la razón de no tocarlo. Regla de trabajo 2 de `CLAUDE.md`.

## Fase 0 — la amputación

- ~~main local (f706527, 275ecf4) no publicado; vive en pivot/agent-conformance
  hasta que la fase 5 reescriba el README.~~ **Cerrado en la 1.1b.** `main` se
  publico en avance rapido sobre `origin/main` (b61f634 era ancestro), y
  `pivot/agent-conformance` se retiro: iba por detras (635532f) y nada de lo
  que tenia falta en `main`, que lo contiene entero en su historia. `main` es
  la linea del producto. Una rama que duplica la linea principal y se queda
  atras es una rama de la que alguien parte sin darse cuenta.
- `README.md` y `README.es.md` siguen describiendo el escáner de modelos entero.
  Cada una de esas frases es también una frase de posicionamiento, y la
  autorización de la fase 0 era mecánica, así que solo se borraron los bloques
  de imagen. **Cerrado en la A**, que los reescribió enteros, y otra vez en la
  S0, que los reescribió sobre superficie, cambio y vigencia.
- Catorce líneas de cada README enuncian una cifra que ya no mide ningún
  comando, medidas contra `scripts/figures_contract.py`, que es la lista de las
  21 que sí se miden. Los dos ficheros están alineados línea a línea, así que
  los números valen para ambos. Regla de trabajo 6 de `CLAUDE.md`. **Cerrado en
  la A**; la tabla se conserva porque nombra el mecanismo, no porque siga
  abierta.

  | línea | cifra sin fuente | lo que dice |
  |---|---|---|
  | L27 | controles, obligaciones | `15 executable controls`, `21 obligations` en la tabla de cabecera |
  | L28 | conectores | `7 connectors` en la tabla de cabecera |
  | L111 | bloque de consola de `scan` | `2 artifact(s): 1 passed, 1 failed, 0 inconclusive` |
  | L137 | bloque de consola de `agent paths` | `8 open, 0 already closed` |
  | L150 | conectores | `7 connectors enumerate and stage and never conclude` |
  | L197 | controles, obligaciones | `15 executable controls over 21 obligations` |
  | L214 | nivel de comprobabilidad | fila `Machine-checkable`, columna de recuento `5` |
  | L215 | nivel de comprobabilidad | fila `Generatable`, columna de recuento `4` |
  | L216 | nivel de comprobabilidad | fila `Evidence-judged`, columna de recuento `5` |
  | L217 | nivel de comprobabilidad | fila `Organizational`, columna de recuento `7` |
  | L221 | obligaciones, reparto organizativo | `7 of the 21 obligations are organizational` |
  | L292 | gadgets desconocidos | `allowlist mode catches 11 of 11`, `denylist mode catches 1` |
  | L296 | supervivencia del marcado | `Naive pipeline: 0 of 32. Metadata-aware pipeline: 8 of 8` |
  | L298 | corpus, objetivos de fuzz | `64 corpus artifacts`, `9 fuzz targets` |

  Otras catorce cifras de esas mismas páginas SÍ tienen comando y no entran
  aquí, una por cada figura del contrato que aparece en la página: `version`,
  `tests`, `lines`, `rules`, `coverage_states`, `capability_rules`,
  `watch_states`, `evidence_states`, `relations`, `predicates`,
  `subject_kinds`, `surfaces`, `commands` y `design_notes`.
  `readme_figures_are_current` pasa por esas catorce, no por las catorce de
  arriba: la comprobación solo mira las cifras que el contrato declara, así que
  su verde no dice nada sobre la tabla. **Cerrado en la A**: ninguna de las
  catorce líneas sobrevivió a la reescritura de los dos READMEs.

  Las tres cifras de este apartado se derivan, no se escriben: 14 y 14 son
  `len(tabla)` y el recuento de patrones que casan en cada página, y 21 es
  `len(scripts/figures_contract.figures())`. Decía «otras cuatro», que era
  falso por diez, en una entrada cuyo asunto es precisamente una cifra sin
  fuente. Se mide así:

  ```sh
  python -c "import sys,re;sys.path[:0]=['scripts','src'];\
  import figures_contract as fc;from pathlib import Path;\
  t=fc.figures();print(len(t));\
  print([len([f for f in t if f.patterns.get(p) and re.findall(f.patterns[p],\
  Path(p).read_text(encoding='utf-8'))]) for p in ('README.md','README.es.md')])"
  ```

- `CONTRIBUTING.md` y `docs/ENGINEERING.md` nombran `make diagrams`, `make
  screenshots` y `docs/img/`, que ya no existen. **Recomprobado en la S3 y
  reasignado con motivo**: `grep -n 'make diagrams\|make screenshots'
  CONTRIBUTING.md docs/ENGINEERING.md` devuelve dos líneas, las dos en
  `docs/ENGINEERING.md:23-24`, y el `Makefile` no tiene ninguno de los dos
  objetivos. La premisa de la reasignación a la S3 resultó falsa: el informe HTML
  no es una imagen de `docs/img/`, es un fichero que el usuario pide con `--html`
  y que no se genera en el repositorio ni se commitea, así que la S3 no devuelve
  ninguna imagen que generar y no hay objetivo que restaurar. Lo que hay que
  hacer es borrar las dos líneas, y eso es un fichero de documentación que esta
  fase no abre. **Sin fase**, hasta que algo vuelva a dibujar.
- `docs/GOVERNANCE.md`, `docs/FORMATS.md`, `docs/EVALUATION.md` y
  `docs/CONCEPTS*.md` documentan módulos archivados. `docs/COMPATIBILITY.md`
  promete que un contrato publicado sigue publicado, y 3.0.0 retira diez.
  **Cerrado entre la A y la A.1**: `GOVERNANCE.md` se reescribió, los otros tres
  pasaron a `docs/archive/` con su cabecera, y `COMPATIBILITY.md` documenta la
  retirada. Lo que sigue abierto de `COMPATIBILITY.md` está en la sección de la
  fase S0, más abajo, y es otra cosa.
- `conformance/model.py` declara `SCHEMA_VERSION = "agent-bom/v2"` y ese esquema
  ya no se publica: el módulo emite un documento contra un contrato que no está
  en `schemas/`. **Cerrado por desaparición**: `conformance/` se fue entero a
  `archive/model-scanner` en la 3.0.0, y el producto que lo iba a necesitar sale
  del plan en la S0. Reproducción: `ls src/actaira/conformance` no existe.
- `statecli._record_manifest` grababa un manifiesto de sujetos en el grafo de
  estado. Se fue con `statecli.py`, y `manifest.py` y `state/` se fueron después
  con la fase A. `actaira contract`, que era quien tenía que traerla de vuelta,
  sale del plan en la S0. Si vuelve, vuelve con la vigencia y su sujeto es una
  superficie, no un artefacto. **Fase P1.**
- Tres tests de `test_state_graph.py` que cubrían esa función se borraron con
  ella, y con ellos la única cobertura de las aristas de pertenencia grabadas
  desde un manifiesto. Vuelven con `state/` o no vuelven. **Fase P1.**
- ~~DEF-115 (un recibo emitido desde un espacio de trabajo no referenciaba
  evidencia) perdió su test.~~ **Cerrada en la S3.** La forma del defecto es «un
  documento firmado que no referencia aquello sobre lo que se firmó», y
  `seal/v1` la hace imposible por construcción: `surface_sha256` es obligatorio
  en el esquema y es el digest canónico del documento `surface/v1` sellado, de
  forma que un sello sin sujeto no valida.
  `test_a_changed_surface_changes_the_digest_an_approval_is_keyed_on` lo
  ejercita por el lado que importa, que es que el digest se mueva cuando la
  superficie se mueve.
- `i18n` conserva 41 ids de regla del escáner, que son los que siguen citados en
  `coverage.py` y en `conformance/`. **Medio cerrado**: el catálogo está vacío
  desde la fase A, y `release_check.rules_are_documented` lo exige vacío en vez
  de dejar que sus dos bucles pasen sobre nada. Lo que falta es el vocabulario
  que lo sustituye, que son los ids de `packs/core`. **Fase S1.**
- `examples/subjects.yaml` documenta en su cabecera dos comandos que ya no
  existen (`policy check --subjects`, `graph build --subjects`). **Cerrado por
  desaparición** en la fase A: `examples/` quedó vacío y se fue. Reproducción:
  `ls examples` no existe.
- `.github/actions/actaira-scan/` sigue apuntando al escáner, por orden.
  **Cerrado en la A.1**, que lo borró. Reproducción: `ls .github/actions` no
  existe. La acción de GitHub que llega en la S3 es otra y no hereda nada de
  esta.
- `.github/workflows/ci.yml` todavía puede invocar pasos de `make` que ya no
  existen. No se tocó: la puerta de la fase 0 es `make all`, no CI. **Cerrado en
  la A.1**, que lo reescribió entero: quitó los cinco trabajos que corrían
  comandos y directorios inexistentes (`eval`, `fuzz`, `benchmark`,
  `attest-self` y `figures`) y dejó escrito en la cabecera del fichero cuáles
  corren y cuáles no, con su motivo. Corre en cada push a `main` y en cada pull
  request. **La S0 reasignó esta línea a S3 sin volver a comprobarla**, que es
  el defecto que el backlog existe para no cometer: una línea heredada se
  reasigna o se cierra, y cerrarla exige mirar.
- `figures.json` registra `git.head` del momento en que se generó, y commitearlo
  cambia el head, así que siempre va un commit por detrás (572f86f registra
  6cec2ec). `release-check` lo tolera por diseño. No se puede arreglar dentro del
  propio fichero: es el problema del punto fijo, el mismo que resuelven los
  árboles de Merkle anclando la constancia fuera del objeto. El ensayo de la
  fase 4.5A, que era su destino, no existe en el plan v3. **Sin fase**: es una
  propiedad conocida y tolerada por diseño, no trabajo pendiente.

## Fase 1 — leer y grabar la traza

- `actaira.mcp.serve` descarta en silencio una línea de stdin que no es JSON, en
  vez de responder el error de análisis `-32700` que manda JSON-RPC. El cliente
  que la envió se queda esperando una respuesta que no llega. No es un
  fail-open de la evidencia (el servidor no afirma nada sobre esa línea), pero
  sí un cliente colgado. **Sin fase asignada.**
- `ClaudeCodeReader._lines` lee con `errors="replace"`, así que un transcript
  con bytes que no son UTF-8 produce digests de un texto alterado sin que la
  traza lo diga. Hoy no se ha visto ninguno: los 420 ficheros de la máquina
  donde se escribió esto se leen limpios. Cuando aparezca uno, el reemplazo
  tiene que ser un hueco declarado y no una sustitución muda. **Sin fase.**
- `actaira scan --out` nombra cada fichero por el `session_id` que declara el
  transcript. Dos sesiones de proyectos distintos que declaren el mismo id se
  pisarían una a otra sin decir nada. No se ha observado; el arreglo es refusar
  el segundo o nombrar por ruta, y las dos opciones cambian el nombre publicado
  del fichero, que es lo que hace que esto no sea un arreglo de una línea.
  **Sin fase.**
- `scripts/build_package.py` sigue exigiendo `actaira/web/static/index.html`,
  `actaira/agents/cassettes/judged-gold.json` y `actaira/schemas/report-v1.json`,
  que se fueron a `archive/model-scanner` en la 3.0.0. **Recomprobado en la S3 y
  NO cerrado, con motivo.** La premisa de la reasignación era que la S3 sería la
  primera fase que publica algo que instala un tercero, y lo es; lo que resultó
  no ser cierto es que ese algo pase por aquí. La acción de GitHub instala con
  `pip install <action_path>`, el trabajo `package` de CI construye con
  `python -m build`, y `make package` no está en `make all` ni en CI, así que
  nada de lo que la S3 publica depende de este fichero. Arreglarlo son cinco
  líneas y es un fichero de diseño que el presupuesto de esta fase no nombra, y
  gastarlo aquí a cambio de nada habría sido alcance por comodidad.
  Reproducción: `grep -n 'web/static' scripts/build_package.py`. **Fase S4.**

## Fase 1.1b — la sesión que el protocolo ya no tiene

- Las cuatro puertas de forma de `proxy/protocol.py` (`_SOFTWARE_NAME`,
  `_TRACEPARENT`, `_REVISION`, `_REQUEST_STATE`) DESCARTAN un valor que no casa,
  y el campo queda `null`. Un lector no puede distinguir «el servidor no declaró
  nada» de «declaró algo que este lector no publica». Es la tercera negativa en
  pequeño: lo no publicado se declara, no se calla. El arreglo es una razón de
  hueco nueva por campo descartado, y eso es vocabulario nuevo, que la regla 2
  prohíbe sacar en la pasada adversarial. **Sin fase.**
- `discover_unavailable` hace incompleta toda sesión con un servidor que el
  agente no llegó a usar, porque nadie le preguntó su inventario. Es correcto y
  es ruidoso: la mayoría de las configuraciones traen servidores que una sesión
  concreta no toca. Puede que el hueco deba ser por servidor observado y no por
  servidor configurado. El derivador de contrato, que era quien iba a arbitrar
  esto, sale del plan en la S0. El árbitro nuevo es `check`, que lee del disco
  qué servidores MCP hay configurados y no necesita preguntárselo a nadie.
  **Fase S1.**
- `actaira scan` sin `--out` no tiene dónde guardar la sal, así que un hueco
  sobre un fichero ilegible no nombra referencia ninguna. El operador que
  diagnostica desde la terminal pierde saber cuál de sus ficheros falló. El
  arreglo obvio —imprimir la sal— la convierte en pública y deshace la D-263.
  **Sin fase.**
- `trace/v2` sale sin entrada propia en `CHANGELOG.md`: la versión del paquete
  sigue siendo 3.0.0 y su entrada ya está escrita, así que la nota pertenece a
  la subida de versión siguiente, no a una edición de una entrada publicada.
  El `schemas/__init__.py` dice que ensanchar un enum cerrado es nota de
  CHANGELOG, y esto lo es. **Fase S3**, que es la primera que sube versión
  porque es la primera que publica algo nuevo que un tercero instala.
- El guardián de red tapa seis puertas de `socket`. No tapa `ssl.SSLSocket`
  creado sobre un descriptor ya conectado, ni `os.system`, ni un subproceso: el
  agente de prueba de `test_proxy_http_interposition.py` es un subproceso y sale
  del guardián por definición. Va a loopback y se puede leer, pero la propiedad
  «la suite no sale de la máquina» es más débil de lo que su nombre sugiere.
  **Sin fase.**

## Fase 1.1c — la procedencia como invariante

- `traceparent` viaja en claro (ver `trace/provenance.py`). Su forma es hex de
  longitud fija, asi que no puede llevar una frase, pero el trace-id son
  dieciseis bytes que el cliente elige: un cliente que quiera codificar algo ahi
  puede. Se acepta porque su unico uso es cruzar el acta con las trazas
  OpenTelemetry que el propio operador ya emite, y una referencia de la que
  nadie mas tiene el mapa no cruza con nada. **Sin fase.**
- `actaira scan` sin `--out` no tiene donde guardar la sal, asi que el lector
  mintea una por ejecucion y dos ejecuciones sobre las mismas sesiones producen
  referencias distintas. Con `--out` la sal se conserva en `index.json` y los
  bytes son estables. Quien capture `--json` sin `--out` no obtiene un documento
  reproducible. **Sin fase.**
- El mapa de referencias del lado del operador vive en tres sitios segun el
  camino: `interposition.json` (alias y sesion), `<servidor>.refs.json` (lo que
  grabo cada proxy) e `index.json` (lo que leyo `scan`). Son tres porque tres
  procesos distintos los escriben y fundirlos exigiria que alguien escriba
  despues de que todos hayan terminado. Un solo `actaira resolve` que los lea
  los tres seria mejor que tres formatos que el operador tiene que conocer, y
  seria un octavo comando. La lista de la S0 tiene siete de ocho, asi que ya
  cabe sin quitar nada, y eso lo convierte de imposible en una decision.
  **Fase S4**, que es la que junta el ambito de maquina con las sesiones que
  corrieron despues, y por tanto la que tiene los tres mapas delante a la vez.
- `trace/v2` queda publicado y sin ningun consumidor posible: vivio un commit.
  La regla de `schemas/__init__.py` dice que un contrato publicado sigue
  publicado y que «nadie lo estaba usando» no es un argumento, asi que se queda
  en disco y legible. Si esto vuelve a pasar, la pregunta no es la regla sino
  por que un esquema se publica antes de que la fase que lo usa haya terminado.
  **Sin fase.**
- Nada en el arbol DICE que `<--out>/records/` no se publica. Ahora contiene,
  ademas de los argumentos en claro cuando se usa `--with-content`, los mapas
  `<servidor>.refs.json` que deshacen todas las referencias de la D-268. Un
  operador que empaquete `--out` entero publica lo que la sal protegia.
  **Reasignada en la S3, con motivo.** La línea daba por hecho que el
  empaquetador sería `seal` y que `seal` empaquetaría una traza. No lo hace:
  `seal` sella una SUPERFICIE, nunca lee `records/` y nunca podría encontrarlo
  dentro, así que la negativa que esta línea pedía no tiene sujeto. Lo que sí
  hizo la S3 es la mitad que sí le corresponde, en su propio terreno:
  `<--out>/index.json` de `seal` lleva una nota escrita que dice que ese fichero
  no viaja y que publicarlo deshace la redacción del paquete. La mitad de `watch`
  sigue abierta y es suya: el que tiene que decirlo es `records/`. **Sin fase**,
  hasta que haya un comando que empaquete una traza.
- El guardian de red tapa seis puertas de `socket` y su meta-test las ejercita
  una a una. Sigue sin tapar un subproceso, que es como sale el agente de prueba
  de `test_proxy_http_interposition.py`. Va a loopback y se puede leer, pero la
  propiedad «la suite no sale de la maquina» es mas debil de lo que su nombre
  sugiere. **Sin fase.**

## Fase A — la verdad y la amputación

Cerrado en esta fase y anotado porque el backlog lo pedía: los dos READMEs se
reescribieron enteros y ya no enuncian ninguna cifra sin fuente. Las catorce
líneas de la tabla de arriba y la entrada de «README describe el escáner» dejan
de estar abiertas.

### Funciones muertas dentro de módulos vivos

La regla de alcanzabilidad se aplica a nivel de módulo, así que estas no
bloquearon la fase. Cada una está en un fichero que un comando sí alcanza.

- `model.Severity`, `model.Verdict` y `model.Finding` no los usa nada en `src/`.
  Son la forma contra la que se escribe S1 (los paquetes de reglas levantan un
  `Finding`), y por eso se conservan en vez de borrarse, pero a día
  de hoy están presentes y sin usar. Reproducción:
  `grep -rn 'Severity\|Verdict\|Finding' src/ | grep -v src/actaira/model.py`
  no devuelve nada. **Fase S1**, que es cuando pasan a tener llamante o a irse:
  `Finding` es la forma natural del hallazgo citado y `check` la usa o la
  sustituye. `Verdict` es vocabulario de conformidad y es el que peor lo tiene.
- `attest/timestamp.py` (1.129 líneas) es el módulo vivo más grande del árbol y
  solo se entra en él desde `verify`, para comprobar un token RFC 3161 que casi
  ningún paquete lleva. No está medido cuánto de él alcanza `verify` de verdad.
  Merece la misma medición a nivel de función que se le hizo a `dsse.py`.
  **Sin fase asignada.**

### Documentación que sigue describiendo el escáner

La fase A reescribió `README.md`, `README.es.md`, `docs/COMPATIBILITY.md` y
`docs/GOVERNANCE.md`, que eran los cuatro que el alcance nombraba. Estos otros
siguen describiendo un producto que este árbol no puede entregar. Ninguna
puerta los lee, así que nada falla: esa es exactamente la razón por la que
llevan seis meses mintiendo.

- `docs/FORMATS.md` describe la lectura de pickle, ONNX, HDF5, GGUF y
  safetensors, y la tabla completa de reglas `ACT-*`. Nada de eso existe aquí.
  Reproducción: `grep -c 'pickle' docs/FORMATS.md`. Candidato a borrarse entero,
  como se borró `docs/CLI-OUTPUT.md` en esta fase.
- `docs/EVALUATION.md` describe un corpus y un harness que viven en
  `archive/model-scanner`.
- `docs/ARCHITECTURE.md` dibuja un árbol de directorios con `formats/`,
  `conformance/`, `policy/` y `state/`.
- `docs/THREAT-MODEL.md` y `docs/CONCEPTS.md` / `CONCEPTS.es.md` están a medias:
  las dos páginas de conceptos sí nombran los cuatro comandos (la puerta lo
  comprueba), y alrededor describen el escáner.
- `docs/DESIGN.md` conserva las secciones 2 a 9, que argumentan el escáner. Se
  dejaron a propósito: son el historial de diseño de código que existió y la
  sección 10 dice dónde recuperarlo. Lo que no debe pasar es que un lector las
  tome por una descripción del árbol de hoy.

**Cerrado en la A.1.** Los seis pasaron a `docs/archive/` sin editarlos, con una
cabecera que dice que describen el producto retirado, y las secciones 2, 5, 6, 7,
8 y 9 de `DESIGN.md` con ellos. No se reescribieron: un documento que argumenta
una decisión vale más que un resumen de esa decisión, y el siguiente que escriba
un lector de artefactos debería poder leer por qué este se hizo así.

### Otros

- `docs/defects.json` perdió 27 pines de test en esta fase: los tests que los
  sujetaban se fueron con los módulos que cubrían. Cada uno pasó a `pinned_note`
  siguiendo la regla que el propio fichero ya usaba para el escáner. Un defecto
  sujetado por una nota está peor sujetado que uno sujetado por un test, y la
  cifra de `docs/ENGINEERING.md` lo refleja ahora.
- `examples/` quedó vacío: sus dos ficheros los leían `conformance/` y
  `policy/`. Si la **fase S1** necesita un ejemplo, es una configuración de
  fixture y no una declaración, y llega bajo la regla de código nueva: real o
  reconstruida de un informe publicado, citada, y con el script inerte.

## Fase A.1 — lo que la medición de alcanzabilidad no mide

- ~~**`test_reachability` mide módulos, no si la cadena del producto se cierra.**~~
  **Cerrada en la S3.** `actaira seal` es el productor: escribe un paquete con un
  documento `seal/v1` dentro, y `verify` lo verifica y además NOMBRA el contrato
  que acaba de verificar en vez de comprobar bytes y no decir nada de ellos. La
  comprobación que la línea pedía - «para cada formato que este árbol verifica,
  existe un comando que lo produce» - ya no es retórica y la sostiene
  `tests/test_seal_and_report.py::test_a_seal_verifies_offline_and_names_the_contract_it_carries`.
  Reproducción del cierre: `grep -rn 'write_package' src/ | grep -v 'def '`
  devuelve ahora la llamada de `attest/seal.py`. El texto original queda debajo.

  ORIGINAL:
  Pregunta si todo módulo es alcanzable desde un comando. `attest/` lo es:
  `verify` entra en `package.py`, `merkle.py`, `chain.py`, `trust.py`,
  `timestamp.py` y `keyring.py`. Lo que no pregunta es si algo que esta
  herramienta ESCRIBE es algo que esta herramienta puede VERIFICAR, y hoy no lo
  es: `attest/package.py::write_package` es el único escritor de paquetes y no
  lo llama nada fuera de `tests/`. Reproducción:

      grep -rn 'write_package' src/ | grep -v 'def write_package'

  devuelve solo una mención en un comentario de `keyring.py`. Es decir: la 3.0
  tiene un verificador de paquetes y ningún productor de paquetes. Eso no es un
  defecto del código, es una fase sin terminar, pero la puerta no lo dice y el
  README sí tiene que decirlo (y lo dice). La comprobación que faltaría es de
  otra clase que la de alcanzabilidad: «para cada formato que este árbol
  verifica, existe un comando que lo produce». **Fase S3**, que es cuando
  `seal` escribe una línea base firmada y la pregunta deja de ser retórica.

- **`.pre-commit-hooks.yaml` publica dos hooks que no pueden ejecutarse.** Ambos
  llaman `actaira scan --fail-on high` sobre ficheros `.pkl`, `.onnx`, `.h5` y
  compañía. Ni `--fail-on` ni el código de salida 3 existen desde la 3.0, y
  `scan` ya no lee artefactos: lee sesiones de agentes. Es exactamente el mismo
  defecto que tenía `.github/actions/actaira-scan`, que la A.1 borró.
  Reproducción: `actaira scan --fail-on high` sale con código 2. No se borró en
  la A.1 porque el alcance nombraba la acción de GitHub y no este fichero, y
  decidir por mi cuenta qué integraciones publica el proyecto no me toca.
  **Cerrado en la S0**, con esa decisión tomada: el fichero se borró. La
  entrada de la fase S0, más abajo, dice cómo.

- **`docs/CONTRACTS.md` y `docs/FIGURES.md` se generan, y nadie comprueba que
  los enlaces internos de los documentos archivados sigan resolviendo.** Los
  seis de `docs/archive/` se movieron con sus enlaces relativos intactos, así
  que un `[x](CONCEPTS.md)` dentro de `archive/FORMATS.md` sigue funcionando
  porque los dos se movieron juntos, pero un enlace de un archivado a algo que
  se quedó en `docs/` (o al revés) no lo comprueba nada.
  `tests/test_readme_parity.py::test_every_repository_link_resolves` solo mira
  los dos READMEs. **Sin fase asignada.**

- **`make all` falla en la primera pasada después de tocar código, y pasa en la
  segunda.** El orden es `lint test figures release-check`, y `make test`
  incluye `tests/test_release_check.py::test_the_gate_passes_on_this_repository`,
  que corre la puerta sobre una copia del árbol. Si `figures.json` está sin
  remedir (o sea, siempre que se haya editado un fichero .py desde el último
  `make figures`), esa comprobación falla dentro de `make test`, antes de que
  `make figures` la habría arreglado. Reproducción: toca cualquier test, corre
  `make all` (rojo), córrelo otra vez (verde). Es la forma de D-181: una puerta
  cuyo remedio es acordarse de correr otra cosa primero es una puerta que se
  rodea. Lo obvio sería `all: lint figures test release-check`, pero eso hace
  que `make all` escriba en el árbol antes de comprobarlo, que es peor por otro
  motivo. Merece una decisión, no un reordenamiento a ciegas.
  **Sin fase asignada.**

## Fase S0 — lo que sigue vendiendo el producto anterior

La pasada adversarial de la S0 (regla de trabajo 2) barrió el árbol entero
fuera de `docs/archive/` y de `CHANGELOG.md` buscando frases que presenten el
producto viejo como objetivo vigente. Encontró siete cosas, y una segunda
pasada, pedida con un criterio más estrecho (¿hace que un fichero PUBLICADO
diga algo falso sobre el estado actual?), encontró dos más que la primera
perdió por barrer frases de posicionamiento en vez de referencias al corpus.

Siete de las nueve se arreglaron en una ampliación de presupuesto autorizada en
la propia fase. Las dos que quedan abiertas no cumplen ese criterio: no son
documentos publicados, son comentarios y docstrings.

### Arregladas en la S0

Se dejan escritas porque cada una dice algo sobre por qué ninguna puerta las
cogió, y esa parte sigue siendo verdad.

- `CITATION.cff` describía el escáner de modelos entero, con protocolos pickle,
  ONNX y GGUF. **La puerta lee de ese fichero la versión y la licencia, no el
  resumen**, que es exactamente por qué llevaba dos fases mintiendo en el
  fichero por el que cita este trabajo quien lo cite.
- El `Dockerfile` imprimía «An independent witness for AI agents» en
  `org.opencontainers.image.description` de cada imagen construida. Ninguna
  comprobación lee esa etiqueta.
- `docs/COMPATIBILITY.md` nombraba `contract`, `verdict`, `receipt` y `fix`
  como los comandos que faltaban. **`readme_documents_the_commands` solo
  comprueba que los que SÍ existen estén nombrados**, nunca que los que faltan
  sean los de verdad, así que la página podía nombrar cuatro comandos
  imaginarios indefinidamente. Ahora nombra los tres que faltan y los cuatro
  retirados en pasado, con el motivo por el que un nombre retirado merece una
  línea: alguien lo tecleará.
- `docs/ENGINEERING.md` decía que las notas de diseño viven en los módulos que
  argumentan. Ahora dice la regla entera, que tiene dos ramas y es estrecha en
  la segunda: una decisión sobre CÓMO se construye algo la implementa el
  módulo; una decisión de doctrina, sobre QUÉ se construye, la implementa
  `CLAUDE.md`, y nada más puede apuntar ahí. `docs/DESIGN.md` §11.3 la
  argumenta y D-269 es la única fila de la segunda clase.
- `src/actaira/mcp.py` anunciaba en `tools/list` dos herramientas del producto
  retirado. Ya no las anuncia. Se comprobó antes de tocarlas que ninguna hacía
  nada: las dos caían en `_unbuilt`, que devolvía una constante. La D-256
  cambia de respuesta y se reescribe con el cambio: una herramienta se anuncia
  solo si se ejecuta, porque un nombre en `tools/list` lo lee un agente como
  capacidad y nada posterior deshace esa lectura.
- `SECURITY.md` tenía una sección entera, «This repository contains malicious
  model artifacts», sobre `evals/corpus/build.py` escribiendo gadget pickles
  funcionales en `evals/artifacts/`. `evals/` no existe desde la fase A, así
  que el documento decía que este repositorio genera malware cuando no lo hace,
  y contradecía la regla de código que la propia S0 escribió. Recortado a lo
  que es verdad: cómo reportar, qué versiones tienen soporte, y qué hay en el
  árbol. **La tabla de versiones soportadas decía 2.2.x** para un paquete
  3.0.0, y eso estaba en una de las dos secciones que se conservan.
- `CONTRIBUTING.md`, que la primera pasada perdió, tenía «Never commit an
  artifact from the corpus» sobre tres directorios que no existen, un bloque de
  `make` con seis objetivos que el `Makefile` no tiene, y un extra `dev` con
  dos dependencias de menos. Recortado igual, sin escribir nada nuevo.
- `.pre-commit-hooks.yaml` publicaba dos hooks que no podían ejecutarse
  (`actaira scan --fail-on high` sobre `.pkl`, `.onnx`, `.h5`). Lo encontró la
  A.1 y no lo borró porque decidir qué integraciones publica el proyecto no le
  tocaba. Borrado. `release_check` ya toleraba su ausencia (`if not
  path.is_file(): continue`), así que el recuento de pines pasa de 1 a 0 sin
  que nada se rompa, que es la misma forma que tuvo borrar
  `.github/actions/actaira-scan`.

### Siguen abiertas

- **«phase B» y «phase 2» sobreviven en cinco ficheros de código y de puerta.**
  `src/actaira/model.py` (dos veces), `src/actaira/trace/redact.py`,
  `scripts/release_check.py`, `tests/test_i18n.py` (dos veces) y
  `tests/test_no_aggregate.py`. Todas quieren decir S1, que es la fase que trae
  los paquetes de reglas. No entran en el criterio de arreglo de la S0: son
  comentarios y docstrings, no documentos publicados, y ningún lector del
  producto los ve. Reproducción: `grep -rn 'phase B\|phase 2' src/ scripts/
  tests/`. `tests/test_cli.py` y `src/actaira/mcp.py` estaban en esta lista y
  salieron al arreglarse en la S0. **Fase S1**, con la fase que las vuelve
  verdad en vez de reescribirlas dos veces.

- **`MANIFEST.in` excluye `.pre-commit-hooks.yaml`, que ya no existe.** Un
  `exclude` sobre un fichero ausente es un aviso de setuptools, no un error, y
  `make package` no está en `make all`. Es la misma línea de trabajo que
  `scripts/build_package.py`, que exige tres ficheros archivados. Se arreglan
  juntos. **Fase S3.**

- **El modelo de amenazas de la entrada nueva no está escrito.** `SECURITY.md`
  lo dice en su cabecera en vez de anticiparlo: la S1 lee ficheros de
  configuración de repositorios que escribió otro, que es entrada controlada
  por el atacante en el sentido más literal, y eso merece un modelo de amenazas
  contra el código que lo lee y no contra el que se piensa escribir. **Fase
  S1**, y está en su puerta.

## Fase S1 — lo que `check` deja abierto

### Cerradas en esta fase, comprobadas contra el árbol

- **«phase B» y «phase 2» en cinco ficheros.** Resueltas. `src/actaira/model.py`
  (dos veces) se reescribió al reutilizar `Finding` y borrar `Severity` y
  `Verdict`; `tests/test_i18n.py` y `tests/test_no_aggregate.py` se repuntaron a
  la S1 y a los paquetes de reglas; `src/actaira/trace/redact.py` dice ahora qué
  necesita una regla, sin fase. Queda UNA mención viva y es deliberada:
  `scripts/release_check.py` CITA entre comillas el docstring viejo que se
  sustituyó, porque el argumento de por qué el check estaba abierto es lo que
  explica por qué ya no lo está. Reproducción: `grep -rn 'phase B\|phase 2' src/
  scripts/ tests/ --include='*.py'` devuelve esa sola línea.
- **`i18n` sin vocabulario que sustituyera a los 41 ids del escáner.** Cerrada:
  `packs/core` define 15, los dos catálogos los llevan, y
  `release_check.rules_are_documented` ya no exige el catálogo vacío sino que lo
  compara contra los paquetes y contra `docs/RULES.md`.
- **`model.Severity`, `model.Verdict` y `model.Finding` sin llamante.** Cerrada.
  `Finding` lo tiene: `surface/rules.py` levanta uno por regla que dispara, con
  `rule_version`, `author` y `pack` nuevos para que la severidad viaje
  atribuida. `Severity` y `Verdict` se borraron, cada uno con su porqué escrito
  en el propio `model.py`.
- **`discover_unavailable` marca incompleta una sesión por servidor configurado
  y no por servidor observado.** Cerrada en cuanto al árbitro: `check` lee del
  disco qué servidores MCP hay configurados y no necesita preguntárselo a la
  sesión. Lo que NO se ha hecho es cambiar `proxy/session.py` para usarlo; eso
  es trabajo de `proxy/`, que está aparcado, y se reabre abajo con su fase.
- **El modelo de amenazas de la entrada nueva.** Escrito en `SECURITY.md`, con
  diez defensas y el test que sujeta cada una.

### Abiertas, con su fase

- ~~**`check` no está expuesto por el servidor MCP.**~~ **Cerrada en la S2.**
  `actaira_check` está en `TOOLS` y llama a `cli.check_document`, que es la
  misma función que imprime el comando: una segunda implementación detrás de la
  herramienta sería un segundo sitio donde se calcula la respuesta y el que se
  queda viejo sin que nadie lo note. No expone `--with-content` ni `--machine`,
  y el porqué está escrito en `_check` (D-289): el primero mete literales en un
  documento que lee el agente de otro, y el segundo lee el directorio personal
  del desarrollador. Llega ahora y no en la S1 por la razón que la línea decía:
  una herramienta que leyera un solo fabricante habría anunciado «la superficie
  de configuración» y devuelto un sexto de ella, y `tools/list` es la única
  superficie donde una lectura que ya ocurrió no se corrige más abajo.
  Reproducción: `test_check_over_mcp_answers_with_the_same_document_the_command_builds`.
- **Tres de las quince reglas no tienen caso violador REAL. Cerrada como
  desviación, no como deuda.** CLAUDE.md tiene desde esta fase una tercera rama
  estrecha que la admite, y las tres la cumplen: ACT-S013 y ACT-S014 comparan
  contra una política gestionada, que vive en una ruta del sistema operativo
  fuera de todo repositorio, así que ninguna búsqueda encontrará jamás una
  muestra pública; ACT-S002 registra siete búsquedas del 17-sep-2026 que
  devolvieron 67 configuraciones públicas entre todas y ni un solo hook `http`.
  La marca está en el propio paquete de reglas, se publica en la fila y en la
  entrada de `docs/RULES.md`, el cargador rechaza una marca sin cita ni
  búsqueda, y `test_a_mark_with_no_evidence_is_refused_at_load` comprueba que el
  rechazo muerde. **Sin fase**: ACT-S002 se desmarca sola el día que una de esas
  búsquedas devuelva un caso, y el guion de corpus ya las sabe correr. ACT-S013
  y ACT-S014 no se desmarcan nunca, por construcción.
- **La versión del agente solo entra por `--agent-version`.** D-277 explica por
  qué no se ejecuta `claude --version` ni se lee de `~/.claude.json`. Queda sin
  resolver si en modo `--machine` merece leerse de disco CON la salvedad de L0
  escrita al lado, que es lo que hace `scan` con un transcript. **Fase S4**, que
  es la del modo máquina.
- **`referenced_path` es una heurística y lo dice.** Reconoce un token con
  forma de ruta y devuelve `None` cuando no reconoce ninguno, con lo que la
  regla que quería un objetivo sale INDETERMINADA. Un comando como
  `sh -c "$(curl ...)"` no nombra ninguna ruta y por tanto no produce hechos
  sobre un objetivo. **Sin fase**: arreglarlo bien es escribir un shell, que es
  exactamente lo que D-272 rechaza.
- ~~**El frontmatter de skills y subagentes no se lee.**~~ **Cerrada en la S2.**
  `surface/miniyaml.py` lee el subconjunto que usan esos ficheros - mapas,
  listas, flujos en línea, escalares planos y entrecomillados, comentarios - y
  RECHAZA POR SU NOMBRE todo lo demás: anclas, alias, etiquetas, escalares de
  bloque, claves complejas y flujos multidocumento. Sin dependencia nueva. El
  hueco no se cierra, se estrecha y cambia de causa: lo INDETERMINADO ya no es
  «no hay lector» sino «este bloque usa una construcción fuera del subconjunto»,
  con la construcción nombrada, que es una causa sobre la que alguien puede
  actuar. No lee los booleanos de YAML 1.1 a propósito (`NO` es la cadena `NO`,
  no `False`), y el porqué está en D-281.
- **`enabledPlugins` solo se resuelve si el plugin está descargado en el árbol.**
  Lo que viene de un marketplace remoto sale INDETERMINADO. Es correcto y es la
  causa de gap más frecuente del corpus (8 de 20 configuraciones). Puede que
  merezca agruparse por marketplace en la consola en vez de una línea por
  plugin. **Sin fase.**
- ~~**`MANIFEST.in` excluye `.pre-commit-hooks.yaml`, que ya no existe.**~~
  **Cerrada en la S3**, y cerrada por los dos lados: el fichero existe otra vez,
  así que la línea vuelve a ser verdad en vez de ser solo silenciosa, y al lado
  se excluye `action.yml` por el mismo motivo. Los dos son manifiestos de
  integración que se leen de un checkout de git: ni `pre-commit` ni GitHub
  Actions miran nunca dentro de una rueda. Reproducción: `python -m build` no
  avisa de ninguna exclusión sin fichero.

### Abiertas de la fase S2

- ~~**Los README publicaban «No existe» de una afirmación que S1 ya había
  construido, y ninguna comprobación lo vio.**~~ **Cerrada en la S3**, y cerrada
  por el hueco y no por la instancia. `readme_claims_resolve_against_the_tree`
  lee la línea `Commands:` de cada bloque de afirmación y la resuelve contra el
  parser EN LOS DOS SENTIDOS: un bloque que dice «construido» nombrando un
  comando que nadie escribió rompe la puerta, y un comando que existe sin que
  ningún bloque lo reclame la rompe igual. El criterio que lo hace posible es el
  que pedía la línea: lo que no se puede comprobar mecánicamente no se afirma,
  así que un bloque sin `Commands:` se rechaza por no ser resoluble en vez de
  aceptarse por ser prosa bonita.

  Con ella llegaron tres más, que son las otras dos cosas que un README afirma:
  `documented_flags_exist` (todo flag que la documentación enseña al lado de un
  comando es una opción que ese comando tiene, leído también de
  `.pre-commit-hooks.yaml`), `exit_codes_are_the_published_ones` (la tabla de
  `COMPATIBILITY.md` es exactamente el conjunto que el CLI define, con el 141
  obligatoriamente FUERA de la tabla y nombrado en la prosa) y
  `package_metadata_names_real_commands` (la descripción de `pyproject.toml`,
  que llevaba dos fases nombrando cuatro comandos sobre un árbol de cinco).

  Seis defectos plantados en `tests/test_release_check.py` exigen que cada forma
  se rechace. Reproducción del cierre: cambiar en `README.md` el bloque
  `> **Built.** Commands: \`actaira diff\`, \`actaira seal\`.` por
  `> **Does not exist.** Commands: none.` y correr `make release-check`.
- **`docs/RULES.md` no dice qué capacidad emite cada regla ni en qué fichero
  vive.** Publica el nombre de la capacidad, que es nuestro vocabulario; un
  lector que quiera saber qué fichero suyo la produce tiene que leer el lector.
  **Sin fase.**
- ~~**Gemini CLI publica `mcpServers.<nombre>.trust` y también
  `general.defaultApprovalMode`, y solo la primera tiene regla.**~~ **Cerrada en
  la S2**, autorizada en conversación. Es **ACT-S031**, con caso violador real:
  65 `.gemini/settings.json` públicos analizados el 18-sep-2026, 43 con un modo
  de aprobación distinto del por defecto. El hecho cambió de nombre y de
  significado al escribirla: era `stops_asking = mode != "default"`, que contaba
  `plan` como un relajamiento cuando la referencia lo llama modo de solo
  lectura, o sea un ENDURECIMIENTO. Ahora es `guardrail_removed = mode ==
  "auto_edit"`, el mismo nombre de hecho que llevan las dos claves de Codex de
  ACT-S022, porque es el mismo enunciado.
- ~~**Los primitivos de disco acotados viven en `surface/claude_code.py` y los
  importan los otros seis lectores.**~~ **Cerrada en la S3.** Están en
  `surface/disk.py`, junto con `SettingsFile` y `Reading`, que tuvieron que ir
  con ellos porque `read_json` devuelve el primero y ningún lector produce algo
  que no sea el segundo. Renombrado mecánico: ni una firma cambió, ni un nombre,
  ni un comportamiento. La nota de diseño D-271 se fue con el código que la
  implementa y ahora es D-300; las filas D-272 y D-279 apuntan al fichero nuevo.
  Se hizo en la S3 y no en la S4 porque en la S4 los lectores de ámbito de
  máquina importan lo mismo y entonces son diez y no seis. Reproducción del
  cierre: `grep -rn 'from .claude_code import' src/actaira/surface/` devuelve
  solo `STARTUP_EVENTS, VENDOR, hook_handlers` y los tres imports diferidos de
  `HANDLER_TYPES`, `COMMAND_KEYS` y `SCRIPT_SUFFIXES`, que sí son de Claude Code.
- **Las filas de la tabla de mezcla de la S1 no se pueden reproducir con ningún
  comando del árbol.** Las de la S2 sí: su `doc_sha256` es
  `curl -sL <url> | sha256sum` sobre los bytes que sirvió esa URL el
  2026-09-18, y está escrito al lado de la tabla. Las ocho de la S1 se tomaron
  con otro método que no quedó registrado, y recalcularlas hoy no las
  reproduce - lo que es esperable, porque una página cambia, pero significa que
  nadie puede distinguir «la página cambió» de «lo medimos de otra forma». No se
  tocan: reescribirlas con la fecha de hoy sería fechar de nuevo una lectura que
  no se hizo hoy. Se vuelven a tomar, con el método escrito, la próxima vez que
  se revise esa documentación. **Sin fase.**
- **`vendors_present` en `scripts/surface_corpus.py` lista las rutas de cada
  fabricante por segunda vez.** La primera está en cada lector. Un fabricante
  nuevo hay que añadirlo en los dos sitios y nada avisa si se olvida el segundo:
  el corpus simplemente no lo promociona. Es un guion y no el paquete, así que
  no rompe ninguna negativa. **Sin fase.**

### De la invariante de cobertura de capacidades (S2, tras la revisión)

- ~~**`hook.mcp_tool` se emitía desde la S1 y ninguna regla lo nombraba.**~~
  **Cerrada**: es **ACT-S032**, con caso violador real y abundante. No lo
  encontró nadie leyendo: lo encontró `test_capability_coverage`, que es
  exactamente para lo que se escribió.
- ~~**El nombre de una capacidad se construía con `f"hook.{kind}"`.**~~
  **Cerrada (D-290).** Un `.claude/settings.json` con `"type": "inventado"`
  producía la capacidad `hook.inventado`: el repositorio auditado eligiendo un
  nombre en el vocabulario de Actaira, y encima imposible de nombrar por
  ninguna regla. Ahora solo los tres tipos documentados dan capacidad y
  cualquier otro sale INDETERMINADO con el tipo escrito en la causa.
- ~~**El lector de Gemini no veía `toolDiscoveryCommand` ni `toolCallCommand`.**~~
  **Cerrada (D-291).** Son la grafía v1 de `tools.discoveryCommand` y
  `tools.callCommand`. Dos repositorios públicos las usan y el informe no decía
  nada de ellas, que es el único fallo que un lector de configuración no puede
  tener. Se leen, y salen INDETERMINADAS: el esquema actual publica solo la
  grafía anidada, y si esta versión de Gemini sigue migrando la plana no está
  publicado en ningún sitio que hayamos encontrado. Afirmar que se ejecuta
  inventa la migración; afirmar que no, inventa su retirada.
- **`gemini-cli helper.command` no tiene regla, y está en
  `EMITTED_WITHOUT_A_RULE` con su motivo.** `tools.discoveryCommand` y
  `tools.callCommand` sí ejecutan un comando desde un fichero de proyecto que se
  impone sobre el del usuario, así que la regla estaría justificada. No existe
  caso violador real: cinco búsquedas registradas del 18-sep-2026 analizaron 56
  ficheros públicos distintos y ninguno fija ninguna de las dos en la grafía
  vigente. Escribir la regla contra un fixture nuestro probaría que sabemos
  escribir el fixture. **Sin fase**: la regla llega el día que aparezca un caso,
  y el guion de corpus ya sabe buscarlo.

### De la pasada adversarial de la S1

- **Con `--lang es`, la `condition` de una capacidad y la `remediation` de una
  regla salen en inglés.** El texto de la regla sí está traducido; esos dos
  campos no. La `remediation` es correcto que no lo esté: la escribe el autor
  del paquete de reglas y traducirla sería reescribir lo que otro dijo, que es
  la segunda negativa. La `condition` es otra cosa: la genera el resolvedor de
  Actaira, así que es texto nuestro sin entrada de catálogo. Arreglarlo bien
  exige convertir cada condición en una clave con parámetros, lo que toca
  `resolve.py` entero. **Sin fase**, y no es alcance de la S1: la pasada
  adversarial solo puede producir un arreglo o una línea aquí.
- ~~**Los hechos de un script al que apunta el hook de un PLUGIN no se
  calculan.**~~ **Cerrada en la S2.** El recorrido que rellena `Reading.scripts`
  pasa ahora por `settings` Y por `mcp_files`, que es donde acababa el
  `hooks/hooks.json` de un plugin descargado, y se corre otra vez después de que
  se hayan añadido los ficheros de plugin y los bloques de frontmatter - un
  segundo paso explícito en vez de una regla de orden que alguien tiene que
  recordar. ACT-S003, ACT-S004 y ACT-S005 responden sobre un hook de plugin en
  vez de salir INDETERMINADAS sobre un objetivo que llevaba todo el rato en
  disco. Reproducción:
  `test_a_plugin_hooks_script_gets_the_same_four_facts_as_any_other`.

### Para el estudio del lanzamiento

- **`task.allowAutomaticTasks` es de ámbito de APLICACIÓN, y eso tiene dos caras
  que el estudio tiene que dar juntas.** Material de la fase de lanzamiento,
  sección 7 del plan maestro, junto al hallazgo de la S1 sobre los hooks y la
  confianza en la carpeta.

  A FAVOR, y es un hallazgo de verdad: el valor que decide si una tarea
  `folderOpen` se ejecuta NO puede vivir en ningún ámbito que controle el
  repositorio. La clave es `ConfigurationScope.APPLICATION` en el propio código
  de VS Code, así que un `.vscode/settings.json` commiteado no la fija, y el
  valor sale del fichero de ajustes del usuario. De ahí se sigue que
  INDETERMINADO es la respuesta CORRECTA por defecto en cualquier pull request,
  no un hueco de la herramienta: quien revisa un PR no puede saber, desde el
  repositorio, si la máquina que lo abra ejecutará la tarea. Un producto que
  respondiera «se ejecuta» o «no se ejecuta» ahí estaría inventando.

  EN CONTRA, Y ESTO VA ESCRITO PARA NO INFLAR EL TITULAR: la tarea que plantó
  keyv solo se ejecuta si el usuario YA tenía la ejecución automática activada.
  El valor por defecto documentado es `off`, y además las tareas automáticas no
  corren nunca en un espacio de trabajo sin confiar, sea cual sea el ajuste. Así
  que el titular del estudio NO puede decir que la mitad de VS Code del gusano
  se ejecuta siempre, ni que se ejecuta en una máquina recién instalada. Lo que
  puede decir es lo que es: que se ejecuta sin preguntar en las máquinas que
  tienen la ejecución automática activada y la carpeta confiada, que el
  repositorio no puede saber cuáles son, y que la otra mitad del mismo gusano
  -el hook de Claude Code- no espera a nada de eso. Las dos mitades no son
  equivalentes y el estudio que las presente como una sola estará vendiendo.


- **Que los hooks y `env` NO esperen a la confianza en la carpeta es el
  mecanismo por el que los dos gusanos de 2026 funcionan, y es material del
  estudio.** La tabla «What runs before you trust a folder» de la página de
  permisos pone los hooks de los ficheros de settings, el bloque `env` y los
  comandos auxiliares en la fila que dice **Used** en las dos situaciones sin
  confianza; solo esperan `permissions.allow`, `additionalDirectories`, las
  aprobaciones de `.mcp.json` y `extraKnownMarketplaces`. La lectura intuitiva
  —«el diálogo de confianza me protege de un repositorio que no he leído»— es
  falsa justo donde importa, y es lo que convierte un `.claude/settings.json`
  commiteado en ejecución de código al abrir la sesión. Está citada en la fila
  correspondiente de `surface/resolve.MERGE_TABLE`, con la URL, el digest de la
  página y la fecha, y la condición sale escrita en cada capacidad afectada del
  informe. **Fase de lanzamiento**, sección 7 del plan maestro: es uno de los
  «lo habría cazado», y el punto que explica por qué.

### Abiertas de la fase S3

- ~~**`uses: $/` está sin probar y se deja para después, a propósito.**~~
  **Cerrada.** El trabajo `action` salió verde dos veces con `uses: ./` (runs
  35382239038 y 35384198525), y solo entonces las dos líneas pasaron a `uses: $/`
  en un commit propio, de forma que un rojo ahí solo podía ser de esa línea. Los
  dos silencios `# zizmor: ignore[self-repository]` se fueron con ellas: zizmor
  sale ahora limpio sin ninguna exención, «No findings to report» sin
  «(N ignored)». El aislamiento de la variable, que es lo que la línea pedía,
  funcionó exactamente como estaba previsto.
- **El informe HTML no tiene una comprobación de que se lea.** Se afirma que no
  carga nada de la red, que sale igual dos veces y que escapa lo que viene de
  otro; no se afirma nada de que el resultado sea legible, y eso no es
  comprobable por una máquina sin una captura, que es exactamente la clase de
  fichero que la A.1 quitó. **Sin fase**: es una limitación conocida, no trabajo
  pendiente.
- **`diff` materializa el árbol entero de cada ref.** Es correcto - filtrar por
  las rutas que los lectores conocen sería una segunda copia de la lista de
  rutas de cada lector, y `diff` respondería sobre un subconjunto mientras
  `check` responde sobre todo - y es caro en un monorepo. Los techos
  (`MAX_TREE_FILES` 50 000, `MAX_TREE_BYTES` 256 MiB) se comprueban contra el
  listado antes de escribir un byte, así que un árbol que no cabe se rechaza con
  el número dicho en vez de extraerse a medias. Lo que no hay es una medida de
  cuánto tarda sobre un repositorio grande de verdad. **Sin fase** hasta que
  alguien lo note; la lista de `.launch/` pide el dato de las cuatro
  ejecuciones.
- **`git_tracked` no sabe responder sobre un árbol materializado de una ref.**
  Un directorio extraído con `cat-file` no tiene `.git/index`, así que el hecho
  sale `null` con su causa escrita, en los DOS lados del diff. Ninguna regla lee
  ese hecho, así que ningún hallazgo cambia, y como es simétrico tampoco produce
  un cambio falso. Rechazado: fabricar un `.git/index` para que el hecho leyera
  `true`, que sería Actaira escribiendo un artefacto de git para que su propia
  respuesta pareciera más completa, y además el hecho no es «estaba en el índice
  de esa ref» sino «estaba en el índice del árbol que se leyó». **Sin fase.**
- **El informe de `diff` no publica lo que no se materializó.** `Extraction`
  lleva un campo `refused` con los submódulos y las rutas que no habrían quedado
  dentro de la extracción, y `to_dict` no lo saca al documento: un submódulo es
  un id de commit y no un fichero, y hoy eso no llega a `not_read`. Es la
  tercera negativa en pequeño y el arreglo es una entrada de `not_read` por cada
  uno. Encontrado en la pasada adversarial de la fase. **Sin fase.**
- **`report/html.py` imprime `facts` enteros y `check` por consola no.** La
  página es más completa que la consola para el mismo documento, que es una
  diferencia entre dos salidas del mismo comando sin nadie que la arbitre. La
  página es la que está bien: un revisor quiere ver el hecho y no solo la frase
  sobre el hecho. **Sin fase.**
- **No está comprobado a qué resuelve `uses: $/` en un evento `pull_request`.**
  En push a `main` sí: el log del run 35384556901 dice
  `Download action repository 'marcosmatalab/actaira@bba5403...' (SHA:bba5403...)`,
  o sea el commit que se está probando. En un pull request no se ha mirado, y
  hay una razón concreta para sospechar: el fichero de workflow de un
  `pull_request` se toma de la BASE, así que si `$/` se resolviera también a la
  base, un PR que cambie `action.yml` se estaría autoprobando contra la versión
  VIEJA de la acción y el trabajo `action` saldría verde sin haber ejecutado ni
  una línea de lo que el PR propone. Con `uses: ./` no pasaba: leía el workspace,
  que en un `pull_request` es el merge del PR. O sea que la sintaxis que es más
  estricta para seguridad puede ser más floja para autoprobarse, y las dos cosas
  pueden ser verdad a la vez.

  Método, para que no haya que inventarlo el día que toque: abrir un PR que
  cambie UNA LÍNEA COMENTADA de `action.yml` - una que no altere ningún
  comportamiento - y leer en el log del trabajo `action` qué SHA descarga en
  `Download action repository`. Si es el del PR, no hay nada que hacer. Si es el
  de la base, el trabajo de autoprueba tiene que volver a `uses: ./` (y con él
  los dos `# zizmor: ignore[self-repository]`), quedándose `$/` para los
  workflows que no se prueban a sí mismos.

  **No es bloqueante hoy**, porque todo lo que ha entrado ha entrado por push a
  `main`. **Lo es el día que haya pull requests de fuera**, que es exactamente el
  día en que un PR puede cambiar `action.yml`.

- **WIDENED no ha corrido nunca de punta a punta en un runner.** Lo cubre la
  suite: `tests/test_diff.py` lo recorre en las dos direcciones sobre las dos
  configuraciones públicas de `michaelgrosner/CoffeeMol` y
  `bybren-llc/safe-agentic-workflow`. Lo que no existe es un run de GitHub
  Actions que haya producido uno. El punto 10 de la S3 saca 0, 1, 3 y 0, y el 0
  de la cuarta carpeta es un NARROWED, no un WIDENED. Las dos direcciones no son
  intercambiables para el código de salida: `fired_on_new_capability` mira
  `added` y `widened`, y WIDENED es el único camino al 1 que no pasa por una
  capacidad nueva — o sea, el único que la carpeta 2 no prueba. Se cubre en la
  **fase L** sobre un repo de fixture propio, que además permite controlar el
  estado de antes; sobre un fork ajeno el lado de antes es el que sea, y aflojar
  el guardarraíl de otro para probarlo no se hace. **Fase L.**
- **¿Sobre qué base documentada se ordena un valor que está fuera del conjunto
  que publica el fabricante?** Escrita como pregunta porque es la pregunta, y
  quien la abra no debería tener que reconstruirla. Las dos ramas:

  - Si la documentación de Google dice que un valor inválido se ignora y cae a
    `default`, entonces ordenarlo por debajo de `auto_edit` es correcto,
    NARROWED es la respuesta buena, y va **citada** — URL, digest de la página y
    fecha, como cualquier otra regla de mezcla.
  - Si no lo dice, ordenarlo es inferir comportamiento del fabricante, que es la
    tercera negativa, y lo honesto es INDETERMINADO con la causa nombrada.

  **El escenario que importa no es `yolo`.** `yolo` está contestado: el schema
  que publica Google para `general.defaultApprovalMode` admite `default`,
  `auto_edit` y `plan`, y dice que YOLO solo se activa por línea de órdenes
  (`--yolo`, `--approval-mode=yolo`), así que un fichero de ajustes no puede
  fijarlo y tratarlo como no-`auto_edit` no es inventar nada. Medido el
  2026-09-18 preparando el punto 10: `auto_edit` -> `"yolo"` sale NARROWED y 0.

  El escenario es el día que un fabricante **añada un modo nuevo más ancho que
  todos los conocidos** y un valor desconocido caiga al extremo seguro del
  orden. Eso sale NARROWED sobre un ensanchamiento real: un falso negativo en la
  única dirección en la que un falso negativo importa. Hoy `surface/gemini.py`
  conoce una sola constante, `AUTO_EDIT = "auto_edit"`, así que todo lo que no
  sea esa cadena es «no auto_edit» — que es exactamente el extremo seguro.

  **El test que lo contesta**: un fichero de Gemini con un valor fuera del
  conjunto publicado a los dos lados de un diff, y la afirmación de qué sale y
  por qué. **Fase L.**
- **Qué OTROS valores arrastran una condición que su fila de mezcla no expresa.**
  Encontrado contando, para la S3.1, cuántas de las 16 claves tienen regla de
  mezcla por valor. Dos la tienen y entran en esa fase. Aparte de esas, un valor
  puede no contradecir el `kind` de su fila y aun así arrastrar una condición que
  la fila no dice: `hooks[].type = "http"` está acotado por `allowedHttpHookUrls`,
  que «applies to hooks from every source, including managed settings», y
  `command` y `mcp_tool` no lo están. Ese caso concreto SE ARREGLA EN LA S3.1,
  como una fila, usando la escalera DECLARADO-a-EFECTIVO que existe para esto.
  Lo que NO entra en la S3.1 es el barrido sistemático: recorrer las 16 claves
  preguntando, valor por valor, qué otra clave lo condiciona. El par de VS Code
  (`runOn: folderOpen` acotado por `task.allowAutomaticTasks`) ya está modelado y
  es la prueba de que el patrón existe en más de un sitio. **Sin fase**, hasta que
  alguien la abra: es un barrido de documentación de seis fabricantes, no un
  arreglo.
