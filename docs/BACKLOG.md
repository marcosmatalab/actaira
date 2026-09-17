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
  screenshots` y `docs/img/`, que ya no existen. Sigue abierto y recomprobado en
  la S0: `grep -n 'make diagrams' CONTRIBUTING.md docs/ENGINEERING.md` devuelve
  dos líneas y el `Makefile` no tiene ninguno de los dos objetivos. **Fase S3**,
  que es cuando vuelve a haber una imagen que generar: el informe HTML.
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
- DEF-115 (un recibo emitido desde un espacio de trabajo no referenciaba
  evidencia) perdió su test: pasaba por `actaira receipt issue --state`. El
  defecto está arreglado en `state/` y el registro lo apunta contra la etiqueta
  `v2.3.0`. `actaira receipt` no vuelve: el documento firmado del plan nuevo es
  el sello de superficie. La forma del defecto sí vuelve, porque es la misma, un
  documento firmado que no referencia aquello sobre lo que se firmó.
  **Fase S3**, con `seal`.
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
  que se fueron a `archive/model-scanner` en la 3.0.0. `make package` no está en
  `make all`, así que la puerta no lo ve. Encontrado leyendo el fichero para
  saber si el fixture del `--demo` viajaba en la rueda. **Fase S3**: es la
  primera que publica algo que instala un tercero, y ese día un `make package`
  roto deja de ser un problema interno.

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
  operador que empaquete `--out` entero publica lo que la sal protegia. El acta
  de la fase 3 empaqueta la traza firmada y no `records/`, asi que el camino
  correcto ya existe; lo que falta es que el directorio lo diga y que el
  empaquetador se niegue si lo encuentra dentro. El empaquetador es `seal`.
  **Fase S3.**
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

- **`test_reachability` mide módulos, no si la cadena del producto se cierra.**
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

- **`check` no está expuesto por el servidor MCP.** Es la decisión que la fase
  traía: cabe en `mcp.py` con una entrada en `TOOLS` y una función como
  `_verify`, pero el fichero 17 del presupuesto era `SECURITY.md` y exponerlo
  habría sido el 18. No es alcance descubierto: el comando funciona entero por
  CLI y nadie pierde una capacidad. **Fase S2**, junto con los lectores nuevos,
  para exponer una herramienta que ya cubra más de un fabricante.
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
- **El frontmatter de skills y subagentes no se lee.** Se detecta que hay una
  clave `hooks` y sale INDETERMINADO con causa. No hay lector YAML en el árbol y
  no se añade dependencia. **Fase S2**, que es donde ya hay que decidir qué
  hacer con AGENTS.md.
- **`enabledPlugins` solo se resuelve si el plugin está descargado en el árbol.**
  Lo que viene de un marketplace remoto sale INDETERMINADO. Es correcto y es la
  causa de gap más frecuente del corpus (8 de 20 configuraciones). Puede que
  merezca agruparse por marketplace en la consola en vez de una línea por
  plugin. **Sin fase.**
- **`MANIFEST.in` excluye `.pre-commit-hooks.yaml`, que ya no existe.** Sigue
  abierta desde la A.1, sin tocar. **Fase S3.**

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
- **Los hechos de un script al que apunta el hook de un PLUGIN no se calculan.**
  `Reading.scripts` se rellena recorriendo `settings`, no los `hooks/hooks.json`
  de los plugins descargados, así que ACT-S003, ACT-S004 y ACT-S005 salen
  INDETERMINADAS sobre un hook de plugin en vez de responder. Es honesto y es
  incompleto. **Fase S2**, que ya vuelve a tocar el lector.

### Para el estudio del lanzamiento

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
