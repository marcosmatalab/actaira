# Backlog

Una línea por cosa encontrada y no arreglada, con la fase que la posee. No es
una lista de deseos: solo entra aquí lo que una pasada real encontró y decidió
no tocar, y la razón de no tocarlo. Regla de trabajo 2 de `CLAUDE.md`.

## Fase 0 — la amputación

- main local (f706527, 275ecf4) no publicado; vive en pivot/agent-conformance hasta que la fase 5 reescriba el README.
- `README.md` y `README.es.md` siguen describiendo el escáner de modelos entero.
  Cada una de esas frases es también una frase de posicionamiento, y la
  autorización de la fase 0 era mecánica, así que solo se borraron los bloques
  de imagen. **Fase 5.**
- Catorce líneas de cada README enuncian una cifra que ya no mide ningún
  comando, medidas contra `scripts/figures_contract.py`, que es la lista de las
  21 que sí se miden. Los dos ficheros están alineados línea a línea, así que
  los números valen para ambos. Regla de trabajo 6 de `CLAUDE.md`. **Fase 5.**

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
  su verde no dice nada sobre la tabla.

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
  screenshots` y `docs/img/`, que ya no existen. **Fase 5.**
- `docs/GOVERNANCE.md`, `docs/FORMATS.md`, `docs/EVALUATION.md` y
  `docs/CONCEPTS*.md` documentan módulos archivados. `docs/COMPATIBILITY.md`
  promete que un contrato publicado sigue publicado, y 3.0.0 retira diez.
  **Fase 5.**
- `conformance/model.py` declara `SCHEMA_VERSION = "agent-bom/v2"` y ese esquema
  ya no se publica: el módulo emite un documento contra un contrato que no está
  en `schemas/`. Se resuelve cuando los paquetes de reglas de conformidad
  definan qué documento emiten. **Fase 2.**
- `statecli._record_manifest` grababa un manifiesto de sujetos en el grafo de
  estado. Se fue con `statecli.py`; `manifest.py` y `state/` siguen aquí y la
  función no. Tiene que volver con `actaira contract`. **Fase 1.**
- Tres tests de `test_state_graph.py` que cubrían esa función se borraron con
  ella, y con ellos la única cobertura de las aristas de pertenencia grabadas
  desde un manifiesto. **Fase 1.**
- DEF-115 (un recibo emitido desde un espacio de trabajo no referenciaba
  evidencia) perdió su test: pasaba por `actaira receipt issue --state`. El
  defecto está arreglado en `state/` y el registro lo apunta contra la etiqueta
  `v2.3.0`. Necesita un test nuevo cuando `actaira receipt` vuelva. **Fase 4.**
- `i18n` conserva 41 ids de regla del escáner, que son los que siguen citados en
  `coverage.py` y en `conformance/`. Son el vocabulario que `report/sarif.py` y
  `report/junit.py` traducen, y no hay otro todavía. Se sustituyen por el
  vocabulario de la traza. **Fase 2.**
- `examples/subjects.yaml` documenta en su cabecera dos comandos que ya no
  existen (`policy check --subjects`, `graph build --subjects`). **Fase 3.**
- `.github/actions/actaira-scan/` sigue apuntando al escáner, por orden. **Fase 4.**
- `.github/workflows/ci.yml` todavía puede invocar pasos de `make` que ya no
  existen. No se tocó: la puerta de la fase 0 es `make all`, no CI. **Fase 4.**
- `figures.json` registra `git.head` del momento en que se generó, y commitearlo
  cambia el head, así que siempre va un commit por detrás (572f86f registra
  6cec2ec). `release-check` lo tolera por diseño. No se puede arreglar dentro del
  propio fichero: es el problema del punto fijo, el mismo que resuelven los
  árboles de Merkle anclando la constancia fuera del objeto. Candidato a ejemplo
  del ensayo de la fase 4.5A.

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
  saber si el fixture del `--demo` viajaba en la rueda. **Fase 4.**
