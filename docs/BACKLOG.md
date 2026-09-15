# Backlog

Una línea por cosa encontrada y no arreglada, con la fase que la posee. No es
una lista de deseos: solo entra aquí lo que una pasada real encontró y decidió
no tocar, y la razón de no tocarlo. Regla de trabajo 2 de `CLAUDE.md`.

## Fase 0 — la amputación

- `README.md` y `README.es.md` siguen describiendo el escáner de modelos entero,
  con cifras cuyo arnés está archivado (15 controles, 21 obligaciones, 7
  conectores, 64 artefactos de corpus, 9 objetivos de fuzz, 11 de 11, 0 de 32,
  8 de 8). Cada una de esas frases es también una frase de posicionamiento, y la
  autorización de la fase 0 era mecánica, así que solo se borraron los bloques
  de imagen. **Fase 5.**
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
