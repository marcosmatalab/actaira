# Conceptos

El vocabulario que usa esta herramienta, un recorrido de cinco minutos, y el
índice completo de comandos. Escrito porque cada término de abajo significa
aquí algo más estrecho que en una página de marketing, y quien asuma el
significado amplio leerá la salida como una afirmación más fuerte de lo que es.

- [Los nueve sustantivos](#los-nueve-sustantivos)
- [Un recorrido de cinco minutos](#un-recorrido-de-cinco-minutos)
- [Todos los comandos](#todos-los-comandos)
- [El almacén de estado](#el-almacén-de-estado)
- [A dónde ir después](#a-dónde-ir-después)

---

## Los nueve sustantivos

### Artefacto

Un fichero, identificado por su SHA-256. Un `.pt`, un `.onnx`, un
`.safetensors`, un `.gguf`, un `.h5`, un `.npy`, un `.pkl` suelto. Un artefacto
es lo único de lo que Actaira lee bytes, y leerlos no significa nunca cargarlos:
el analizador de pickle es una interpretación abstracta exacta de la pila de
valores y del memo, no un unpickler con un filtro.

### Bundle

Un *repositorio* de modelo, resuelto en miembros, relaciones y huecos: shards,
un índice, una config, un tokenizador, un `adapter_config.json` que apunta a un
modelo base en otro sitio, y el Python que haya al lado. Un bundle lleva dos
digests distintos a propósito:

| | |
|---|---|
| `structural_digest` | sobre la disposición: rutas, tamaños, roles y los digests de miembro que se hayan calculado. Siempre disponible. |
| `content_identity` | sobre los pesos, con un estado propio: `complete`, `partial`, `externally_bound` o `unavailable`. |

Están separados porque un digest sobre la disposición no es la identidad de los
pesos, y una herramienta que devolviera un solo digest dejaría creer a quien lo
lee que los pesos estaban fijados cuando solo lo estaba la lista de ficheros.

### Agente

Una declaración: un modelo, un prompt de sistema, un conjunto de herramientas
con efectos declarados, servidores MCP y subagentes. Actaira nunca habla con un
agente. Lee lo que el despliegue dice que el agente es, y el digest del agente
cubre el prompt de sistema además de las herramientas, porque cambiar las
instrucciones cambia el comportamiento tan a fondo como cambiar una herramienta.

### Sistema

Varios de los anteriores, nombrados juntos como la cosa que una obligación
vincula de verdad: un bundle más un agente más las fuentes de las que vinieron.
La mayoría de las preguntas de cumplimiento son sobre un sistema, y responderlas
sobre una lista de ficheros es el error de categoría más común en este espacio.

### Sujeto

El tipo de referencia que hace que un solo lenguaje de política funcione sobre
todo lo anterior. Hay 5 tipos de sujeto, `artifact`, `bundle`, `agent`, `system`
y `source`, y `subject_kind` es una guarda que cortocircuita: una regla escrita
sobre bundles evalúa a "no aplicable" contra un agente, no a falso.

### Evidencia

Algo observado, atado al digest de lo que se observó, con un estado y una vida
útil. 5 estados de evidencia:

| | |
|---|---|
| `valid` | observado, y el sujeto sigue teniendo el digest con el que se observó. |
| `stale` | más antiguo que el `evidence_max_age_days` que la política fija para ese tipo de afirmación. |
| `superseded` | el digest al que estaba atado ya no existe. Una observación más nueva lo reemplazó. |
| `revoked` | retirado deliberadamente, por ejemplo porque se revocó la clave de firma. |
| `untrusted` | el firmante ya no lo acepta la política de confianza de este entorno. |

La sustitución está atada al digest, no al nombre. Una revisión nueva de un
shard no invalida la evidencia sobre un hermano que nadie tocó, y una
herramienta que sustituyera por nombre tiraría en silencio trabajo que seguía
siendo cierto.

### Política de confianza

Qué acepta *este entorno*, deliberadamente aparte de qué probó la criptografía.
`actaira verify` responde "¿coinciden estos bytes con esta firma?";
`actaira trust check` responde "¿y aceptamos a ese firmante?". Un entorno que no
ha escrito ninguna política de confianza no ha rechazado nada, así que ahí la
respuesta es `UNKNOWN`, nunca `UNTRUSTED`.

### Recibo

La única salida pensada para salir de la organización que la produjo, leída por
alguien que no tiene ni los artefactos ni esta herramienta. Lleva los sujetos
por digest, la matriz de cobertura, los hallazgos por severidad, la decisión de
política con su prueba y el estado de la cadena de suministro, y está firmada
sobre el JSON canónico de sí misma menos la firma, algo que un tercero puede
reimplementar en veinte líneas.

No es una certificación y no es una puntuación. Un test busca `score`, `grade`,
`rating` y `percent` en el documento terminado y falla si aparece alguno, y
`states_what_it_does_not_cover` es un campo obligatorio, porque la forma más
común en que un documento de assurance engaña es que se lea como exhaustivo.

### Grafo de activos

Activos y los 12 tipos de relación entre ellos: `contains`, `uses`,
`uses_model`, `reads`, `writes`, `exposes`, `delegates_to`, `served_by`,
`runs_as`, `governed_by`, `supports`, `evidenced_by`.

Cada arista lleva `stated_by`: el manifiesto, la declaración de agente o el
snapshot que la afirmó. Nada se infiere de que dos activos compartan registro,
organización o nombre. `actaira impact` recorre esas aristas y responde con la
ruta:

```console
$ actaira impact source:huggingface://acme/fraud-model

  affected
    1 agent
    1 system

  re-evaluate
    agent:ticket-triage
    system:ticket-triage-service

  Why?
    agent:ticket-triage -> USES -> source:huggingface://acme/fraud-model
    system:ticket-triage-service -> USES -> agent:ticket-triage -> USES -> source:huggingface://acme/fraud-model
```

Un informe de impacto que listara todo lo que hay cerca sería técnicamente
completo y enseñaría a la gente a ignorar los informes de impacto.

---

## Un recorrido de cinco minutos

Todos los comandos de abajo se ejecutan sin conexión, contra ficheros que este
repositorio construye. Copia el bloque; funciona desde una copia recién hecha
de este árbol después de `pip install -e ".[dev]"`.

**Minuto 1: construir un corpus y mirarlo.**

```bash
make eval                      # escribe evals/artifacts/ desde código, sin descargas
actaira scan evals/artifacts/gadget_known_posix_system_p2.pkl
echo $?                        # 1: un hallazgo igual o por encima del umbral de fallo
```

La salida nombra la regla, el callable, el digest y la matriz de cobertura. Lee
la matriz: es el alcance de la afirmación que tiene encima, y se imprime también
para los artefactos limpios.

**Minuto 2: preguntar qué opina una política.**

```bash
actaira policy check evals/artifacts --policy-file policies/production-model.yaml
```

DENY con las reglas y la evidencia que lo causaron. Fíjate en la regla que salió
REVIEW: a esta ejecución no se le dio ninguna atestación, así que
`signature_verified` no tenía nada que evaluar, y un predicado sin información va
a REVIEW en vez de devolver falso en silencio.

**Minuto 3: firmar lo observado, y luego comprobarlo.**

```bash
actaira keygen --key key.pem
actaira attest evals/artifacts --out release.actaira.zip --key key.pem --dsse
echo $?                        # 1: el paquete se escribe, y el corpus tiene hallazgos
actaira verify release.actaira.zip --trusted-keyring keyring.json --require-trust
```

Ocho comprobaciones separadas, impresas por separado. Integridad e identidad son
dos preguntas y la salida no las mezcla nunca. `--dsse` escribe además un
Statement in-toto dentro de un sobre DSSE, para que el mismo veredicto lo puedan
consumir cosign y policy-controller y no solo esta herramienta.

**Minuto 4: darle memoria.**

```bash
actaira init
actaira source add ./evals/artifacts --id corpus
actaira watch corpus            # BASELINE: no había nada con lo que comparar
actaira watch corpus            # UNCHANGED: nada se reanaliza, nada se escribe
printf '\0' >> evals/artifacts/benign_array.npy
actaira watch corpus            # CHANGED: solo se reanaliza lo que se movió
actaira evidence list
```

**Minuto 5: preguntar a qué llega un cambio, y qué podría hacer un agente.**

```bash
actaira graph build --subjects examples/subjects.yaml
actaira impact source:huggingface://acme/fraud-model
actaira agent check examples/agent-ticket-triage.yaml
actaira agent paths examples/agent-ticket-triage.yaml
```

`agent check` informa de parejas de capacidades que son una mala combinación.
`agent paths` informa de la ruta entre ellas y de qué la rompería, e informa como
cerrada una ruta que un control existente ya cierra, porque un hallazgo que salta
sobre una mitigación que funciona es como un equipo aprende a ignorar la salida.

---

## Todos los comandos

Sin estado, no necesitan más que los ficheros que les señales:

| | |
> **Estas dos filas son los comandos de la era de la traza.** El resto de esta
> página sigue describiendo el escáner de modelos archivado en `v2.3.0`; la
> fase 5 la reescribe entera.
>
> | | |
> |---|---|
> | `actaira scan` | leer las sesiones que un agente ya grabó en esta máquina, como trazas canónicas. Nivel de captura L0: el transcript lo escribió el propio agente auditado, así que la autenticidad no se evalúa y la traza sirve para diagnóstico, no como prueba. `--demo` corre sobre una sesión sintética que trae el paquete. |
> | `actaira watch -- <comando>` | ejecutar un agente con un proxy de MCP delante de cada uno de sus servidores y grabar lo que llamó, desde fuera de él. Nivel de captura L1. Lo que el proxy no pudo observar se declara como hueco con su razón; una traza nunca sale pareciendo completa sin serlo. |
>
> El servidor MCP no es un comando. Es un segundo punto de entrada,
> `actaira-mcp`, que publica `actaira_verify` más `actaira_verdict` y
> `actaira_contract`, que devuelven un estado explícito de no implementado
> hasta la fase 2.

|---|---|
| `actaira scan` | inspeccionar artefactos, con `--format sarif`, `junit` o `json` |
| `actaira bom` | un ML-BOM CycloneDX 1.6 de lo inspeccionado |
| `actaira bundle` | resolver un repositorio de modelo en miembros, relaciones y huecos |
| `actaira agent` | `check`, `bom`, `diff` y `paths` sobre una declaración de agente |
| `actaira controls` | `list` y `run` de los controles ejecutables, o `mark` de salida sintética |
| `actaira governance` | `clock` qué obligaciones vinculan, `assess` la evidencia contra ellas, `pack` un dossier firmado |
| `actaira policy` | `check` bajo una política versionada, o `show` qué dice una |
| `actaira schema` | imprimir un JSON Schema publicado, o listarlos |
| `actaira keygen` | crear, rotar o revocar una clave de firma Ed25519 y su keyring |
| `actaira attest` | escribir un paquete de atestación firmado, sin conexión |
| `actaira verify` | comprobar uno, respondiendo integridad e identidad por separado |
| `actaira receipt` | `issue` y `verify` de una declaración firmada del estado observado |
| `actaira trust` | `check` de un firmante contra la política de confianza de este entorno |
| `actaira discover` | enumerar una fuente remota por un conector, sin descargar nada que no nombrara |
| `actaira serve` | una interfaz local de solo lectura en 127.0.0.1 |

Con estado, necesitan `.actaira/`:

| | |
|---|---|
| `actaira init` | crear `.actaira/` y una base de datos de estado versionada |
| `actaira source` | `add` y `list` de las fuentes que este workspace vigila |
| `actaira watch` | observar una fuente ahora, comparar con la línea base, registrar qué se movió |
| `actaira snapshot` | imprimir o exportar el `source-snapshot/v1` almacenado de una fuente |
| `actaira evidence` | `list` de lo observado y `show` de un registro |
| `actaira graph` | `build`, `show` o `export` de las relaciones declaradas entre activos |
| `actaira impact` | de qué depende esto, y la ruta exacta que llega hasta ahí |
| `actaira changes` | las observaciones que este espacio de trabajo ha registrado, de la más antigua a la más reciente |
| `actaira decisions` | cada decisión registrada, y si sus entradas siguen describiendo a su sujeto |

`actaira --lang es <comando>` cambia el idioma de la salida. El flag es global,
así que va antes del subcomando, y un test falla si un idioma gana una cadena
que el otro no tiene.

Todo comando con estado acepta `--state` si guardas la base de datos en otro
sitio, y los comandos que imprimen un informe aceptan `--json` si prefieres
parsearlo; los que escriben un documento aceptan `--out` en su lugar. En
cualquier caso la forma es un contrato publicado: ver
[`CONTRACTS.md`](CONTRACTS.md).

---

## El almacén de estado

`.actaira/state.db` es SQLite de la biblioteca estándar. Es opcional: todos los
comandos sin estado de arriba funcionan sin él, y la capa de estado es memoria,
no un requisito previo.

**Las migraciones son numeradas y solo hacia delante.** `actaira init` crea la
versión actual; abrir una base de datos más antigua aplica cada paso en orden.
El release gate aplica cada migración a una base de datos construida por todas
las anteriores y rechaza una versión donde algún paso no tenga fixture, porque
una migración que no se ha ejecutado nunca es una migración que no funciona.

```bash
actaira init                            # store schema version 2
actaira snapshot corpus --out snap.json  # el source-snapshot/v1 almacenado
actaira graph export --out graph.json    # asset-graph/v1
```

**La exportación es determinista.** Dos ejecuciones sobre la misma observación
producen documentos idénticos byte a byte, algo que el gate comprueba en cada
versión: una exportación que reordenara filas haría ilegible cualquier diff
entre dos estados, y lo primero que hace cualquiera con una exportación de
estado es un diff.

No hay comando de importación y es deliberado. Un almacén se reconstruye
volviendo a observar las fuentes, que es barato, sin conexión y honesto sobre
cuándo se estableció cada hecho. Una importación dejaría que un documento
afirmara una línea base que nadie observó nunca, y el sentido entero de la línea
base es que alguien la observó.

---

## Cuando algo cambia

Este es el bucle al que sirve el resto de la herramienta, y cada flecha es un
sitio donde una herramienta puede mentir sin que se note:

```
observar -> estado -> cambio -> invalidar -> impacto -> decidir -> demostrar
```

**Invalidar.** La evidencia se ata al digest sobre el que se tomó, nunca al
nombre del sujeto. Así que volver a observar un modelo que no cambió no
sustituye nada, observar uno que sí cambió sustituye solo los registros
tomados sobre los bytes que ya no están, y el escaneo de un hermano que nadie
tocó sigue siendo válido. Esa es la diferencia entre una invalidación sobre la
que alguien actúa y una pantalla roja que nadie lee.

**El impacto empieza en lo que se movió.** No en la fuente que lo contiene.
Una fuente con cuarenta ficheros de los que cambió uno tiene un artefacto
cambiado, y el recorrido empieza ahí. Cuando cambian dos artefactos y ambos
llegan al mismo sistema, ese sistema aparece una vez con dos causas debajo:
quien tenga que reevaluarlo necesita saber que está aguas abajo de dos
cambios.

**Decidir son dos preguntas, no una.** Lo que se decidió es historia y esta
herramienta no la reescribe: un ALLOW registrado en marzo se imprime como
ALLOW para siempre, porque sobrescribirlo destruye el único registro de lo que
se aprobó. Si sigue aplicando es otra pregunta, con sus propios tres valores:

| | |
|---|---|
| `current` | cada entrada que registró sigue describiendo a su sujeto |
| `requires_reassessment` | al menos una demostrablemente ya no, y aquí está cuál |
| `undetermined` | este espacio de trabajo no guarda lo suficiente para decirlo |

A `requires_reassessment` no se llega nunca por inferencia. Hace falta una
fila: un registro de evidencia cuyo estado no sea `valid`, o un sujeto cuyo
digest registrado difiera del que la decisión nombró. "El modelo cambió hace
poco" no es una razón. `{"reason": "evidence_superseded", "evidence_id":
"ev_...", "was": "sha256:...", "now": "sha256:..."}` sí lo es, y eso es lo que
imprime el comando y lo que lleva `--json`.

Una decisión archivada antes de que el almacén registrase dependencias no
tiene ninguna, y queda `undetermined` en vez de `current`. Leer "sin entradas"
como "nada de lo que dependía ha cambiado" marcaría precisamente las
decisiones sobre las que esta herramienta sabe menos como las que no requieren
atención.

```bash
actaira scan models/model.pt --state .actaira/state.db   # archiva un registro artifact_scan
actaira policy check --subjects examples/subjects.yaml \
    --policy-file policies/production-model.yaml --state .actaira/state.db
actaira watch corpus                                     # qué se movió, y qué costó eso
actaira decisions --state .actaira/state.db              # y qué aprobaciones deja abiertas
```

`--state` es opcional en todos ellos, y nunca crea una base de datos. Un
escaneo en una máquina sin espacio de trabajo se comporta exactamente como
antes de que nada de esto existiera, que es la propiedad local-first por la
que la herramienta merece la pena.

Una cosa que el registro todavía no hace. Cuatro de los siete tipos de
evidencia tienen productor: `source_snapshot`, `artifact_scan`,
`agent_assessment` y `policy_decision`. `bundle`, `governance` y `attestation`
están definidos y todavía no los escribe nada, y ese reparto está fijado por
un test para que no cambie sin que alguien se entere.

---

## Los dos ficheros que usan todos los ejemplos

`models/` en los bloques de salida del README son dos ficheros, construidos
desde bytes literales para que sus digests sean los mismos en todas partes: en
el README, en la interfaz local, y en el directorio donde los construyas tú.

```bash
mkdir -p models
python3 - <<'PY'
import pathlib
models = pathlib.Path("models")
header = b'{"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}'
(models / "clean.safetensors").write_bytes(
    len(header).to_bytes(8, "little") + header + b"\x00" * 16
)
(models / "trojan.pkl").write_bytes(
    b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."
)
PY
```

`clean.safetensors` es un tensor 2x2 float32 llamado `w`: un fichero válido sin
nada que encontrar dentro. `trojan.pkl` son 25 bytes de pickle de protocolo 2
que reducen a través de `posix.system`, que es lo más pequeño que demuestra
para qué sirve el escáner. Sus digests son `sha256:d1398981d27e3b57...` y
`sha256:48fc51f766e9c91b...`, y deberías obtener exactamente esos.

`scripts/cli_transcripts.py` construye esos mismos dos ficheros y ejecuta la
CLI contra ellos, que es de donde salen los bloques de consola del README. La
verja de release lo ejecuta dos veces con semillas de hash distintas y rechaza
un árbol donde las dos ejecuciones hayan impreso bytes distintos.

---

## Usarlo en algún sitio que no sea un terminal

Con la herramienta viajan tres superficies de integración fáciles de pasar por
alto, porque ninguna de las tres es un comando.

**Como hook de pre-commit.** `.pre-commit-hooks.yaml` define dos: `actaira`
inspecciona los artefactos de modelo del commit, y `actaira-repo` inspecciona
todos los del árbol de trabajo cada vez que cambia alguno, que es lo que caza
un artefacto commiteado antes de que el hook existiera.

Este árbol no está publicado en ningún sitio, así que la forma que funciona
hoy apunta a una Actaira ya instalada en el entorno:

```yaml
repos:
  - repo: local
    hooks:
      - id: actaira
        name: actaira (inspect model artifacts)
        entry: actaira scan --fail-on high
        language: system
        types: [file]
        files: '(?i)\.(pkl|pt|safetensors|onnx|gguf|npy|h5|joblib)$'
```

`.pre-commit-hooks.yaml` es la otra mitad de esa integración: las definiciones
de hook a las que apuntaría una entrada `repos:` si este árbol se publicara, y
el fichero del que la verja de release lee el pin de versión.

Los dos salen con código distinto de cero ante un artefacto que no se pudo
leer del todo, no solo ante uno que falló, porque ese es el contrato de la CLI
y porque "no pude leer este fichero" no es una razón para dejarlo entrar en un
commit. Añade `args: [--allow-inconclusive]` si tu repositorio decide otra
cosa: la decisión vive entonces en tu configuración, a la vista, en vez de en
el hook, en silencio.

**Como GitHub Action.** `.github/actions/actaira-scan` es una acción
compuesta, no una de Docker, así que fija la herramienta al tag que pide el
workflow y no a lo que llevara dentro la última imagen construida. Emite SARIF
para code scanning y falla el job a la severidad que elijas.

**En un contenedor.** El `Dockerfile` de la raíz construye una imagen con la
herramienta y nada más. Excluye el constructor del corpus, por la razón que da
[`SECURITY.md`](../SECURITY.md): ese script escribe pickles con gadgets que
funcionan, y una imagen publicada no es donde eso va.

---

## A dónde ir después

| | |
|---|---|
| [`FORMATS.md`](FORMATS.md) | cada regla, sobre qué salta y qué no cubre |
| [`DESIGN.md`](DESIGN.md) | las notas de diseño, cada una nombrando el fichero y la línea que la implementa |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | de qué defiende esto, y de qué no |
| [`CONTRACTS.md`](CONTRACTS.md) | los esquemas publicados, actuales y sustituidos |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | qué promete una versión no romper |
| [`FIGURES.md`](FIGURES.md) | cada número publicado, y el comando que lo produjo |
