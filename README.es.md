<div align="center">

**Un testigo independiente para agentes de IA.**

Actaira produce evidencia verificable de lo que un agente hizo, comparada con lo que estaba autorizado a hacer.

**Actaira 3.0.0** · Python 3.11 · 3.12 · 3.13 · Apache-2.0 · una dependencia en tiempo de ejecución · sin conexión, sin telemetría, sin cuenta

**[English](README.md)** · [Quickstart](#quickstart) · [Los cuatro comandos](#los-cuatro-comandos) · [Niveles de captura](#niveles-de-captura) · [Lo que Actaira se niega a hacer](#lo-que-actaira-se-niega-a-hacer) · [Límites](#límites-publicados) · [Docs](#el-resto-de-la-documentación)

</div>

---

## Qué es esto

Un agente se ejecuta. Lee ficheros, llama a herramientas, habla con un proveedor
de modelos. Después alguien pregunta qué hizo en realidad, y el único relato
disponible es el que el propio agente escribió sobre sí mismo.

Actaira captura ese relato **desde fuera del proceso**, decide de forma
determinista si la ejecución se salió de lo que declaró, y emite un acta que un
tercero puede comprobar sin confiar en el operador y sin confiar en Actaira.

No es un escáner de modelos. No es una plataforma de observabilidad. No es una
herramienta de cumplimiento.

Un acta de Actaira afirma exactamente tres cosas y nada más:

1. **Autenticidad.** La traza se capturó en el borde del proceso, no la produjo
   el agente sobre sí mismo. Está firmada, encadenada, y declara el nivel al que
   se capturó.
2. **Conformidad.** La ejecución conforma, no conforma, o es indeterminada
   respecto a un contrato. Cuando no conforma, el acta nombra el evento, su
   índice y la regla.
3. **Inclusión.** El acta está en un registro append-only cofirmado por testigos.

Cualquier cosa fuera de esas tres es un defecto de producto, aunque sea verdad.

---

## Quickstart

Cinco minutos, sin ningún agente instalado, sin red.

```bash
git clone https://github.com/<tu-fork>/actaira
cd actaira
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Una dependencia en tiempo de ejecución (`cryptography`). Después:

```console
$ actaira scan --demo

Reading the synthetic demo session shipped with the package.
  1 session(s), 4 tool call(s), from 2026-03-04T09:15:00.000Z to 2026-03-04T09:15:15.000Z
  1 session(s) declare a gap: something happened that was not observed

CAPTURE LEVEL L0: this transcript was written by the agent being audited, about
itself. Authenticity is not evaluated here and cannot be. It is diagnosis and
retrospective analysis, not evidence a third party can rely on. Use `actaira
watch` to record a run from outside the agent.
```

Ese bloque es el producto entero en miniatura. Leyó una sesión, dijo lo que vio,
y a continuación dijo - sin que nadie se lo pidiera - que lo que acababa de leer
no puede sostener la afirmación para la que existe la herramienta.

Con `--lang es` la salida sale en español. Si tienes Claude Code, Cursor o Cline
en esta máquina, quita el `--demo` y `actaira scan` lee las sesiones que ya
escribieron en disco.

---

## Los cuatro comandos

```
actaira scan      lee las sesiones que un agente ya grabó en esta máquina (L0)
actaira watch     graba una ejecución desde fuera del agente, por un proxy MCP (L1)
actaira verify    verifica un paquete de atestación sin conexión
actaira keygen    crea, rota o revoca una clave de firma
```

Esa es la lista completa. `actaira --help` imprime los mismos cuatro.

### `actaira watch` - grabar desde fuera

`watch` pone un proxy MCP entre el agente y sus servidores de herramientas,
ejecuta tu comando, y ensambla lo que el proxy vio en una sola traza.

```console
$ actaira watch -- python -c "print('agent ran')"

agent ran
Recorded session 1587a6c3-ae8f-4d5a-915c-21e763c88b44 at capture level L1
  0 tool call(s) observed from outside the agent
  ! [end_not_recorded] nothing recorded the end of this session, so what came
    after the last event was not observed
  ! [not_interposed] nothing readable recorded which MCP servers this session
    was configured with, so this tool cannot show that it observed all of them
  ! [proxy_start_failed] no proxy recorded anything for this session. Either the
    agent made no tool call, or it was never routed through the proxy, and this
    tool cannot tell which - so it declares the hole rather than publishing an
    empty clean trace.
  INCOMPLETE: the gaps above are what this run could not observe
  wrote the trace and its digest to ./actaira-watch
```

Lee esa salida otra vez, porque es el diseño. No se observó nada, y la
herramienta lo dijo de tres maneras distintas en vez de escribir una traza
limpia y vacía. Un testigo que informa del silencio como «no pasó nada» es peor
que no tener testigo, porque alguien se va a fiar de él.

Apúntalo a un agente real con su configuración MCP y el mismo comando graba las
llamadas a herramientas:

```bash
actaira watch --mcp-config .mcp.json -- claude -p "refactoriza el módulo de auth"
```

`--with-content` conserva los argumentos y resultados literales. Sin él, los
argumentos viajan como digests con sal: un digest no tiene falsos negativos y un
filtro de secretos sí.

### `actaira verify` - comprobar sin confiar en nadie

```bash
actaira verify attestation.zip
actaira verify attestation.zip --trusted-keyring keys.json --require-trust
```

Sin conexión, siempre. Integridad e identidad son respuestas separadas: un
paquete siempre lleva su propia clave, así que la integridad siempre se puede
responder, y «nadie ha avalado esta clave» se informa como exactamente eso y no
como un fallo. Pasa `--trusted-keyring` o `--pubkey` para atarlo a una clave en
la que ya confías.

### `actaira keygen` - la clave de firma

```bash
actaira keygen                      # crear
actaira keygen --rotate             # retirar la clave actual, seguir verificando lo antiguo
actaira keygen --revoke <key-id>    # nada de lo que firmó se acepta nunca más
```

Ed25519. El llavero vive al lado de la clave.

---

## Niveles de captura

Cada acta declara el nivel al que se capturó, y **el nivel decide qué puede
afirmar el acta**. Esta es la diferencia entre evidencia y diagnóstico, y no es
un detalle.

| Nivel | Qué es | Qué puede afirmar |
|---|---|---|
| **L0** | El transcript que el propio agente escribió - lo que Claude Code, Cursor o Cline ya guardaron en disco. Trae las llamadas de herramienta con sus argumentos. | **No puede afirmar autenticidad.** Lo produjo el auditado. Se declara como no evaluada, con su razón escrita. Diagnóstico y análisis retrospectivo, no evidencia para un tercero. |
| **L1** | Un proxy de MCP. Capturado desde fuera del agente. | Ve llamadas de herramienta. |
| **L2** | Un proxy de red. | Ve las llamadas de herramienta y las llamadas al proveedor del modelo. |
| **L3** | Un sandbox con seccomp. | Ve ficheros, red y ejecución. El único nivel que puede afirmar que no se tocó nada más. |

`scan` es L0. `watch` es L1. L2 y L3 no están implementados en este árbol.

Un nivel que no se emprendió no puede hacer inconcluso el veredicto. Uno que
estaba en alcance y falló, sí - y lo hace.

---

## Lo que Actaira se niega a hacer

Cuatro invariantes. Son el argumento, no una guía de estilo. Un cambio que viole
una se rechaza sin discusión.

**1. Nunca un número.** No hay score, grade, rating, percent, confidence ni
ranking en ningún documento emitido. Un test greppea esas palabras sobre todos
los documentos que este árbol produce, y solo se amplía. Una regla puede traer
una `severity` escrita por el autor de su paquete: eso es una etiqueta atribuida,
no un cálculo de Actaira, y nunca se agrega ni se suma con otra.

**2. Nunca juzgar, solo citar.** Actaira no tiene opinión sobre lo que un agente
debería haber hecho. Compara lo observado contra una norma **escrita por otro**,
y la nombra. Todo NO CONFORMA publica el id de la regla, su versión, su paquete
y su autor. De aquí se sigue: prohibido llamar a un modelo en el camino de
decisión. Un LLM puede ayudar a redactar una regla; no puede evaluarla, y tampoco
puede escribir su remediación.

**3. Nunca inferir lo no observado.** Si el nivel de captura no cubría algo, el
acta lo dice. Un predicado sin información devuelve INDETERMINADO, jamás False.
Cada regla declara el nivel de captura que necesita, y por debajo de él devuelve
INDETERMINADO sola, sin que nadie se acuerde de comprobarlo.

**4. Nunca actuar sobre lo que se observa.** Actaira *sugiere* remediaciones,
nunca las aplica. Un testigo que además actúa no puede dar fe de sus propios
actos, y ese conflicto de interés es exactamente lo que nos separa de un
proveedor de observabilidad. Si algún día existe un `--apply`, el cambio queda
registrado como un evento más de la traza, atribuido a Actaira, y el motor lo
evalúa como cualquier otro. Silencioso, jamás.

---

## Límites publicados

Están en el README, en la web y en el propio acta. No se ablandan para vender
mejor.

1. No reproducimos la salida de un modelo hospedado. Ni con seed ni con
   temperatura cero. La causa es el tamaño de lote del proveedor y el
   enrutamiento MoE, y no está bajo nuestro control.
2. No podemos aislar una ejecución de la carga de otros usuarios del proveedor.
3. No podemos detectar que el proveedor cambió de backend, salvo por
   `system_fingerprint` en OpenAI.
4. No hay determinismo en modelos MoE, que son todos los relevantes.
5. No podemos reproducir herramientas con estado sin congelar el mundo.
6. No demostramos la ausencia de una acción, solo su presencia.
7. Una traza producida por el propio agente no es evidencia.
8. Un testigo detecta una inconsistencia pero no la denuncia.
9. Conformidad no es seguridad. Un agente puede conformar con un contrato malo.
10. El contrato derivado hereda los errores de la declaración de la que se deriva.

---

## Los contratos publicados

3 documentos de esquema viajan en el paquete: una familia, un emisor vivo.

| Contrato | Estado | Lo emite |
|---|---|---|
| `trace/v3` | **vivo** | `actaira scan`, `actaira watch` |
| `trace/v2` | historia congelada - se lee, no se escribe | nada |
| `trace/v1` | historia congelada - se lee, no se escribe | nada |

Una revisión congelada se queda en disco para que un documento escrito por una
build anterior siga parseando. No es un contrato contra el que un consumidor deba
esperar documentos nuevos, y un test afirma que nadie la emite.
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) registra qué sustituyó a cada
una y por qué.

**`trace/v3` es la última revisión antes de publicar.** Tres revisiones en tres
días fueron la regla de versionado funcionando mientras nadie consumía el
formato. Desde que esto se instale en algún sitio, la exención de «nadie lo
usaba» deja de estar disponible, porque alguien lo usa.

Los nombres de campo siguen las convenciones semánticas GenAI de OpenTelemetry.
No inventamos vocabulario donde ya existe.

---

## Cómo se sostiene el repositorio

```bash
make all      # lint, test, figures, release-check
```

La puerta de release rechaza un árbol cuyas partes se contradicen entre sí: una
cifra que se desvió de lo que el código mide, una nota de diseño que apunta a una
línea que no la argumenta, una versión de esquema escrita en dos sitios, un
documento que nombra un test que ya no existe.

1.567 tests sobre 23.932 líneas de Python corren en cada commit, y las dos cifras las
mide `make figures` en vez de escribirlas a mano: la puerta rechaza un árbol
donde un número de este fichero no coincide con lo que el código reporta.

Una comprobación merece nombre propio porque es nueva y es el tema de esta
release. **Todo módulo del paquete tiene que ser alcanzable desde la CLI o desde
el servidor MCP, y `tests/test_reachability.py` falla con uno que no lo sea.**
Antes de que ese test existiera, casi la mitad de este árbol no se alcanzaba
desde ningún comando.

---

## El resto de la documentación

| | |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Qué es Actaira, las invariantes, y las reglas que sigue el trabajo. El único documento de gobierno. |
| [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) | Qué se promete entre versiones, y qué no. |
| [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) | La frontera entre este núcleo abierto y la plataforma alojada. |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Cada decisión de diseño con su alternativa rechazada, cada una nombrando el fichero y la línea que la implementa. |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Qué puede y qué no puede hacerle un atacante a un acta. |
| [`docs/ENGINEERING.md`](docs/ENGINEERING.md) | Las puertas, el trinquete de tipos, y el registro de defectos. |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Defectos conocidos y trabajo aplazado, con su reproducción. |

---

## Alcance

Este repositorio es el núcleo abierto: la CLI, el formato de traza, los paquetes
de reglas, el informe, y en su momento el colector autoalojable. La plataforma
alojada es un producto separado, en otro repositorio, con otra licencia, que
consume las actas que este produce y no contiene nada de este. Ver
[`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

## Contribuir y licencia

[`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md),
[`SECURITY.md`](SECURITY.md). Licenciado bajo [Apache-2.0](LICENSE).
