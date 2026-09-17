<div align="center">

**Control de cambios de lo que tus agentes de IA pueden hacer.**

Actaira lee la configuración que cargan tus agentes de código, resuelve lo que de verdad les permite hacer, y dice qué cambió entre dos momentos.

**Actaira 3.0.0** · Python 3.11 · 3.12 · 3.13 · Apache-2.0 · una dependencia en tiempo de ejecución · sin conexión, sin telemetría, sin cuenta

**[English](README.md)** · [Quickstart](#quickstart) · [Los cuatro comandos](#los-cuatro-comandos) · [Niveles de captura](#niveles-de-captura) · [Lo que Actaira se niega a hacer](#lo-que-actaira-se-niega-a-hacer) · [Límites](#límites-publicados) · [Docs](#el-resto-de-la-documentación)

</div>

---

## Qué es esto

Un agente abre tu repositorio. Antes de que escribas nada ya ha leído un fichero
de ajustes que puede registrar un hook para ejecutarse al abrir sesión, una
lista de servidores MCP a los que conectarse, un conjunto de permisos, una
política de sandbox y un fichero de instrucciones. Esos ficheros llegan de
varios ámbitos a la vez (gestión, usuario, proyecto, local) y cada fabricante
documenta sus propias reglas para mezclarlos. La respuesta a «qué puede hacer
este agente aquí» no está escrita en ninguno de ellos.

Actaira lee esos ficheros, resuelve a qué suman, nombra cada capacidad con la
regla que la encontró, y dice qué ha cambiado desde la última vez.

No es un escáner de modelos. No es una plataforma de observabilidad. No es una
herramienta de cumplimiento. No es un EDR: no vigila en ejecución y no bloquea.

### El objetivo, y dónde está de verdad

Actaira afirma exactamente tres cosas y nada más. Cualquier cosa fuera de esas
tres es un defecto de producto, aunque sea verdad.

**Ninguna de las tres está construida.** Se enuncian aquí igualmente, en el
sitio donde se describiría un producto terminado, porque la alternativa es una
página que describe en presente una intención, que es justo el defecto que este
proyecto se pasó la fase A.1 quitando y no una costumbre que conservó. Lo que el
árbol sí sabe hacer hoy está más abajo, en [los cuatro
comandos](#los-cuatro-comandos).

**1. Superficie** - lo que un agente puede hacer en este repositorio o en esta
máquina, resuelto entre ámbitos y fabricantes. Cada capacidad cita el fichero
del que sale, la regla de mezcla documentada que la resolvió, con la URL y la
versión de la documentación del fabricante que la enuncia, y la regla de Actaira
que la nombra.

> **No existe.** En este árbol no hay lector, ni resolución de ámbitos, ni
> paquete de reglas. `actaira check` llega en la fase S1, para Claude Code y sus
> cuatro ámbitos; la fase S2 añade Codex, Cursor, Gemini CLI, el fichero de
> tareas de VS Code, el devcontainer y AGENTS.md.

**2. Cambio** - qué capacidad aparece, desaparece, se ensancha o se estrecha
entre dos momentos.

> **No existe.** `actaira diff`, la línea base firmada que escribe `actaira
> seal`, el informe y la acción de GitHub llegan en la fase S3. La fase S4 añade
> la línea base de máquina, que es donde un hook plantado en el ámbito de
> usuario y no en un repositorio se vuelve visible siquiera.

**3. Vigencia** - si una aprobación o una evidencia sigue describiendo lo que
hay. Ligada a digests, nunca a nombres y nunca a fechas.

> **No existe**, y es la única de las tres que ya tiene su argumento escrito:
> [`docs/DESIGN.md`](docs/DESIGN.md) §10 conserva el razonamiento de los cinco
> estados de evidencia y de la sustitución ligada a un digest en vez de al
> nombre del sujeto, del paquete `state/` que la fase A quitó por inalcanzable.
> Su consumidor es la fase P1.

Y lo que ninguna de las tres puede afirmar, dicho aquí en vez de dejarlo a la
deducción: **la configuración declara; no demuestra comportamiento.** Un hook
escrito no es un hook que se ejecutó, y un hook ausente no prueba que no se
ejecutara nada. Lo que no se pudo resolver es INDETERMINADO, se cuenta aparte, y
nunca se reparte entre las respuestas que sí se pudieron dar.

Lo que este árbol hace hoy no es ninguna de las dos: lee lo que un agente grabó
sobre una ejecución, y graba una desde fuera del agente donde puede. Esa es la
[escalera de captura](#niveles-de-captura) de abajo, y se conserva porque un
cambio en una configuración y las sesiones que corrieron después son la misma
pregunta hecha dos veces.

---

## Quickstart

Cinco minutos, sin ningún agente instalado, sin red.

```bash
git clone https://github.com/marcosmatalab/actaira
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

Ese bloque es el estilo de la casa en miniatura. Leyó una sesión, dijo lo que
vio, y a continuación dijo - sin que nadie se lo pidiera - que lo que acababa de
leer no puede sostener la afirmación que un lector le atribuiría.

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

Esa es la lista completa de lo que funciona, y `actaira --help` imprime los
mismos cuatro. [`CLAUDE.md`](CLAUDE.md) enumera siete, y cada uno que no está
construido lleva escrita la fase en la que llega; `tests/test_cli.py` falla con
un nombre de esa lista que ni existe en el parser ni dice cuándo llegará.

### `actaira watch` - grabar desde fuera

`watch` pone un proxy MCP entre el agente y sus servidores de herramientas,
ejecuta tu comando, y ensambla lo que el proxy vio en una sola traza.

```console
$ actaira watch -- python -c "print('agent ran')"

agent ran
Recorded session <session-id> at capture level L1
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
  wrote the trace and its digest to actaira-trace
```

Lee esa salida otra vez, porque es el diseño. No se observó nada, y la
herramienta lo dijo de tres maneras distintas en vez de escribir una traza
limpia y vacía. Un testigo que informa del silencio como «no pasó nada» es peor
que no tener testigo, porque alguien se va a fiar de él.

`actaira-trace/` guarda después la traza en JSON, un `.sha256` al lado, y un
`index.json`. Con `--out` van a otro sitio. El id de sesión es un uuid nuevo en
cada ejecución, y por eso arriba está escrito `<session-id>`: todos los demás
caracteres de ese bloque los compara `tests/test_readme_parity.py` contra la
salida real.

Apúntalo a un agente real con su configuración MCP y el mismo comando graba las
llamadas a herramientas:

```bash
actaira watch --mcp-config .mcp.json -- claude -p "refactoriza el módulo de auth"
```

`--with-content` conserva los argumentos y resultados literales. Sin él, los
argumentos viajan como digests con sal: un digest no tiene falsos negativos y un
filtro de secretos sí.

### `actaira verify` - comprobar sin confiar en nadie

> **Lee esto antes de probarlo: ningún comando de Actaira 3.0 produce un
> paquete.** `verify` lee paquetes de atestación escritos por el escáner de
> modelos 2.x, y el comando que los escribía (`actaira attest`) se fue a
> `archive/model-scanner`. El escritor sigue en el árbol -
> `attest/package.py::write_package` - y no lo llama nada fuera de los tests.
> Así que `verify` es un lector sin escritor en esta release: útil si tienes un
> paquete 2.x en la mano, inútil si no, y se conserva porque el día que este
> árbol firme algo propio, que es la línea base de superficie que escribe
> `actaira seal` en la fase S3, el verificador es la mitad que ya tiene que
> estar bien.
>
> `tests/test_reachability.py` no coge esto. Pregunta si todo módulo es
> alcanzable desde un comando, y `attest/` lo es: `verify` llega a todo él. No
> pregunta si la cadena del producto se cierra, es decir si algo que esta
> herramienta escribe es algo que esta herramienta puede verificar.
> `docs/BACKLOG.md` lleva la línea.

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

Ed25519. El llavero vive al lado de la clave. Mismo matiz que en `verify`: esto
gestiona la clave que firma un paquete, y en la 3.0 no hay nada que escriba uno.
La rotación y la revocación las ejercita la suite de punta a punta, contra
paquetes que construye ella misma.

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
y la nombra. Todo hallazgo publica el id de la regla, su versión, su paquete y
su autor. De aquí se sigue: prohibido llamar a un modelo en el camino de
decisión. Un LLM puede ayudar a redactar una regla; no puede evaluarla, y tampoco
puede escribir su remediación.

**3. Nunca inferir lo no observado.** Si lo que se leyó no cubría algo, el
informe lo dice. Un predicado sin información devuelve INDETERMINADO, jamás
False. Cada regla declara lo que necesita para responder, y por debajo de eso
devuelve INDETERMINADO sola, sin que nadie se acuerde de comprobarlo.

**4. Nunca actuar sobre lo que se observa.** Actaira *sugiere* la remediación
que trae su regla, nunca la aplica. Un testigo que además actúa no puede dar fe
de sus propios actos, y ese conflicto de interés es exactamente lo que nos
separa de un proveedor de observabilidad. Si algún día existe un `--apply`, el
cambio queda registrado como un hallazgo más, atribuido a Actaira, y se evalúa
como cualquier otro. Silencioso, jamás. Un código de salida **informa**: si un
pull request se bloquea o no lo decide la protección de rama del usuario, que es
suya. Salir con código distinto de cero no es actuar; escribir en el árbol del
usuario sí.

> **Tres de estas cuatro son restricciones sobre código que aún no está
> escrito.** En este árbol no hay reglas, ni predicados, ni remediaciones: la
> segunda negativa no tiene regla que citar, la tercera no tiene predicado que
> devuelva INDETERMINADO, y la cuarta no tiene remediación que negarse a
> aplicar. Están escritas ahora, antes de que exista el código, porque una
> restricción que se adopta después se discute; y la tercera ya sostiene peso en
> lo que sí existe: `scan --demo` declara que a nivel L0 la autenticidad no se
> puede evaluar, y `watch` declara los huecos por los que no pudo ver en vez de
> informar de una ejecución limpia.
>
> La primera negativa sí se aplica hoy, sobre todos los documentos que este
> árbol emite, en `tests/test_no_aggregate.py`.

---

## Límites publicados

Están en el README, en la web y en el propio informe. No se ablandan para vender
mejor. Los diez primeros son de lo que mirar una **ejecución** no puede enseñar,
que es `scan` y `watch`; los cuatro últimos son de lo que leer una
**configuración** no puede enseñar, y llegan con la superficie.

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
9. No disparar ninguna regla no es seguridad. Un repositorio puede no producir
   un solo hallazgo y estar mal configurado por una razón que ninguna regla
   nombra.
10. Lo resuelto hereda los errores de aquello de lo que se resuelve. Una
    superficie efectiva calculada sobre la configuración equivocada es una
    respuesta correcta a la pregunta equivocada.
11. **La configuración no es el comportamiento.** Que una capacidad esté
    declarada no prueba que se ejerciera, y su ausencia no prueba que no
    ocurriera nada.
12. **Solo vemos lo que está en disco.** La configuración que un fabricante
    empuja desde un servidor sin dejar fichero es invisible para nosotros, y eso
    se declara en vez de tratarse como ausencia.
13. **La semántica de mezcla depende de la versión del agente.** Sin versión
    conocida, la capacidad que dependa de ella sale INDETERMINADA; no se resuelve
    con la versión que parezca más probable.
14. **Un script referenciado puede cambiar después de leído.** Por eso todo se
    liga a su digest y no a su ruta: una aprobación sobre un nombre de fichero es
    una aprobación sobre lo que haya ahí mañana.

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

1.566 tests sobre 23.940 líneas de Python corren en cada commit, y las dos cifras las
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
| [`docs/archive/`](docs/archive/) | La documentación del escáner de modelos, archivada sin editar en la fase A.1: formatos, evaluación, arquitectura, modelo de amenazas, las dos páginas de conceptos y las secciones de diseño que las argumentan. Nada de eso describe este árbol. |
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
