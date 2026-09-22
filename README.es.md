<div align="center">

**Control de cambios de lo que tus agentes de IA pueden hacer.**

Actaira lee la configuración que cargan tus agentes de código, resuelve lo que de verdad les permite hacer, y dice qué cambió entre dos momentos.

**Actaira 3.0.0** · Python 3.11 · 3.12 · 3.13 · Apache-2.0 · una dependencia en tiempo de ejecución · sin conexión, sin telemetría, sin cuenta

**[English](README.md)** · [Quickstart](#quickstart) · [Los siete comandos](#los-siete-comandos) · [Niveles de captura](#niveles-de-captura) · [Lo que Actaira se niega a hacer](#lo-que-actaira-se-niega-a-hacer) · [Límites](#límites-publicados) · [Docs](#el-resto-de-la-documentación)

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

Cada bloque de abajo dice qué existe, y cada uno nombra los comandos sobre los
que se sostiene su afirmación. Eso no es una costumbre de formato:
`scripts/release_check.py` lee esos nombres y los resuelve contra el parser, en
los dos sentidos. Un bloque que dice «construido» nombrando un comando que nadie
escribió rompe la puerta, y un comando que funciona sin que ningún bloque lo
reclame la rompe igual. Esta página publicó «No existe» sobre `actaira check`
durante una fase entera después de que ese comando llegara, porque la única
comprobación que había preguntaba si el comando estaba mencionado en algún sitio,
no si era cierto lo que la página decía de él.

**1. Superficie** - lo que un agente puede hacer en este repositorio o en esta
máquina, resuelto entre ámbitos y fabricantes. Cada capacidad cita el fichero
del que sale, la regla de mezcla documentada que la resolvió, con la URL y la
versión de la documentación del fabricante que la enuncia, y la regla de Actaira
que la nombra.

> **Construido.** Comandos: `actaira check`.
> Lee Claude Code, Codex CLI, Cursor, Gemini CLI, los ficheros de tareas y
> ajustes de VS Code, `devcontainer.json` y los ficheros de instrucciones
> AGENTS.md / CLAUDE.md / GEMINI.md. Cada fabricante se resuelve contra su propia
> precedencia documentada, y la superficie del repositorio es la unión de los
> siete, nunca una mezcla de ellos.

**2. Cambio** - qué capacidad aparece, desaparece, se ensancha o se estrecha
entre dos momentos.

> **Construido.** Comandos: `actaira diff`, `actaira seal`.
> Dos refs de git, o dos directorios, se comparan sin hacer checkout de ninguna
> de las dos. Qué aparece, qué desaparece, qué se ensancha, qué se estrecha, qué
> cambia con los dos digests, y aparte lo que no se pudo resolver en uno de los
> dos lados. La acción de GitHub y el hook de pre-commit de este repositorio son
> el mismo comando puesto donde entra el cambio. La fase S4 añade la línea base
> de máquina, que es donde un hook plantado en el ámbito de usuario y no en un
> repositorio se vuelve visible siquiera.

**3. Vigencia** - si una aprobación o una evidencia sigue describiendo lo que
hay. Ligada a digests, nunca a nombres y nunca a fechas.

> **Construido en parte.** Comandos: `actaira seal`, `actaira verify`.
> `seal` firma una línea base de una superficie que no lleva contenido, ligada al
> digest de esa superficie, y `verify` la comprueba sin conexión y sin fiarse de
> quien la produjo. O sea que hoy SÍ se puede atar una aprobación a un digest y
> SÍ se puede demostrar que dejó de describir el árbol. Lo que no existe es el
> registro que guarda esas aprobaciones y las caduca por ti:
> [`docs/DESIGN.md`](docs/DESIGN.md) §10 conserva el razonamiento de los cinco
> estados de evidencia y de la sustitución ligada a un digest en vez de al
> nombre del sujeto, del paquete `state/` que la fase A quitó por inalcanzable.
> Su consumidor es la fase P1.

Y lo que ninguna de las tres puede afirmar, dicho aquí en vez de dejarlo a la
deducción: **la configuración declara; no demuestra comportamiento.** Un hook
escrito no es un hook que se ejecutó, y un hook ausente no prueba que no se
ejecutara nada. Lo que no se pudo resolver es INDETERMINADO, se cuenta aparte, y
nunca se reparte entre las respuestas que sí se pudieron dar.

**Fuera de las tres afirmaciones**, y dicho aquí en vez de dejarlo sin cuadrar.
Dos comandos leen lo que un agente HIZO y no lo que puede hacer, y uno gestiona
una clave. No implementan ninguna de las tres afirmaciones de arriba, y una
página que simplemente no los mencionara sería una página cuyo silencio tiene
que interpretar quien la lee.

> **Fuera de las tres afirmaciones.** Comandos: `actaira scan`, `actaira watch`,
> `actaira keygen`.
> `scan` y `watch` son la [escalera de captura](#niveles-de-captura), que va de
> una ejecución y no de una configuración; `keygen` gestiona la clave con la que
> firma `seal`. Se conservan porque un cambio en una configuración y las
> sesiones que corrieron después son la misma pregunta hecha dos veces.


---

## Quickstart

Cinco minutos, sin ningún agente instalado, sin red.

```bash
git clone https://github.com/marcosmatalab/actaira
cd actaira
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Una dependencia en tiempo de ejecución (`cryptography`). Después, para qué sirve
el producto, sobre la oleada de keyv del 4 de agosto de 2026 reconstruida desde
los informes publicados. El guion construye un repositorio desechable con dos
commits (limpio, y después comprometido) y los diferencia:

```console
$ python3 scripts/demo_keyv.py --lang es    # exits 1: una regla disparó sobre algo que llegó

Que ha cambiado entre HEAD~1 y HEAD

APARECE: 1
  + claude-code  hook.command  .claude/settings.json  [project]
      despues  effective  63a9a33e2cd93139
      ! ACT-S001  Un hook ejecuta un comando en un evento de arranque de sesión, así que abrir una sesión lo ejecuta antes de que nadie haya leído nada.
        regla escrita por  Actaira core core / high
        sugerido por la regla: Remove the hook, or move it to ~/.claude/settings.json where it is yours rather than the repository's. A hook on a session-start event runs before you have read anything.
      ! ACT-S003  Un hook ejecuta un script de este repositorio, así que quien pueda meter un commit decide qué se ejecuta.
        regla escrita por  Actaira core core / medium
        sugerido por la regla: Tie your approval to the script's sha256 rather than its path: the file at that path can change after you read it, and the hook will run whatever is there.

No se pudo resolver en uno de los dos lados: 2
  ? ACT-S016 on task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)
  ? a change to vscode task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)

Identicas en los dos lados: 0
Visto y no leído en esta versión: 7

La configuración DECLARA; no demuestra comportamiento. Un hook escrito no es un hook que se ejecutó, y uno ausente no prueba que no se ejecutara nada (límite publicado 11).
```

Lee la mitad sin resolver, porque es el diseño. El gusano planta dos cosas y
esto dice algo de las dos: el hook de Claude Code sale EFECTIVO y lo nombran dos
reglas, y la tarea de `.vscode/tasks.json` sale INDETERMINADA, porque si se
ejecuta o no lo decide un ajuste que solo puede tener la máquina del usuario, así
que un repositorio no puede responderlo y esto se niega a adivinarlo. Contado
aparte, nunca mezclado.

La reconstrucción está en `tests/fixtures/surface/keyv-august/`, su fichero de
procedencia cita la frase de la que sale cada fragmento, y el `setup.mjs` al que
apunta el hook es un stub inerte. Un repositorio de seguridad que repartiera la
carga del gusano para demostrar que caza al gusano sería el gusano.

Y sin ningún agente instalado y sin nada configurado:

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
vio, y a continuación dijo, sin que nadie se lo pidiera, que lo que acababa de
leer no puede sostener la afirmación que un lector le atribuiría. Con `--lang es`
la salida sale en español.

---

## Los siete comandos

```
actaira check     lee la configuración de agentes de este repo y resuelve qué permite
actaira diff      dice qué capacidad cambió entre dos momentos
actaira seal      firma una línea base de la superficie, sin llevar contenido
actaira verify    verifica un paquete firmado sin conexión
actaira keygen    crea, rota o revoca una clave de firma
actaira scan      lee las sesiones que un agente ya grabó en esta máquina (L0)
actaira watch     graba una ejecución desde fuera del agente, por un proxy MCP (L1)
```

Esa es la lista completa de lo que funciona: 7 comandos de CLI, y `actaira
--help` imprime los mismos siete. [`CLAUDE.md`](CLAUDE.md) enumera siete y topa
la lista en ocho, así que por primera vez no queda ningún nombre prometido en
ella; `tests/test_cli.py` falla con un nombre de esa lista que ni existe en el
parser ni dice cuándo llegará, y con uno que existe y sigue llevando una fase.

### `actaira check` - qué puede hacer un agente aquí

`check` lee la configuración de agentes de este repositorio, resuelve qué
permite de verdad entre ámbitos y entre fabricantes, y aplica los paquetes de
reglas. Lee Claude Code, Codex CLI, Cursor, Gemini CLI, `.vscode/tasks.json` y
`.vscode/settings.json`, `devcontainer.json`, y los ficheros de instrucciones
AGENTS.md, CLAUDE.md y GEMINI.md, contra 32 reglas documentadas.

Cada fabricante se resuelve contra la precedencia que publica su propia
documentación, porque esas escaleras no coinciden: Claude Code pone el fichero
del usuario por encima del del proyecto, Gemini CLI pone el del proyecto por
encima del del usuario, y VS Code pone el del espacio de trabajo por encima de
los dos. La superficie de un repositorio es por tanto la UNIÓN de las siete
superficies por fabricante, y dos fabricantes que configuran el mismo servidor
MCP son dos capacidades con el mismo digest, no una fila que no es de ninguno.

Lo que sigue sin leerse se imprime, no se salta, incluidos los dos ámbitos que
no dejan fichero alguno: los hooks de equipo de Cursor, configurados en un panel
y sincronizados a los miembros, y los requisitos de Codex que llegan por MDM o
desde la nube. Esos salen INDETERMINADOS con su causa, nunca como ausencia.

```
actaira check                                   # este repositorio
actaira check --machine                         # y los ámbitos de usuario y gestionado
actaira check --agent-version claude-code=2.1.257
actaira check --json                            # un documento surface/v1
actaira check --html informe.html               # un solo fichero, sin red
```

Tres cosas que no hará. Nunca ejecuta lo que lee: de un script al que apunta un
hook registra cuatro hechos (si existe, si está dentro del árbol, si lo controla
git y su sha256) y jamás un quinto. No imprime literales de comandos, URLs ni
cabeceras sin `--with-content`, porque un fichero de configuración puede llevar
un secreto y este informe se pega en un log de CI. Y nunca adivina: una
capacidad cuya respuesta dependa de una versión del agente que nadie declaró
sale INDETERMINADA con el umbral nombrado, y se cuenta aparte de todo lo demás.

Códigos de salida: `0` no disparó nada y no quedó nada sin resolver, `1` disparó
una regla, `3` no disparó nada y algo no se pudo resolver.

### `actaira diff` - qué ha cambiado

```
actaira diff main HEAD                          # dos refs de este repositorio
actaira diff --repo ../otro main feature        # de otro sitio
actaira diff --from-dir a --to-dir b            # dos árboles, sin git
actaira diff main HEAD --html informe.html      # y el mismo informe como página
actaira diff main HEAD --sarif actaira.sarif    # SARIF 2.1.0 para un host de código
```

De ninguna de las dos refs se hace checkout. Los dos árboles se leen con
`git ls-tree` y `git cat-file`, que no ejecutan ningún hook, no aplican ningún
filtro ni ningún driver de textconv, y se escriben en un directorio temporal que
se borra al salir. Tu árbol de trabajo no se toca, tu HEAD no se mueve, y a un
hook `post-checkout` del repositorio que se está examinando no se le da nunca la
ocasión de ejecutarse, que sería ejecutar código de otro para responder una
pregunta sobre código de otro. Una ref que empieza por guion se rechaza con
código de salida `2`.

Cinco tipos de cambio, y una sexta cosa que no es uno de ellos. Una capacidad
APARECE, DESAPARECE, SE ENSANCHA, SE ESTRECHA o CAMBIA; y si uno de los dos lados
no se pudo resolver, el cambio es INDETERMINADO, va en su propia lista con su
causa y nunca se cuenta con los cinco. Ensancharse y estrecharse solo existen
donde el nombre del propio hecho dice cuál de los dos valores es el más ancho,
como `guardrail_removed` pasando de false a true. En todo lo demás la respuesta
es CAMBIA, con los dos digests, para que quien revisa decida por su cuenta en vez
de que le digan qué pensar de los ajustes de un fabricante.

Códigos de salida: `1` una regla disparó sobre algo añadido o ensanchado, `3`
ninguna regla disparó y algo no se pudo resolver, `0` en el resto, `2` error de
uso. Un hallazgo que ya estaba y sigue estando no es ninguno de estos: para eso
está `check`, y un comando que responde «qué ha cambiado» no debe objetar a lo
que no cambió.

### En un pull request: la acción y el hook de pre-commit

La acción es este repositorio. `uses: marcosmatalab/actaira@<sha>` instala la
herramienta desde el ref que fijaste y ejecuta `diff` entre la base y la cabeza
del pull request:

```yaml
name: actaira
on: pull_request
permissions:
  contents: read
jobs:
  surface:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09  # v5
        with:
          fetch-depth: 0       # diff necesita los dos lados, o sea la historia entera
          persist-credentials: false
      - uses: marcosmatalab/actaira@c0a33675c14b8a622ddb794ab3f516a514e3124d
```

**Los dos `uses:` van fijados por SHA de commit, y eso no es decoracion.** Una
etiqueta es un nombre y un nombre se mueve, que es lo que ACT-S003 le dice al
mundo sobre sus propios servidores MCP y sus hooks; un ejemplo que te dijera
`@main` seria esta herramienta pidiendote lo que senala en tu repositorio.
Para volver a resolver uno: `gh api repos/<owner>/<repo>/git/ref/tags/<tag>
--jq .object.sha`.

Escribe el informe en el resumen del trabajo y SARIF 2.1.0 en `actaira.sarif`;
subirlo a code scanning es cosa tuya, con `github/codeql-action/upload-sarif` y
`security-events: write`. El código de salida pasa tal cual (no hay ningún
`|| true` en ninguna parte), así que una regla que disparó sobre algo nuevo hace
fallar el trabajo, y si eso bloquea el merge lo decide tu protección de rama, que
es tuya.

`comment: true` publica el mismo resumen como comentario del pull request y
necesita `pull-requests: write`. Está apagado por defecto, porque la mayoría de
los flujos no deberían tener ese permiso y el resumen del trabajo no necesita
ninguno.

**Úsala con `pull_request`. No con `pull_request_target` haciendo checkout de la
cabeza.** Esa combinación le da al código de un fork un token con escritura y tus
secretos, y ningún cuidado tomado dentro de la acción lo cambia. Cada entrada
llega al shell por `env` en vez de pegarse dentro de un script con `${{ }}`, cada
acción de terceros de los flujos de este repositorio está fijada por SHA de
commit, y `zizmor` corre sobre `action.yml` y `.github/workflows/` en cada build.

Para un hook local, este repositorio publica uno:

```yaml
repos:
  - repo: https://github.com/marcosmatalab/actaira
    rev: c0a33675c14b8a622ddb794ab3f516a514e3124d
    hooks:
      - id: actaira-check
```

`check` y no `diff`, porque `pre-commit` tiene un árbol delante y un diff
necesita dos momentos. El sitio donde existen dos momentos es el pull request.

### `actaira seal` - una línea base firmada sin contenido dentro

```bash
actaira keygen                                  # una vez
actaira seal --repo . --key ~/.actaira/signing-key.pem --out baseline/
actaira verify baseline/surface-seal.zip
```

`seal` escribe un paquete firmado con un documento `seal/v1` dentro: de cada
capacidad, su fabricante, su nombre, su ámbito, su resolución y su regla de
mezcla, una referencia con sal al fichero del que salió, y un sha256 sobre todo
lo que observó. Más las reglas que dispararon, cada una con su autor y su
paquete. Más recuentos de lo que no se pudo resolver y de lo que no se leyó. Eso
es todo.

**Ni rutas, ni comandos, ni URLs, ni nombres de servidores.** Una ruta se vuelve
`H(sal || dominio || ruta)`, y la sal se queda contigo en el directorio de
salida, al lado del paquete y nunca dentro de él; el paquete lo dice con sus
propias palabras. Todo lo que una capacidad observó se vuelve un digest del mapa
de hechos entero en vez de un digest por hecho, porque `sha256(".env")` son los
mismos dieciséis caracteres en todas las máquinas que han existido.

De lo que va todo esto es del digest de superficie de arriba. Aprueba ese, y la
aprobación caduca sola el día que la superficie cambie, que es el límite
publicado 14 con el signo cambiado, y la razón de que aquí nada esté ligado a un
nombre de fichero ni a una fecha.

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

```bash
actaira verify baseline/surface-seal.zip
actaira verify baseline/surface-seal.zip --trusted-keyring keys.json --require-trust
```

Sin conexión, siempre. Integridad e identidad son respuestas separadas: un
paquete siempre lleva su propia clave, así que la integridad siempre se puede
responder, y «nadie ha avalado esta clave» se informa como exactamente eso y no
como un fallo. Pasa `--trusted-keyring` o `--pubkey` para atarlo a una clave en
la que ya confías.

Además nombra qué ha verificado. Un paquete cuyas entradas declaran `seal/v1` se
comprueba contra los campos que ese contrato exige y la versión se informa; uno
que declara una versión que esta release no publica falla, en vez de darse por
bueno con su significado adivinado. Los paquetes que escribió el escáner de
modelos 2.x siguen verificando, y no declaran contrato alguno, que no es un
defecto suyo.

### `actaira keygen` - la clave de firma

```bash
actaira keygen                      # crear
actaira keygen --rotate             # retirar la clave actual, seguir verificando lo antiguo
actaira keygen --revoke <key-id>    # nada de lo que firmó se acepta nunca más
```

Ed25519. El llavero vive al lado de la clave. Esta es la clave con la que firma
`actaira seal`; la rotación y la revocación las ejercita la suite de punta a
punta.

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

> **Las cuatro se aplican hoy sobre código que existe.** No era así, y la nota
> que había aquí lo decía: hasta que llegaron los paquetes de reglas no había
> reglas, ni predicados, ni remediaciones, así que tres de las cuatro no tenían
> nada que restringir. Ahora sí, y cada una tiene su propiedad afirmada encima:
> la primera en `tests/test_no_aggregate.py` sobre todos los documentos que este
> árbol emite, la segunda en cada hallazgo llevando el autor y el paquete de su
> regla, la tercera en `Clause.holds` devolviendo None ante un hecho que nadie
> escribió, y la cuarta en `diff` leyendo dos árboles sin hacer checkout de
> ninguno.

---

## Límites publicados

Están en el README, en la web y en el propio informe. No se ablandan para vender
mejor. Diez son de lo que mirar una **ejecución** no puede enseñar, que es
`scan` y `watch`; cuatro son de lo que leer una **configuración** no puede
enseñar, y llegaron con la superficie; y los dos últimos vuelven a ser de
`watch`, uno de ellos sobre la plataforma en la que se escribe este árbol.

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
15. **En Windows un transporte cerrado parece uno callado.** Un servidor que
    cierra su transporte estando vivo no se distingue de uno que simplemente ha
    dejado de hablar: el sistema operativo no entrega EOF al lector mientras el
    proceso que escribe sigue vivo, así que el hueco se llama `upstream_timeout`
    y no `transport_closed`. La ejecución se graba y el hueco se declara
    igualmente; lo que se pierde es cuál de las dos cosas pasó. En la práctica un
    cliente que se cansa antes del plazo del propio proxy deja además
    `end_not_recorded`, que no es de la plataforma: es lo que informa cualquier
    proxy al que matan, y es la verdad.
16. **El proxy no contesta por un servidor que no contestó.** Cuando un servidor
    no responde, `watch` graba el hueco y no reenvía nada, así que un cliente MCP
    sin plazo propio se queda esperando. Escribirle un error de plazo agotado
    metería en la entrada del agente un mensaje que ningún servidor mandó, y el
    agente no podría distinguirlo de uno real: un testigo no actúa sobre lo que
    observa.

---

## Los contratos publicados

El paquete lleva 6 documentos de esquema: 4 contratos versionados vivos,
y 2 versiones sustituidas que se leen y no se escriben nunca.

| Contrato | Estado | Lo emite |
|---|---|---|
| `surface/v1` | **vivo** | `actaira check` |
| `surface-diff/v1` | **vivo** | `actaira diff` |
| `seal/v1` | **vivo** | `actaira seal` |
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
documento que nombra un test que ya no existe, un flag que la documentación
enseña y el comando no tiene, y una afirmación de esta página que el parser
contradice.

2.504 tests corren en cada commit sobre 15.803 líneas de código de producto, de
las 38.648 líneas de Python que hay en el árbol contando la suite y los scripts.
Cada cifra de aquí la mide `make figures` en vez de escribirse a mano: la puerta
rechaza un árbol donde un número de este fichero no coincide con lo que el código
reporta.

Una comprobación merece nombre propio porque es el tema de esta release. **Todo
módulo del paquete tiene que ser alcanzable desde la CLI o desde el servidor MCP,
y `tests/test_reachability.py` falla con uno que no lo sea.** Antes de que ese
test existiera, casi la mitad de este árbol no se alcanzaba desde ningún comando.

---

## El resto de la documentación

| | |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Qué es Actaira, las invariantes, y las reglas que sigue el trabajo. El único documento de gobierno. |
| [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) | Qué se promete entre versiones, y qué no. |
| [`docs/RULES.md`](docs/RULES.md) | Cada regla, con su autor, su versión, los hechos que necesita y su configuración violadora. Generada desde los paquetes. |
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
