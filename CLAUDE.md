# Actaira

## Qué es

Actaira es el control de cambios de lo que los agentes de código pueden hacer.
Lee la configuración de Claude Code, Codex, Cursor, Gemini CLI, VS Code y el
devcontainer; resuelve entre ámbitos y fabricantes lo que de verdad pueden
hacer; dice qué ha cambiado entre dos momentos; y ata las aprobaciones al
digest de lo que se aprobó, de forma que caducan solas cuando eso cambia.

No es un escáner de modelos. No es una plataforma de observabilidad. No es una
herramienta de compliance. No es un EDR: no vigila en ejecución y no bloquea.
Si una decisión de diseño solo tiene sentido bajo una de esas cuatro
descripciones, está mal.

Por qué el producto es este y no el anterior, con las tres alternativas que se
descartaron antes de llegar aquí y la fuente de cada descarte: `docs/DESIGN.md`
§11, nota de diseño D-269.

## Las tres afirmaciones del producto

Actaira afirma exactamente esto y nada más:

1. SUPERFICIE. Lo que un agente puede hacer en este repo o en esta máquina,
   resuelto entre ámbitos y fabricantes. Cada capacidad cita el fichero de
   donde sale, la regla de mezcla documentada que la resolvió (con la URL y la
   versión de la documentación del fabricante) y la regla de Actaira que la
   nombra.
2. CAMBIO. Qué capacidad aparece, desaparece, se ensancha o se estrecha entre
   dos momentos.
3. VIGENCIA. Si una aprobación o una evidencia sigue describiendo lo que hay.
   Se liga a digests, nunca a nombres ni a fechas.

Cualquier afirmación fuera de estas tres es un defecto de producto, aunque sea
verdadera.

Y lo que ninguna de las tres puede afirmar, dicho aquí para que no haga falta
deducirlo: la configuración DECLARA, no demuestra comportamiento. Que un hook
esté escrito no prueba que se ejecutara, y que no lo esté no prueba que nada se
ejecutara. Lo que no se pudo resolver es INDETERMINADO, se cuenta aparte y
nunca se reparte entre las respuestas que sí se pudieron dar.

## Los tres estados de resolución de una capacidad

  DECLARADO       está escrito en un fichero, y se cita cuál
  EFECTIVO        resuelto entre ámbitos, con la versión del agente conocida
  INDETERMINADO   no se pudo resolver, con la causa nombrada

Los cuatro niveles de captura de abajo no se van: siguen gobernando `scan` y
`watch`, que son lo que mira una ejecución. Estos tres gobiernan lo que mira un
fichero. Un documento que mezcle los dos vocabularios está confundiendo lo que
un agente PUEDE hacer con lo que un agente HIZO.

## Las cuatro negativas

Son invariantes. Un cambio que las viole se rechaza sin discusión.

1. NUNCA UN NÚMERO. No hay score, grade, rating, percent, confidence ni ranking
   en ningún documento emitido. El test que greppea esas palabras se mantiene y
   se amplía, nunca se relaja. Una regla puede traer una `severity` escrita por
   el autor de su paquete: eso es una etiqueta atribuida, no un cálculo de
   Actaira, y NO se agrega ni se suma con otras.
2. NUNCA JUZGAR, SOLO CITAR. Actaira no tiene opinión sobre lo que un agente
   debería haber hecho. Solo compara lo observado contra una norma ESCRITA POR
   OTRO, y la nombra. Todo hallazgo publica el id de la regla, su versión, su
   paquete y su autor. De aquí se sigue lo de siempre: prohibido llamar a un
   modelo en el camino de decisión. Un LLM puede ayudar a redactar una regla;
   no puede evaluarla, y tampoco puede escribir su remediación.
3. NUNCA INFERIR LO NO OBSERVADO. Si lo que se leyó no cubría algo, el informe
   lo dice. Un predicado sin información devuelve INDETERMINADO, jamás False.
   Cada regla declara lo que necesita para responder; por debajo de eso la
   regla devuelve INDETERMINADO sola, sin que nadie se acuerde de comprobarlo.
4. NUNCA ACTUAR SOBRE LO QUE SE OBSERVA. Actaira SUGIERE la remediación que
   trae la regla, nunca la aplica por su cuenta. Un testigo que además actúa no
   puede dar fe de sus propios actos, y ese conflicto de interés es exactamente
   el que nos separa de los proveedores de observabilidad. Si algún día existe
   un `--apply`, el cambio queda registrado como un hallazgo más, atribuido a
   Actaira, y el motor lo evalúa como cualquier otro. Silencioso, jamás.
   Un código de salida INFORMA: bloquear o no lo decide la protección de rama
   del usuario, que es suya. Salir con código distinto de cero no es actuar;
   escribir en el árbol del usuario sí.

## Los límites publicados

Van en el README, en la web y en el propio informe. No se ablandan para vender
mejor. Los diez primeros son de lo que mira una EJECUCIÓN, que es `scan` y
`watch`. Los cuatro últimos son de lo que mira la CONFIGURACIÓN, y llegan con
la superficie.

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
9. No disparar ninguna regla no es seguridad. Un repo puede no tener un solo
   hallazgo y estar mal configurado por una razón que ninguna regla nombra.
10. Lo resuelto hereda los errores de aquello de lo que se resuelve. Una
    superficie efectiva calculada sobre una configuración equivocada es una
    respuesta correcta a la pregunta equivocada.
11. LA CONFIGURACIÓN NO ES EL COMPORTAMIENTO. Que una capacidad esté declarada
    no prueba que se ejerciera, y que no lo esté no prueba que no ocurriera.
12. Solo se ve lo que está en disco. La configuración que un fabricante empuja
    desde un servidor sin dejar fichero es invisible para nosotros, y eso se
    declara en vez de tratarse como ausencia.
13. La semántica de mezcla depende de la versión del agente. Sin versión
    conocida, la capacidad que dependa de ella sale INDETERMINADA; no se
    resuelve con la versión que nos parezca más probable.
14. Un script referenciado puede cambiar después de leído. Por eso todo se liga
    a su digest y no a su ruta: una aprobación sobre un nombre de fichero es
    una aprobación sobre lo que haya ahí mañana.

## Los cuatro niveles de captura

Cada acta declara con qué nivel se capturó, y el nivel decide qué puede
afirmar. Esto no es un detalle: es la diferencia entre evidencia y diagnóstico.

  L0  TRANSCRIPT DEL PROPIO AGENTE
      Lo que Claude Code, Cursor o Cline ya guardaron en disco por su cuenta.
      Trae las tool calls con sus argumentos, pero lo produjo el auditado.
      Un acta de nivel L0 NO PUEDE AFIRMAR AUTENTICIDAD. La declara como no
      evaluada, con su razón escrita. Sirve para diagnóstico y para análisis
      retrospectivo, no como prueba ante un tercero.
  L1  PROXY DE MCP
      Capturado desde fuera del agente. Ve llamadas de herramienta.
  L2  PROXY DE RED
      Ve además las llamadas al proveedor del modelo.
  L3  SANDBOX CON SECCOMP
      Ve ficheros, red y ejecución. El único que puede afirmar que no se tocó
      nada más.

Un nivel que no se emprendió no puede hacer inconcluso el veredicto. Uno que
estaba en alcance y falló, sí.

## Reglas de trabajo

1. UNA FASE, UN OBJETIVO, UNA PUERTA. La puerta se escribe antes de empezar la
   fase y es comprobable por una máquina, no por una opinión.
2. UNA SOLA PASADA ADVERSARIAL POR FASE. Esa pasada solo puede producir un
   arreglo o una línea en `docs/BACKLOG.md`. No puede producir un criterio nuevo,
   ni una decisión pendiente nueva, ni una fase nueva. Si encuentra algo que
   parece exigir un criterio nuevo, se escribe como línea de backlog y se sigue.
3. PRESUPUESTO DE FICHEROS POR FASE, declarado antes de empezar. Superarlo
   requiere que yo lo autorice explícitamente en la conversación.
   Hay TRES categorías de fichero, no dos:

   1. DISEÑO. Cuenta contra el presupuesto.
   2. FORZADO POR LA PUERTA. No cuenta: documentación que una comprobación de
      release exige, generadores que abortan sin una entrada, y tests que
      afirman el estado viejo. Cada fichero que se declare forzado TIENE QUE
      NOMBRAR en el informe la comprobación concreta que lo fuerza. Un fichero
      forzado sin su comprobación nombrada es alcance, y entonces sí cuenta.
   3. ALCANCE DESCUBIERTO A MITAD DE FASE. El objetivo de la fase se vuelve
      incoherente sin él. No cuenta contra el presupuesto, PERO OBLIGA A PARAR
      Y PREGUNTAR ANTES DE ESCRIBIRLO, y se anota en el commit con el argumento
      de por qué la fase no se sostiene sin él.

   La tercera existe porque en la 1.1b se usaron 11 de 10 y el de más fue
   `cli.py`: ninguna comprobación de la puerta lo forzaba, lo forzaba que el
   operador perdía la capacidad de encontrar su propia sesión. El argumento era
   correcto y la categoría 2 no era su sitio. Archivar alcance descubierto como
   "forzado por la puerta" por comodidad es como la categoría 2 deja de
   significar nada.
4. PROHIBIDO EMPEZAR LA FASE SIGUIENTE ANTES DE CERRAR LA ACTUAL. Aunque sea
   evidente, aunque queden tokens, aunque el cambio sea de una línea.
5. CADA DECISIÓN DE DISEÑO SE ESCRIBE CON SU ALTERNATIVA RECHAZADA Y SU PORQUÉ,
   en el propio código, en cinco líneas o menos. No en cincuenta. Un docstring
   de noventa líneas es un pasivo.
6. NINGUNA CIFRA PUBLICADA SIN UN COMANDO QUE LA MIDA. `make figures` la mide y
   el gate de release falla si deriva. Esto ya existe y se mantiene.
7. LA PUERTA SE CORRE EN WSL Y SOBRE UN CLON LIMPIO DE HEAD, nunca sobre el
   directorio de trabajo. En WSL porque Windows no tiene `make`, probar los
   cuatro comandos a mano no prueba el Makefile, y ahí no se salta el test de
   bits de permiso POSIX. Sobre un clon porque el árbol de trabajo tiene
   ficheros que no se publican: la S1 pasó en verde con dos fixtures que
   `.gitignore` excluía y `git add -A` saltó en silencio, y el rojo llegó en la
   primera CI, que es el primer clon limpio que existió. Una puerta que corre
   donde están esos ficheros no mide lo que se entrega, mide esta máquina.
   Ubuntu 24.04, GNU Make 4.3, venv en `/tmp/actaira-venv` con
   `pip install -e ".[dev]"`:
   `wsl -e bash -lc 'rm -rf /tmp/actaira-gate && git clone -q /mnt/c/Users/Usuario/Desktop/actaira /tmp/actaira-gate && cd /tmp/actaira-gate && PY=/tmp/actaira-venv/bin/python make all'`
   La variante sobre el directorio montado
   (`cd /mnt/c/... && PY=... make all`) es un ATAJO DE ITERACIÓN y jamás la
   puerta: es más rápida y responde por un árbol que nadie recibe.
   `tests/test_fixtures_are_published.py` cubre el caso concreto que lo destapó;
   el clon cubre la clase.
8. UN PRESUPUESTO QUE SOLO VIVE EN EL CHAT NO EXISTE. Cuando yo autorice una
   ampliación de presupuesto o de alcance, esa autorización se escribe en el
   mensaje del commit de la fase, con el número, el motivo y qué ficheros la
   consumen. Una sesión posterior solo puede leer el repo.

## La regla de alcanzabilidad

Todo módulo del paquete tiene que ser alcanzable desde el CLI o desde el
servidor MCP. Lo que no lo sea, sale. El historial lo guarda y
`archive/model-scanner` está intacta; un `git show` lo trae de vuelta.

La alcanzabilidad se calcula DESDE LAS RAÍCES A TRAVÉS DE LAS FUNCIONES QUE SE
ALCANZAN, no a través de los imports a nivel de módulo. Un import que solo
ocurre dentro de una función que ningún comando alcanza no es una arista de
alcanzabilidad. Esto es más estricto que la regla anterior, no más laxo: sin
esa precisión, la mitad de emisión muerta de `attest/dsse.py` mantenía viva a
`ArtifactReport`, y esta a `coverage.py` detrás, y con ellas dos violaciones de
la primera negativa dentro del paquete que se publica.

Se aplica a nivel de MÓDULO. Una función muerta dentro de un módulo vivo va a
`docs/BACKLOG.md` con su nombre; no bloquea una fase.

PROHIBIDA UNA LISTA DE EXCEPCIONES. Una excepción se satisface añadiendo una
línea a la lista, así que la regla la cumpliría quien decidiera no añadirla. Los
dos módulos que pedían excepción cuando esto se escribió, `schemas/__init__.py`
y `trace/provenance.py`, eran cada uno el segundo sitio donde estaba escrito un
hecho, con un test arbitrando entre las copias. Se cablearon a sus lectores en
vez de exceptuarse, y eso eliminó el defecto real que la regla había destapado.

`tests/test_reachability.py` es la puerta y corre en `make all`.

## Reglas de código

- Una sola dependencia de runtime: `cryptography`. Añadir otra requiere que yo
  lo autorice y que se justifique en el propio `pyproject.toml`.
- Todo documento emitido es JSON canónico. Mismo input, mismo byte.
- Nada en el camino de decisión lee el reloj, la red o el disco fuera de lo que
  se le pasó. El tiempo es un argumento, nunca una llamada.
- Los errores de formato se detectan al cargar, no al evaluar. Un identificador
  mal escrito es un error de carga con mensaje, no un traceback ni un DENY.
- Cada regla nueva llega con dos tests: un caso conforme y un caso violador.
  Los dos sobre una configuración REAL: o de un repo público con licencia OSI,
  citando repo, commit y licencia; o reconstruida de una configuración
  publicada en un informe de incidente, citando la URL y el fragmento del que
  sale. Nunca inventada. Una regla probada contra un fixture que escribimos
  nosotros prueba que sabemos escribir el fixture.
- TERCERA RAMA, ESTRECHA, PARA EL CASO VIOLADOR. Se admite la configuración
  publicada por la documentación del fabricante, citada con URL, digest de la
  página y fecha, SOLO en dos situaciones: cuando el alcance de la regla hace
  imposible una muestra pública —una política gestionada vive fuera de todo
  repositorio— o cuando una búsqueda REGISTRADA, con su consulta y su fecha, no
  encontró ninguna. La regla queda marcada y la marca se publica en
  `docs/RULES.md`, no solo en la procedencia del fixture. Existe porque negar la
  rama no crea la muestra: obliga a inventarla o a no escribir la regla, y las
  dos son peores que decir cuál no tiene violador real. El cargador rechaza una
  marca sin su cita o sin su búsqueda, y un test comprueba que ese rechazo muerde:
  una excepción que se satisface escribiendo una línea la cumple quien decida no
  escribirla.
- NINGÚN FIXTURE CONTIENE CARGA MALICIOSA. Reconstruimos la FORMA de la
  configuración, no su efecto: el script al que apunta un hook es un stub
  inerte o no existe. Un repositorio de seguridad que reparte el payload del
  gusano que detecta es el gusano.
- Los lectores tocan disco y no hacen nada más. La resolución de ámbitos y las
  reglas son funciones puras sobre lo que los lectores leyeron. Actaira NUNCA
  ejecuta un binario de agente ni un script referenciado para averiguar algo:
  preguntarle a la herramienta auditada qué haría es fiarse de ella, y ejecutar
  lo que estamos analizando es ser el vector.
- Los nombres de los campos de la traza siguen las convenciones GenAI de
  OpenTelemetry, que viven en `open-telemetry/semantic-conventions-genai`.
  No inventamos vocabulario donde ya existe.

## El CLI

Siete comandos. El tope sigue siendo ocho: añadir uno octavo es una decisión, y
un noveno exige quitar otro.

    actaira check                lee la configuración de los agentes de este
                                 repo y de esta máquina, resuelve la superficie
                                 efectiva y aplica las reglas
    actaira diff A B             qué capacidad aparece, desaparece, se ensancha
                                 o se estrecha entre dos momentos
    actaira seal                 sella una línea base firmada de la superficie,
                                 que es lo que `verify` verifica
    actaira verify <sello.zip>   verifica un sello sin red
    actaira keygen               crea, rota o revoca una clave
    actaira scan                 analiza sesiones que el agente ya grabó (L0)
    actaira watch -- <comando>   graba una ejecución desde el borde (L1 o más)

`check` llegó en la S1 leyendo Claude Code y en la S2 lee además Codex CLI,
Cursor, Gemini CLI, los ficheros de VS Code, el devcontainer y los ficheros de
instrucciones; lo que siga sin leerse está en la lista de «no leído» de su
propio informe, no en silencio. `diff` y `seal` llegaron en la S3, y con ellos
la lista se queda sin ningún nombre pendiente: los siete existen.
`tests/test_cli.py` lo comprueba en los dos sentidos: un comando de esta lista
que ni exista en el parser ni lleve su fase marcada rompe la puerta, y uno que
exista y siga marcado con una fase la rompe igual. Un nombre en esta lista sin
fase es una promesa publicada; una fase sobre un comando construido es la misma
mentira del otro lado.

Salieron de la lista `contract`, `verdict`, `receipt` y `fix`. Los tres
primeros eran el producto de conformidad, que el plan retira; `fix` imprimía
remediaciones, y la remediación pasa a ser un campo que `check` imprime con su
hallazgo en vez de un comando propio.

`actaira scan --demo` corre sobre un fixture incluido, para quien no tenga
ningún agente instalado.

## Lo prohibido

- Volver a tocar `formats/`, `controls/`, `connectors/`, `scan/`, `bom/`,
  `agents/`, `governance/`, `web/`, `evals_support/`, `bundle.py`, `marking.py`,
  `inspect.py`, `remote.py`, `trustpolicy.py`. Están en la rama
  `archive/model-scanner` y ahí se quedan.
- Reintroducir el pipeline de LLM como juez, o generar remediaciones con un
  modelo. La remediación es un campo de la regla, escrito por un humano.
- Aplicar un cambio en el entorno del usuario sin que él lo ejecute.
- Añadir dependencias de runtime.
- Escribir un documento de gobierno nuevo. Este fichero es el único.
- Construir un dashboard, un modo servidor propio, multi tenant, o cualquier
  cosa que empiece por "y además".
- Ejecutar lo que declaran un hook, una tarea o un servidor MCP. Se lee, se
  cita y se liga a su digest. No se corre, ni para ver qué hace, ni en un
  sandbox, ni con el argumento de que así el hallazgo sería más preciso.
