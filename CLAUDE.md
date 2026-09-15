# Actaira

## Qué es

Actaira captura lo que hizo un agente de IA desde fuera de él, decide de forma
determinista si se salió de lo que declaró, y emite un acta que un tercero
verifica sin confiar en el operador ni en Actaira.

No es un escáner de modelos. No es una plataforma de observabilidad. No es una
herramienta de compliance. Si una decisión de diseño solo tiene sentido bajo una
de esas tres descripciones, está mal.

## Las tres afirmaciones del producto

El acta afirma exactamente esto y nada más:

1. AUTENTICIDAD. La traza se capturó en el borde del proceso, no la produjo el
   agente sobre sí mismo. Está firmada, encadenada, y declara su nivel de captura.
2. CONFORMIDAD. La ejecución conforma, no conforma, o es indeterminada, respecto
   a un contrato. Cuando no conforma, se nombra el evento, su índice y la regla.
3. INCLUSIÓN. El acta está en un registro append-only cofirmado por testigos.

Cualquier afirmación fuera de estas tres es un defecto de producto, aunque sea
verdadera.

## Las cuatro negativas

Son invariantes. Un cambio que las viole se rechaza sin discusión.

1. NUNCA UN NÚMERO. No hay score, grade, rating, percent, confidence ni ranking
   en ningún documento emitido. El test que greppea esas palabras se mantiene y
   se amplía, nunca se relaja. Una regla puede traer una `severity` escrita por
   el autor de su paquete: eso es una etiqueta atribuida, no un cálculo de
   Actaira, y NO se agrega ni se suma con otras.
2. NUNCA JUZGAR, SOLO CITAR. Actaira no tiene opinión sobre lo que un agente
   debería haber hecho. Solo compara lo observado contra una norma ESCRITA POR
   OTRO, y la nombra. Todo NO CONFORMA publica el id de la regla, su versión, su
   paquete y su autor. De aquí se sigue lo de siempre: prohibido llamar a un
   modelo en el camino de decisión. Un LLM puede ayudar a redactar una regla;
   no puede evaluarla, y tampoco puede escribir su remediación.
3. NUNCA INFERIR LO NO OBSERVADO. Si el nivel de captura no cubría algo, el acta
   lo dice. Un predicado sin información devuelve INDETERMINADO, jamás False.
   Cada regla declara el nivel de captura que necesita; por debajo de él la
   regla devuelve INDETERMINADO sola, sin que nadie se acuerde de comprobarlo.
4. NUNCA ACTUAR SOBRE LO QUE SE OBSERVA. Actaira SUGIERE remediaciones, nunca
   las aplica por su cuenta. Un testigo que además actúa no puede dar fe de sus
   propios actos, y ese conflicto de interés es exactamente el que nos separa
   de los proveedores de observabilidad. Si algún día existe un `--apply`, el
   cambio queda registrado como un evento más de la traza, atribuido a Actaira,
   y el motor lo evalúa como cualquier otro. Silencioso, jamás.

## Los límites publicados

Van en el README, en la web y en el propio acta. No se ablandan para vender mejor.

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
4. PROHIBIDO EMPEZAR LA FASE SIGUIENTE ANTES DE CERRAR LA ACTUAL. Aunque sea
   evidente, aunque queden tokens, aunque el cambio sea de una línea.
5. CADA DECISIÓN DE DISEÑO SE ESCRIBE CON SU ALTERNATIVA RECHAZADA Y SU PORQUÉ,
   en el propio código, en cinco líneas o menos. No en cincuenta. Un docstring
   de noventa líneas es un pasivo.
6. NINGUNA CIFRA PUBLICADA SIN UN COMANDO QUE LA MIDA. `make figures` la mide y
   el gate de release falla si deriva. Esto ya existe y se mantiene.
7. LA PUERTA SE CORRE EN WSL, porque Windows no tiene `make` y probar los cuatro
   comandos a mano no prueba el Makefile. Ubuntu 24.04, GNU Make 4.3, venv en
   `/tmp/actaira-venv` con `pip install -e ".[dev]"`, el repo por su ruta
   montada:
   `wsl -e bash -lc 'cd /mnt/c/Users/Usuario/Desktop/actaira && PY=/tmp/actaira-venv/bin/python make all'`
   Ahí la suite tarda ~85 s en vez de ~205 s, y no se salta el test de bits de
   permiso POSIX que Windows no puede correr.
8. UN PRESUPUESTO QUE SOLO VIVE EN EL CHAT NO EXISTE. Cuando yo autorice una
   ampliación de presupuesto o de alcance, esa autorización se escribe en el
   mensaje del commit de la fase, con el número, el motivo y qué ficheros la
   consumen. Una sesión posterior solo puede leer el repo.

## Reglas de código

- Una sola dependencia de runtime: `cryptography`. Añadir otra requiere que yo
  lo autorice y que se justifique en el propio `pyproject.toml`.
- Todo documento emitido es JSON canónico. Mismo input, mismo byte.
- Nada en el camino de decisión lee el reloj, la red o el disco fuera de lo que
  se le pasó. El tiempo es un argumento, nunca una llamada.
- Los errores de formato se detectan al cargar, no al evaluar. Un identificador
  mal escrito es un error de carga con mensaje, no un traceback ni un DENY.
- Cada regla nueva llega con dos tests: un caso conforme y un caso violador,
  ambos sobre una traza real, no sintética.
- Los nombres de los campos de la traza siguen las convenciones GenAI de
  OpenTelemetry, que viven en `open-telemetry/semantic-conventions-genai`.
  No inventamos vocabulario donde ya existe.

## El CLI

Ocho comandos y ni uno más. Añadir uno exige quitar otro.

    actaira scan                 analiza sesiones que el agente ya grabó (L0)
    actaira watch -- <comando>   graba una ejecución desde el borde (L1 o más)
    actaira contract             deriva y muestra el contrato, y su anchura
    actaira verdict              emite el veredicto de una sesión
    actaira receipt              firma el acta
    actaira verify <acta.zip>    verifica un acta sin red
    actaira keygen               crea, rota o revoca una clave
    actaira fix                  imprime las remediaciones que traen las reglas
                                 que dispararon. Imprime. No aplica nada.

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
