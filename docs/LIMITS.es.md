# Límites publicados

Lo que Seamark no puede enseñarte, en el mismo sitio en cada release. Están en
el informe que imprime la herramienta, en [`README.es.md`](../README.es.md) como
enlace, y aquí. No se ablandan para vender mejor, y una afirmación de cualquier
parte de este repositorio que contradiga uno de ellos es un defecto de la
afirmación.

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

El texto inglés de esta página es [`LIMITS.md`](LIMITS.md), y no es una
cortesía: `seamark --lang es` imprime los mismos límites, así que las dos
lenguas tienen que enunciar la misma cantidad y `tests/test_proxy_completeness.py`
falla cuando no lo hacen.
