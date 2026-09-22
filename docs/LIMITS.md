# Published limits

What Actaira cannot show you, in the same place every release. These are in the
report the tool prints, in [`README.md`](../README.md) as a link, and here. They
do not get softened to sell better, and a claim anywhere in this repository that
contradicts one of them is a defect in the claim.

1. We do not reproduce the output of a hosted model. Not with a seed, not at
   temperature zero. The cause is the provider's batch size and MoE routing, and
   it is not under our control.
2. We cannot isolate a run from the load of the provider's other users.
3. We cannot detect that the provider changed backend, except via
   `system_fingerprint` on OpenAI.
4. There is no determinism in MoE models, which is all the relevant ones.
5. We cannot reproduce stateful tools without freezing the world.
6. We do not prove the absence of an action, only its presence.
7. A trace produced by the agent itself is not evidence.
8. A witness detects an inconsistency; it does not denounce it.
9. Firing no rule is not safety. A repository can produce no finding at all and
   be badly configured for a reason no rule names.
10. What is resolved inherits the errors of what it was resolved from. An
    effective surface computed over the wrong configuration is a correct answer
    to the wrong question.
11. **Configuration is not behaviour.** A capability being declared does not
    prove it was exercised, and its absence does not prove nothing happened.
12. **We see only what is on disk.** Configuration a vendor pushes from a server
    without leaving a file is invisible to us, and that gets declared rather
    than treated as absence.
13. **Merge semantics depend on the agent's version.** With no known version,
    any capability that depends on it comes out INDETERMINATE; it is not
    resolved with whichever version looks likeliest.
14. **A referenced script can change after it is read.** Which is why everything
    binds to its digest and not to its path: an approval over a file name is an
    approval over whatever is there tomorrow.
15. **On Windows a closed transport looks like a quiet one.** On Windows a
    server that closes its transport while still running cannot be told apart
    from one that has simply gone quiet. The operating system does not deliver
    EOF to the reader while the writing process is alive, so the gap is named
    `upstream_timeout` and not `transport_closed`. The run is recorded and the
    gap is declared either way; what is lost is which of the two happened. In
    practice a client that gives up before the proxy's own deadline also leaves
    `end_not_recorded` behind, which is not platform-specific - it is what any
    killed proxy reports, and it is the truth.
16. **The proxy does not answer for a server that did not.** When an upstream
    produces no reply, `watch` records the gap and forwards nothing, so an MCP
    client with no deadline of its own waits. Writing a timeout error back would
    put a message in the agent's own input that no server sent, and the agent
    could not tell it from a real one - a witness does not act on what it
    observes.

---

The Spanish text of this page is [`LIMITS.es.md`](LIMITS.es.md), and it is not
a courtesy: `actaira --lang es` prints the same limits, so both languages have
to state the same number of them and `tests/test_proxy_completeness.py` fails
when they do not.
