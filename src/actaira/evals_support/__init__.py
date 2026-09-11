"""Measurement helpers that need development-only dependencies.

Kept out of the main package tree on purpose: everything under `actaira/`
proper imports nothing but the standard library and `cryptography`, and a
reader checking that claim should not have to reason about which modules are
reachable from a runtime path. Nothing here is imported at start-up; the
controls that use it import it inside the function and degrade to INCONCLUSIVE
when the dependency is absent.
"""
