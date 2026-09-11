"""Discovery connectors: the only part of Actaira that opens a socket.

The contract every connector in this package obeys is in `model.py`, and the
three rules that make a connector a small thing are design note D-80: it
enumerates rather than concludes, a digest the source published is a claim
rather than a measurement, and the network is opt-in per command and printed.

Nothing is imported here beyond the contract itself. The connector modules are
loaded by `registry._ensure_loaded()` on first use, for the reason given in
`registry.py`: importing them at package import would make `actaira scan`,
which never touches the network, pay for a package it does not use.
"""
from __future__ import annotations

from .model import (
    Connector,
    ConnectorError,
    Discovery,
    Http,
    HttpStatusError,
    OfflineError,
    RemoteArtifact,
    stage,
    token_from_env,
)

__all__ = [
    "Connector",
    "ConnectorError",
    "Discovery",
    "Http",
    "HttpStatusError",
    "OfflineError",
    "RemoteArtifact",
    "stage",
    "token_from_env",
]
