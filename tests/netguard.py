"""A permanent refusal: no test in this suite reaches anything but loopback.

Design note D-267. A tool whose threat model says "works offline, opens no
outbound connection" has to be able to show it, and a test suite is the only
place the claim is ever exercised. This suite could not show it: a parametrised
privacy test pointed at a hostname and did ten DNS lookups per run - a test that
reaches a third party and fails differently depending on whose resolver is
answering. It was found by a throwaway plugin somebody ran once.

**A guard that exists only when somebody remembers to run it is not a guard.**
So this is installed from `conftest.py` for the whole suite, and the release
gate runs `tests/test_netguard.py` and fails if the guard is not armed. That
second half is the one that matters and it is the lesson of phase 0.1: a suite
passing under a broken checker reads exactly like a suite that is clean, so the
checker needs a test that proves it still bites.

What is allowed: loopback. `tests/test_proxy_transports.py` and
`tests/test_proxy_http_interposition.py` stand up `ThreadingHTTPServer` on
127.0.0.1 and talk to it, which is the only way to exercise an HTTP transport
without either mocking the thing under test or leaving the machine. Unix
sockets are allowed for the same reason: they are not a network.

What is refused: every other address, and every name lookup of anything that is
not already a loopback literal. The lookup is guarded separately from the
connect because a resolver call IS the outbound connection - it is the one this
suite was actually making, and a test that resolves a name and then fails to
connect has still told somebody else's DNS server what this suite is doing.

Rejected: a firewall in CI. It does not run on the machine of the person who
finds the problem, it cannot say which test did it, and this repository is
installed and tested by people who will never see the CI configuration.
"""
from __future__ import annotations

import socket
from typing import Any

LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", ""})
LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1"})  # noqa: S104 - a bind wildcard, matched not used


class NetworkRefused(AssertionError):
    """A test tried to leave this machine.

    An AssertionError rather than a bespoke exception so that it reads as a
    failed test wherever it surfaces, including inside a `try` that a test is
    using to prove something else.
    """


def _is_loopback(host: Any) -> bool:
    if isinstance(host, bytes):
        host = host.decode("utf-8", "replace")
    if not isinstance(host, str):
        return False
    name = host.strip("[]").lower()
    if name in LOOPBACK_NAMES or name in LOOPBACK_ADDRESSES:
        return True
    return name.startswith("127.")


def _refuse(what: str, host: Any) -> NetworkRefused:
    return NetworkRefused(
        f"this test tried to {what} {host!r}, which is not loopback. The suite runs "
        "offline: nothing in it may reach a name server, a package index or somebody "
        "else's machine. If a test needs a server, stand one up on 127.0.0.1 "
        "(tests/netguard.py says why)."
    )


_original = {
    "getaddrinfo": socket.getaddrinfo,
    "gethostbyname": socket.gethostbyname,
    "gethostbyaddr": socket.gethostbyaddr,
    "create_connection": socket.create_connection,
    "connect": socket.socket.connect,
    "connect_ex": socket.socket.connect_ex,
}
_armed = False


def _address_host(address: Any) -> Any:
    if isinstance(address, tuple) and address:
        return address[0]
    return address


def armed() -> bool:
    """Whether the guard is actually installed right now.

    Read by its own meta-test and by the release gate. Without it, "the suite
    passed" and "the suite passed with the guard switched off" are the same
    observation.
    """
    return _armed


def install() -> None:
    """Patch the six doors out of this process. Idempotent.

    `gethostbyname` and `gethostbyaddr` are here because they are a SECOND
    resolver, reachable without touching `getaddrinfo` at all - and
    `http.server` walks through one of them on every bind, via
    `socket.getfqdn`, which is how a guard with four doors reads as a guard
    with all of them.
    """
    global _armed
    if _armed:
        return

    def getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if not _is_loopback(host):
            raise _refuse("resolve", host)
        return _original["getaddrinfo"](host, port, *args, **kwargs)

    def create_connection(address, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        host = _address_host(address)
        if not _is_loopback(host):
            raise _refuse("connect to", host)
        return _original["create_connection"](address, *args, **kwargs)

    def connect(self, address):  # noqa: ANN001
        if self.family != getattr(socket, "AF_UNIX", object()) and not _is_loopback(
            _address_host(address)
        ):
            raise _refuse("connect to", _address_host(address))
        return _original["connect"](self, address)

    def connect_ex(self, address):  # noqa: ANN001
        if self.family != getattr(socket, "AF_UNIX", object()) and not _is_loopback(
            _address_host(address)
        ):
            raise _refuse("connect to", _address_host(address))
        return _original["connect_ex"](self, address)

    def gethostbyname(host):  # noqa: ANN001
        if not _is_loopback(host):
            raise _refuse("resolve", host)
        return _original["gethostbyname"](host)

    def gethostbyaddr(host):  # noqa: ANN001
        if not _is_loopback(host):
            raise _refuse("reverse-resolve", host)
        return _original["gethostbyaddr"](host)

    socket.getaddrinfo = getaddrinfo
    socket.gethostbyname = gethostbyname
    socket.gethostbyaddr = gethostbyaddr
    socket.create_connection = create_connection
    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    _armed = True


def uninstall() -> None:
    """Put the originals back. Only the meta-test has any business here."""
    global _armed
    socket.getaddrinfo = _original["getaddrinfo"]
    socket.gethostbyname = _original["gethostbyname"]
    socket.gethostbyaddr = _original["gethostbyaddr"]
    socket.create_connection = _original["create_connection"]
    socket.socket.connect = _original["connect"]
    socket.socket.connect_ex = _original["connect_ex"]
    _armed = False
