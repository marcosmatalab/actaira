"""The guard on the guard.

`tests/netguard.py` refuses every outbound connection that is not loopback. A
suite that passes under a guard which has quietly stopped biting looks exactly
like a suite that is clean - that is the shape phase 0.1 took out of `verify`,
and installing a checker without a test of the checker would put it straight
back. So this file asserts three things: the guard is armed right now, it
refuses what it says it refuses, and it still allows the loopback the proxy
tests are built on.
"""
from __future__ import annotations

import socket

import pytest

import netguard


def test_the_guard_is_armed_for_this_whole_suite():
    """The assertion the release gate is really running. Everything else in
    this file could pass with the guard uninstalled."""
    assert netguard.armed(), (
        "the network guard is not installed, so every other test in this suite ran "
        "with the machine's network wide open and nothing would have said so"
    )


def test_resolving_a_name_is_refused():
    """The lookup is guarded separately from the connect because a resolver
    call IS an outbound connection, and it was the one this suite was making."""
    with pytest.raises(netguard.NetworkRefused):
        socket.getaddrinfo("example.invalid", 443)


def test_the_second_resolver_is_refused_too():
    """`gethostbyname` reaches a name server without going anywhere near
    `getaddrinfo`, so a guard on one of them is a guard on neither."""
    with pytest.raises(netguard.NetworkRefused):
        socket.gethostbyname("example.invalid")
    with pytest.raises(netguard.NetworkRefused):
        socket.gethostbyaddr("198.51.100.7")


def test_the_loopback_reverse_lookup_that_http_server_needs_still_works():
    """`http.server` calls `socket.getfqdn` on every bind, which goes through
    `gethostbyaddr`. Refusing that would make the proxy tests unrunnable, so
    the allowance is asserted rather than discovered."""
    assert socket.getfqdn("127.0.0.1")


def test_connecting_off_the_machine_is_refused():
    with pytest.raises(netguard.NetworkRefused):
        socket.create_connection(("198.51.100.7", 443), timeout=1)


def test_connecting_off_the_machine_through_a_socket_is_refused():
    with socket.socket() as probe, pytest.raises(netguard.NetworkRefused):
        probe.connect(("198.51.100.7", 443))


def test_connect_ex_is_refused_too():
    """`connect_ex` returns an error number instead of raising, which is
    exactly how a guarded `connect` gets routed around by accident."""
    with socket.socket() as probe, pytest.raises(netguard.NetworkRefused):
        probe.connect_ex(("198.51.100.7", 443))


def test_loopback_still_works():
    """The other half. A guard that refused everything would make the HTTP
    transport untestable, and an untested transport is what phase 1.1b exists
    to fix - so the allowance is asserted rather than assumed."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            assert client.getpeername()[1] == port


def test_the_guard_bites_only_because_it_is_installed():
    """Uninstall it, show the same call no longer raises, put it back.

    Without this the four refusals above would also pass against a guard that
    refused every address including loopback, or against one whose predicate
    happened to match the fixtures. It is the difference between "this test
    saw a refusal" and "this guard is what refused".
    """
    netguard.uninstall()
    try:
        assert not netguard.armed()
        with pytest.raises(OSError):  # noqa: PT011 - any OS refusal will do; the point is it is not ours
            socket.create_connection(("127.0.0.1", 1), timeout=1)
    finally:
        netguard.install()
    assert netguard.armed()
