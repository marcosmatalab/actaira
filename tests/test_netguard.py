"""The guard on the guard, one door at a time.

`tests/netguard.py` refuses every outbound connection that is not loopback. A
suite that passes under a guard which has quietly stopped biting looks exactly
like a suite that is clean - that is the shape phase 0.1 took out of `verify` -
so the guard needs a test of its own.

It had one, and the one it had was the third failure mode of document 91: a
test asserting a property that is not the one being protected. The guard
claimed four doors, each assertion exercised whichever one it happened to reach,
and the 1.1b adversarial pass found `gethostbyname` and `gethostbyaddr` open the
whole time with every case green. `socket` has more than one way out of a
process, and a meta-test that samples them reports on a sample.

So this file is parametrised over the doors THE GUARD ITSELF SAYS IT COVERS,
`netguard._original`, and one test asserts that the table below is exactly that
set. Adding a door to the guard without a case here fails. Removing a case
without removing the door fails. Neither can be done by forgetting.
"""
from __future__ import annotations

import socket

import pytest

import netguard

OFF_MACHINE = "198.51.100.7"  # TEST-NET-3, never routed
OFF_MACHINE_NAME = "example.invalid"


def _impatient() -> socket.socket:
    """A socket that gives up quickly.

    Belt and braces: these calls must never reach the network, because the
    guard refuses them. If one ever did, an unbounded `connect` to an
    unrouted address hangs the whole suite for a TCP timeout, and a suite that
    hangs is a suite somebody kills rather than reads.
    """
    probe = socket.socket()
    probe.settimeout(0.2)
    return probe


# One entry per door the guard patches. `outward` must raise the guard's own
# refusal; `inward` is the loopback call the suite's own fixtures depend on and
# must not. `None` means this door's allowance is asserted by
# `test_loopback_still_works`, which needs a live listener to be meaningful.
DOORS = {
    "getaddrinfo": (
        lambda: socket.getaddrinfo(OFF_MACHINE_NAME, 443),
        lambda: socket.getaddrinfo("127.0.0.1", 80),
    ),
    "gethostbyname": (
        lambda: socket.gethostbyname(OFF_MACHINE_NAME),
        lambda: socket.gethostbyname("127.0.0.1"),
    ),
    "gethostbyaddr": (
        lambda: socket.gethostbyaddr(OFF_MACHINE),
        lambda: socket.gethostbyaddr("127.0.0.1"),
    ),
    "create_connection": (
        lambda: socket.create_connection((OFF_MACHINE, 443), timeout=0.2),
        None,
    ),
    "connect": (
        lambda: _impatient().connect((OFF_MACHINE, 443)),
        None,
    ),
    "connect_ex": (
        lambda: _impatient().connect_ex((OFF_MACHINE, 443)),
        None,
    ),
}


# Where each door actually lives, so this file can look at the attribute rather
# than at what happens when it is called.
WHERE = {
    "getaddrinfo": (socket, "getaddrinfo"),
    "gethostbyname": (socket, "gethostbyname"),
    "gethostbyaddr": (socket, "gethostbyaddr"),
    "create_connection": (socket, "create_connection"),
    "connect": (socket.socket, "connect"),
    "connect_ex": (socket.socket, "connect_ex"),
}


def test_the_guard_is_armed_for_this_whole_suite():
    """The assertion the release gate is really running. Everything else in
    this file could pass with the guard uninstalled."""
    assert netguard.armed(), (
        "the network guard is not installed, so every other test in this suite ran "
        "with the machine's network wide open and nothing would have said so"
    )


def test_the_map_of_where_each_door_lives_covers_them_all():
    assert set(WHERE) == set(DOORS)


def test_every_door_the_guard_patches_has_a_case_here():
    """The check that makes this file a meta-test rather than a sample.

    The guard's own record of what it replaced is the authority, so a door
    added to `netguard.install` without a case below fails here, and a case
    left behind after a door is removed fails here too.
    """
    assert set(DOORS) == set(netguard._original), (
        "the doors this file exercises and the doors the guard says it covers have "
        f"come apart: only in the guard {sorted(set(netguard._original) - set(DOORS))}, "
        f"only here {sorted(set(DOORS) - set(netguard._original))}. A guard with an "
        "unexercised door is how gethostbyname stayed open through a green suite."
    )


@pytest.mark.parametrize("door", sorted(DOORS))
def test_each_door_refuses_what_is_not_loopback(door):
    """One case per door, named, so a failure says which one stopped biting."""
    outward, _inward = DOORS[door]

    with pytest.raises(netguard.NetworkRefused):
        outward()


@pytest.mark.parametrize("door", sorted(DOORS))
def test_each_door_is_the_guard_and_goes_back_to_being_itself(door):
    """The half that distinguishes "the guard refused this" from "this address
    was unreachable anyway", without leaving the machine to find out.

    Calling the real function with the guard uninstalled would settle the same
    question and would do it by opening the connection this suite exists to
    refuse - a meta-test that breaks the property it is testing. So the
    question is asked of the ATTRIBUTE instead: while the guard is armed each
    door is not what `socket` shipped, uninstalling puts the original back, and
    installing takes it away again. Together with the refusal above, that is
    the whole claim: this door is replaced, and what replaces it refuses.
    """
    holder, name = WHERE[door]

    assert getattr(holder, name) is not netguard._original[door], (
        f"{door} is still the function socket shipped, so nothing is guarding it and "
        "the refusal asserted above came from somewhere else"
    )
    netguard.uninstall()
    try:
        assert getattr(holder, name) is netguard._original[door], (
            f"{door} did not go back to the original, so the guard cannot be taken off "
            "and what it replaced is not recoverable"
        )
    finally:
        netguard.install()
    assert getattr(holder, name) is not netguard._original[door]


@pytest.mark.parametrize(
    "door", sorted(name for name, (_out, inward) in DOORS.items() if inward is not None)
)
def test_each_resolver_door_still_answers_for_loopback(door):
    """A guard that refused everything would make the HTTP transport untestable,
    and an untested transport is what phase 1.1b existed to fix. `http.server`
    itself walks through `gethostbyaddr` on every bind, via `socket.getfqdn`."""
    _outward, inward = DOORS[door]

    assert inward() is not None


def test_loopback_still_works():
    """The connecting doors' half of the allowance, against a live listener."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            assert client.getpeername()[1] == port
