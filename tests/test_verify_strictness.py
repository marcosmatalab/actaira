"""Two properties of `verify_package` that no single test case can state.

**Strictness is monotone.** Supplying a trust anchor is an assertion about who
or what the verifier accepts. It may turn an OK into a FAILED - that is what an
anchor is for - and it must never do the reverse. Two paths did exactly the
reverse: a `--tsa-trust-store` that would not load returned before
`timestamp_matches_manifest` was ever recorded, and a `--trusted-keyring` that
named the signing key made the `status: revoked` the package confessed about
itself unreachable. Both printed `Result: OK` on a package that failed without
the flag. The property below is over a corpus rather than over one case,
because both bugs lived in the space between two arguments and neither was
visible from inside a test about one of them.

**Every check is classified.** `result.ok` used to be an allow-list: five
integrity checks plus three named extras, read through
`result.checks.get(name, True)`, so a check that was False and not on the list
did nothing and a check that never ran counted as passed. `dsse_envelope_valid`
was the check that fell through, and the CLI printed `[FAIL]` beside
`Result: OK` on the same screen. The default is inverted now, and the test here
is the guard on the inversion: a check name this module can write that is in
neither `verify.FAILING_CHECKS` nor `verify.ADVISORY_CHECKS` fails this file.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

import tsa
from actaira.attest import chain, package, signing
from actaira.attest import keyring as keyring_mod
from actaira.attest import timestamp as ts
from actaira.attest import verify as verify_mod
from actaira.attest.dsse import to_envelope
from actaira.cli import _print_verify
from actaira.i18n.catalog import SUPPORTED, Catalog, load
from support.reports import make_report

VERIFY_SOURCE = Path(verify_mod.__file__)


# ---------------------------------------------------------------------------
# The corpus: one package per way of being wrong, all signed by one key so a
# single keyring can name every one of them.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    name: str
    path: Path


def _members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _rewrite(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in sorted(members.items()):
            archive.writestr(name, blob)
    return path


@pytest.fixture(scope="module")
def authority() -> tsa.FixtureTSA:
    return tsa.FixtureTSA()


@pytest.fixture(scope="module")
def signer():
    return signing.generate()


@pytest.fixture(scope="module")
def entries(tmp_path_factory):
    report = make_report(tmp_path_factory.mktemp("subject") / "clean.safetensors")
    built: list[chain.Entry] = []
    chain.append(built, report.sha256, report.to_dict(), timestamp="2026-01-01T00:00:00")
    return built, report


@pytest.fixture(scope="module")
def corpus(tmp_path_factory, signer, authority, entries) -> list[Case]:
    home = tmp_path_factory.mktemp("corpus")
    built, report = entries
    cases: list[Case] = []

    healthy = package.write_package(home / "healthy.zip", built, signer)
    cases.append(Case("healthy", healthy.path))

    # A signature over the right shape of bytes and the wrong bytes.
    members = _members(healthy.path)
    document = json.loads(members["manifest.sig"])
    document["signature_b64"] = base64.b64encode(signer.sign(b"some other manifest")).decode("ascii")
    members["manifest.sig"] = json.dumps(document, indent=2).encode("utf-8")
    cases.append(Case("broken signature", _rewrite(home / "broken-signature.zip", members)))

    # A real token from a real authority, issued over a digest that is not this
    # manifest's. The manifest advertises the token it was meant to carry.
    def stamp(url: str, digest: bytes, timeout: float = 10.0) -> ts.StampResult:
        nonce = ts.make_nonce()
        request = ts.build_request(digest, nonce=nonce, cert_req=True)
        response = ts.parse_response(authority.respond(request))
        verification = ts.verify_token(response.token, digest, expected_nonce=nonce)
        return ts.StampResult(
            token=response.token, info=verification.info, verification=verification, tsa_url=url
        )

    anchored = package.write_package(
        home / "anchored.zip", built, signer, tsa_url="https://tsa.invalid/", stamp_fn=stamp
    )
    cases.append(Case("anchored, honest", anchored.path))

    members = _members(anchored.path)
    swapped = stamp("https://tsa.invalid/", hashlib.sha256(b"a different manifest").digest())
    members["manifest.tsr"] = swapped.token
    cases.append(Case("token over another digest", _rewrite(home / "token-swapped.zip", members)))

    # The package's own keyring, admitting against its own interest that the key
    # which signed it has been revoked.
    ring = keyring_mod.Keyring(
        keys=[keyring_mod.KeyRecord.from_keypair(signer, not_before="2020-01-01T00:00:00+00:00")]
    )
    ring.revoke(signer.key_id, "2020-06-01T00:00:00+00:00")
    revoked = package.write_package(home / "revoked.zip", built, signer, keyring=ring)
    cases.append(Case("key the package calls revoked", revoked.path))

    # A DSSE envelope nobody signed. Its digest matches the manifest, so only
    # its own signature check can tell.
    unsigned = to_envelope([report], None, inspected_at="2026-01-01T00:00:00+00:00")
    envelope = package.write_package(
        home / "unsigned-envelope.zip", built, signer, envelope=unsigned.to_json().encode("utf-8")
    )
    cases.append(Case("unsigned DSSE envelope", envelope.path))

    return cases


@pytest.fixture(scope="module")
def anchors(tmp_path_factory, signer, authority) -> list[tuple[str, dict]]:
    """Every shape of anchor argument, including the two that fail to load.

    An anchor the caller asked for and this process cannot read is the case
    both regressions lived in, so it is a first-class member of this list
    rather than a separate test.
    """
    home = tmp_path_factory.mktemp("anchors")

    keyring_path = home / "trusted.json"
    keyring_path.write_text(
        json.dumps({"keys": [{"fingerprint_sha256": signer.fingerprint}]}), encoding="utf-8"
    )
    unreadable_ring = home / "not-written-yet.json"

    store = home / "tsa-root.pem"
    store.write_bytes(authority.root_cert.public_bytes(serialization.Encoding.PEM))
    unreadable_store = home / "anchors-i-meant-to-write.pem"

    return [
        ("trusted keyring naming the signer", {"trusted_keyring": keyring_path}),
        ("trusted keyring that will not load", {"trusted_keyring": unreadable_ring}),
        ("pubkey of the signer", {"trusted_pubkey_b64": signer.public_b64}),
        ("TSA trust store", {"tsa_trust_store": store}),
        ("TSA trust store that will not load", {"tsa_trust_store": unreadable_store}),
        (
            "keyring and TSA store, both good",
            {"trusted_keyring": keyring_path, "tsa_trust_store": store},
        ),
        (
            "keyring and TSA store, both unreadable",
            {"trusted_keyring": unreadable_ring, "tsa_trust_store": unreadable_store},
        ),
        ("require-trust on top of a good keyring",
         {"trusted_keyring": keyring_path, "require_trust": True}),
    ]


def _identifiers(case: Case, label: str) -> str:
    return f"{case.name} + {label}"


# ---------------------------------------------------------------------------
# Invariant A: an anchor may only ever make the answer stricter
# ---------------------------------------------------------------------------


def test_the_corpus_covers_both_verdicts(corpus):
    """A property test over a corpus where everything fails, or everything
    passes, is a property test that proves nothing."""
    verdicts = {verify_mod.verify_package(case.path).ok for case in corpus}

    assert verdicts == {True, False}, "the corpus must hold packages of both verdicts"


def test_an_anchor_never_turns_a_failure_into_a_pass(corpus, anchors):
    """The invariant, over every (package, anchors) pair.

    Stated one way only. An anchor turning OK into FAILED is the whole point of
    supplying one; an anchor turning FAILED into OK means the verifier learned
    something and concluded less, which is not a trade any caller would make
    knowingly.
    """
    weakened: list[str] = []
    for case in corpus:
        baseline = verify_mod.verify_package(case.path)
        if baseline.ok:
            continue
        for label, arguments in anchors:
            anchored = verify_mod.verify_package(case.path, **arguments)
            if anchored.ok:
                weakened.append(
                    f"{_identifiers(case, label)}: FAILED without anchors "
                    f"({baseline.problems[:1]}), OK with them"
                )

    assert weakened == [], "\n".join(weakened)


def test_a_package_that_admits_its_key_is_revoked_is_refused_with_any_anchors(corpus, anchors):
    """The first regression, named, because a property test that goes green for
    the wrong reason is one nobody notices going green for no reason."""
    case = next(item for item in corpus if "revoked" in item.name)

    assert not verify_mod.verify_package(case.path).ok
    for label, arguments in anchors:
        result = verify_mod.verify_package(case.path, **arguments)
        assert not result.ok, _identifiers(case, label)
        assert result.key_state == "revoked", _identifiers(case, label)


def test_an_unreadable_tsa_store_does_not_excuse_the_timestamp(corpus, anchors):
    """The second regression. The store failing to load is a hard failure of
    its own, and the timestamp it was going to check stays unestablished."""
    case = next(item for item in corpus if item.name == "token over another digest")
    store = dict(anchors)["TSA trust store that will not load"]

    result = verify_mod.verify_package(case.path, **store)

    assert result.checks["tsa_trust_store_loaded"] is False
    assert result.checks["timestamp_matches_manifest"] is False
    assert not result.ok


# ---------------------------------------------------------------------------
# Invariant B: every check is classified, and a False one fails
# ---------------------------------------------------------------------------


def recorded_check_names() -> set[str]:
    """Every literal name `verify.py` writes into `result.checks`.

    Read out of the source rather than out of a run, because a check only some
    packages reach would otherwise be invisible to this test until somebody
    wrote the package that reaches it - which is exactly how
    `tsa_trust_store_loaded` came to have no catalogue entry.
    """
    tree = ast.parse(VERIFY_SOURCE.read_text(encoding="utf-8"), filename=str(VERIFY_SOURCE))
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        target = node.value
        if not (
            isinstance(target, ast.Attribute)
            and target.attr == "checks"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            continue
        names.add(node.slice.value)
    return names


def test_the_source_scan_found_the_checks():
    found = recorded_check_names()

    assert len(found) >= 8, f"the scan found {found}; it is not scanning"
    assert "dsse_envelope_valid" in found, "the conditional check was missed"


def test_every_check_the_code_can_write_is_classified():
    """The guard on the inversion. A check in neither list is a check whose
    effect on the verdict nobody decided, and under the new default it would
    silently fail every package that records it."""
    unclassified = recorded_check_names() - set(verify_mod.FAILING_CHECKS) - set(
        verify_mod.ADVISORY_CHECKS
    )

    assert unclassified == set(), (
        f"{sorted(unclassified)} is written into result.checks and is in neither "
        "FAILING_CHECKS nor ADVISORY_CHECKS. Put it in one: under the inverted "
        "default a False value fails the package, and that has to be a decision "
        "somebody made rather than one a new line fell into."
    )


def test_no_check_is_both_a_failure_and_an_advisory():
    assert set(verify_mod.FAILING_CHECKS) & set(verify_mod.ADVISORY_CHECKS) == set()


def test_every_advisory_carries_the_reason_it_is_one():
    """A list of exceptions with no reasons written down is a list that grows."""
    for name, why in verify_mod.ADVISORY_CHECKS.items():
        assert len(why) > 30, f"{name} is excused without saying why"


def test_every_required_check_is_recorded_on_every_package(corpus):
    """`.get(name, True)` read a check that never ran as one that passed. The
    required ones are recorded on every path now, and this is what says so."""
    for case in corpus:
        result = verify_mod.verify_package(case.path)
        missing = [name for name in verify_mod.REQUIRED_CHECKS if name not in result.checks]
        assert missing == [], f"{case.name}: {missing}"


def test_the_timestamp_check_is_recorded_whenever_it_applies(corpus, anchors):
    """The distinction the tally rests on, and the one that was blurred.

    A package that claims no anchor and carries no token has nothing for this
    check to be about, and recording True there would say an RFC 3161 stamp
    covers a manifest no stamp covers. A package that claims one, or carries a
    token, is a package where the check applies - and every branch that reaches
    that state has to write it down, because the hole being closed here was a
    branch that applied and returned before recording anything.
    """
    for case in corpus:
        for label, arguments in [("no anchors", {}), *anchors]:
            result = verify_mod.verify_package(case.path, **arguments)
            with zipfile.ZipFile(case.path) as archive:
                carries_token = "manifest.tsr" in archive.namelist()
            claims_anchor = str(result.manifest.get("time_anchor", "none")) != "none"
            applies = claims_anchor or carries_token
            recorded = "timestamp_matches_manifest" in result.checks
            assert recorded is applies, (
                f"{_identifiers(case, label)}: applies={applies}, recorded={recorded}"
            )


def test_a_package_with_no_anchor_claims_nothing_about_time(corpus):
    """The other side of it, stated as the refusal rather than the mechanics."""
    case = next(item for item in corpus if item.name == "healthy")

    result = verify_mod.verify_package(case.path)

    assert result.ok
    assert "timestamp_matches_manifest" not in result.checks
    assert result.time_anchor == "none"
    assert result.time_evidence == "self_asserted"
    assert any("NO TIME ANCHOR" in warning for warning in result.warnings)


def test_a_false_check_fails_the_package_whatever_its_name(corpus):
    case = next(item for item in corpus if item.name == "unsigned DSSE envelope")

    result = verify_mod.verify_package(case.path)

    assert result.checks["dsse_envelope_valid"] is False
    assert result.checks["signature_valid"] is True, "the manifest itself is fine"
    assert not result.ok, "a check outside the old allow-list must still fail the package"


def test_a_required_check_that_never_ran_fails():
    """The other half of the inversion, forced rather than waited for.

    Against `settle` directly: reaching this state through `verify_package`
    would mean building a package that skips one branch, and the property is
    about the tally, not about the package that happens to reach it.
    """
    for absent in verify_mod.REQUIRED_CHECKS:
        result = verify_mod.VerifyResult(
            checks={name: True for name in verify_mod.REQUIRED_CHECKS if name != absent}
        )

        verify_mod.settle(result)

        assert not result.ok, absent
        assert any(absent in problem for problem in result.problems), absent


# ---------------------------------------------------------------------------
# What the operator sees. Gate 4.
# ---------------------------------------------------------------------------


def test_the_marker_is_derived_from_the_classification():
    """Condition (a): the word a check prints is a function of its list, not a
    choice made where it is printed. A name outside ADVISORY_CHECKS cannot
    print the advisory marker however it is called."""
    for name in sorted(recorded_check_names()):
        assert verify_mod.check_mark(name, True) == verify_mod.MARK_PASSED, name
        expected = (
            verify_mod.MARK_ADVISORY
            if name in verify_mod.ADVISORY_CHECKS
            else verify_mod.MARK_FAILED
        )
        assert verify_mod.check_mark(name, False) == expected, name


def test_only_an_advisory_can_print_the_advisory_marker():
    failing = [
        name
        for name in verify_mod.FAILING_CHECKS
        if verify_mod.check_mark(name, False) == verify_mod.MARK_ADVISORY
    ]

    assert failing == []


@pytest.mark.parametrize("lang", SUPPORTED)
def test_the_cli_never_prints_a_failed_check_beside_an_ok_result(corpus, anchors, capsys, lang):
    """The screen is the contract for everyone who does not read `--json`."""
    contradictions: list[str] = []
    for case in corpus:
        for label, arguments in [("no anchors", {}), *anchors]:
            result = verify_mod.verify_package(case.path, **arguments)
            _print_verify(result, Catalog(lang))
            printed = capsys.readouterr().out
            body, _, verdict = printed.rpartition("\n\n")
            if f"[{verify_mod.MARK_FAILED}]" in body and verdict.strip().endswith("OK"):
                contradictions.append(_identifiers(case, label))

    assert contradictions == [], "\n".join(contradictions)


@pytest.mark.parametrize("lang", SUPPORTED)
def test_the_advisory_marker_is_explained_exactly_when_it_is_used(corpus, anchors, capsys, lang):
    """Condition (b). A marker the reader cannot interpret leaves them unable
    to tell a documented limit from something that went wrong."""
    for case in corpus:
        for label, arguments in [("no anchors", {}), *anchors]:
            result = verify_mod.verify_package(case.path, **arguments)
            _print_verify(result, Catalog(lang))
            printed = capsys.readouterr().out
            shown = f"  [{verify_mod.MARK_ADVISORY}] " in printed
            legend = Catalog(lang).line("verify.advisory_legend", mark=verify_mod.MARK_ADVISORY)
            assert legend != "verify.advisory_legend", f"no {lang} text for the legend"
            assert (legend in printed) is shown, _identifiers(case, label)
            assert printed.count(legend) <= 1, "said once"


@pytest.mark.parametrize("lang", SUPPORTED)
def test_the_cli_never_prints_a_raw_catalogue_key(corpus, anchors, capsys, lang):
    """`check.tsa_trust_store_loaded` reached the screen untranslated, because
    nothing compared the names this module writes with the catalogue."""
    for case in corpus:
        for label, arguments in [("no anchors", {}), *anchors]:
            _print_verify(verify_mod.verify_package(case.path, **arguments), Catalog(lang))
            printed = capsys.readouterr().out
            raw = re.findall(r"\bcheck\.[a-z_]+", printed)
            assert raw == [], f"{_identifiers(case, label)}: {raw}"


@pytest.mark.parametrize("lang", SUPPORTED)
def test_every_check_name_has_text_in_both_languages(lang):
    """The same two directions `test_i18n.py` already holds for rule ids: a
    check with no entry prints its key, and an entry for a check the code
    cannot write is text nobody will ever read."""
    catalogue = load(lang).get("ui", {})
    names = recorded_check_names()

    missing = sorted(name for name in names if f"check.{name}" not in catalogue)
    orphans = sorted(
        key.removeprefix("check.")
        for key in catalogue
        if key.startswith("check.") and key.removeprefix("check.") not in names
    )

    assert missing == [], f"no {lang} text for: {missing}"
    assert orphans == [], f"{lang} describes checks the code cannot write: {orphans}"
