"""The two policy routes, and the ways a decision can be asked for wrongly.

Policy is the step that turns everything else into an answer: an artifact or
an agent goes in, and ALLOW, DENY or REVIEW comes out with the rules and the
evidence that caused it. It was reachable from the terminal only.

Three properties matter more than the rest here, and each has tests below.

**The browser and the terminal must decide the same thing.** The handler loads
the document with the engine's loader and calls `policy.decide`, so the tests
that matter compare the route's answer with the engine's, not with a literal.

**A policy that does not load is a usage error.** Never a warning, never a
default-allow. Carrying on with the rules that happened to parse is how a
pipeline ends up governed by half a document, and a 200 with a partial
decision would be worse than a refusal.

**The date is an input.** A waiver expires; a policy therefore decides
differently on different days. A decision that quietly used `today()` could
not be reproduced tomorrow, so `on` is sent and echoed back.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import threading
from pathlib import Path

import pytest

from actaira.web import server as web
from conftest import REPO_ROOT, corpus_build

BOUNDARY = "----actairapolicy"
POLICY = (Path(REPO_ROOT) / "policies" / "production-model.yaml").read_text(encoding="utf-8")
AGENT = (Path(REPO_ROOT) / "examples" / "agent-ticket-triage.yaml").read_text(encoding="utf-8")
ON = "2026-01-01"


@pytest.fixture(scope="module")
def running():
    httpd = web.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


def multipart(file_bytes: bytes, filename: str = "subject.bin", **fields: str) -> bytes:
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value.encode("utf-8") + b"\r\n"
        )
    chunks.append(
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n\r\n'.encode()
        + file_bytes + b"\r\n"
    )
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(chunks)


def post(address, path: str, body: bytes, **overrides: str) -> tuple[int, dict]:
    headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Host": f"{address[0]}:{address[1]}",
    }
    headers.update(overrides)
    connection = http.client.HTTPConnection(address[0], address[1], timeout=60)
    try:
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        try:
            return response.status, json.loads(payload)
        except ValueError:
            return response.status, {}
    finally:
        connection.close()


def clean_artifact() -> bytes:
    return corpus_build.build_safetensors(
        {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}, b"\x00" * 64
    )


def gadget_artifact() -> bytes:
    """A pickle that reduces through `posix.system`, which the policy denies."""
    return corpus_build.craft_reduce("posix", "system", ("id",), 4)


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


def test_show_returns_the_document_the_engine_parsed(running):
    from actaira.policy import load_policy_text

    status, payload = post(running, "/api/policy/show",
                           multipart(POLICY.encode("utf-8"), "production-model.yaml"))
    assert status == 200, payload
    assert payload["document"] == load_policy_text(POLICY).to_dict()
    assert payload["policy"]["id"] == "production-model"


def test_show_carries_the_digest_a_decision_names(running):
    """A decision names the policy it was made under. A reader who cannot
    recompute that digest cannot check the two are the same document."""
    from actaira.policy import load_policy_text

    status, payload = post(running, "/api/policy/show", multipart(POLICY.encode("utf-8")))
    assert status == 200
    assert payload["policy"]["digest"] == load_policy_text(POLICY).digest


@pytest.mark.parametrize(
    "broken",
    [
        "",
        "- not a mapping\n",
        "policy: x\nrules: notalist\n",
        "policy: x\nrules:\n  - id: a\n    effect: purple\n",
        "policy: x\nrules:\n  - id: a\n    effect: deny\n    when: {no_such_predicate: 1}\n",
    ],
)
def test_a_policy_that_does_not_load_is_refused(running, broken):
    status, payload = post(running, "/api/policy/show", multipart(broken.encode("utf-8")))
    assert status == 400, payload
    assert payload["error"]["code"] in ("bad_policy", "empty_file", "empty_declaration")
    assert payload["error"]["message"]


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


def rules_contributing(decision: dict, outcome: str) -> set[str]:
    return {row["rule"] for row in decision["proof"] if row.get("contributes") == outcome}


def test_the_same_document_denies_two_subjects_for_different_reasons(running):
    """The whole point, end to end, and the assertion is about the *reason*.

    Both of these come back DENY under the shipped policy, and comparing the
    verdicts alone would have looked like the route ignoring its subject. It
    is not: the clean safetensors is denied by `execution-surface-read-end-to-
    end`, because the policy requires a coverage surface that format does not
    have, and the pickle is denied by that *and* by a critical finding. The
    proof is where a decision says which, and that is what is compared.
    """
    clean = post(running, "/api/policy/check",
                 multipart(clean_artifact(), "clean.safetensors", policy_document=POLICY, on=ON))
    gadget = post(running, "/api/policy/check",
                  multipart(gadget_artifact(), "trojan.pkl", policy_document=POLICY, on=ON))
    assert clean[0] == 200 and gadget[0] == 200, (clean, gadget)

    denied_clean = rules_contributing(clean[1]["decision"], "deny")
    denied_gadget = rules_contributing(gadget[1]["decision"], "deny")
    assert "no-high-severity-findings" in denied_gadget, gadget[1]["decision"]["proof"]
    assert "no-high-severity-findings" not in denied_clean, clean[1]["decision"]["proof"]


def test_the_decision_is_the_one_the_engine_makes(running):
    """Compared with the engine rather than with a literal, because a literal
    here would be a second opinion about what the policy says."""
    from actaira.inspect import inspect_artifact
    from actaira.policy import decide, load_policy_text
    from actaira.subject import for_artifact

    blob = gadget_artifact()
    status, payload = post(running, "/api/policy/check",
                           multipart(blob, "trojan.pkl", policy_document=POLICY, on=ON))
    assert status == 200, payload

    scratch = Path(REPO_ROOT) / ".pytest_cache" / "policy-subject.pkl"
    scratch.parent.mkdir(parents=True, exist_ok=True)
    scratch.write_bytes(blob)
    try:
        report = inspect_artifact(scratch)
        report.path = "trojan.pkl"
        expected = decide(load_policy_text(POLICY), [for_artifact(report)],
                          on=dt.date.fromisoformat(ON)).to_dict()
    finally:
        scratch.unlink(missing_ok=True)
    assert payload["decision"]["decision"] == expected["decision"]
    assert payload["decision"]["proof"] == expected["proof"]


def test_an_agent_can_be_the_subject_of_a_policy(running):
    """The step that closes the loop: an agent's findings and routes become
    ALLOW, DENY or REVIEW under a document somebody wrote down."""
    status, payload = post(running, "/api/policy/check",
                           multipart(AGENT.encode("utf-8"), "agent.yaml",
                                     policy_document=POLICY, subject="agent", on=ON))
    assert status == 200, payload
    assert payload["subject"]["kind"] == "agent"
    assert payload["subject"]["name"] == "ticket-triage"
    assert payload["decision"]["decision"] in ("allow", "deny", "review")


def test_the_decision_echoes_the_date_it_was_made_on(running):
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy_document=POLICY, on=ON))
    assert status == 200
    assert payload["decided_on"] == ON


def test_a_rule_with_nothing_to_evaluate_goes_to_review_not_to_false(running):
    """The doctrine, asserted where a reader can see it.

    No attestation is supplied, so the signer rule cannot be evaluated. It has
    to come back as a review outcome rather than quietly failing, because a
    predicate that returned false for "I do not know" would let
    `deny: when the signer is untrusted` pass on a run with no signature.
    """
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy_document=POLICY, on=ON))
    assert status == 200
    proof = payload["decision"]["proof"]
    review = [row for row in proof if row.get("contributes") == "review"]
    assert review, f"nothing went to review with no attestation supplied: {proof}"
    # And it says why it could not be evaluated, rather than just shrugging.
    assert any("unevaluable" in json.dumps(row.get("evidence", {})) for row in review), review


# ---------------------------------------------------------------------------
# What it refuses
# ---------------------------------------------------------------------------


def test_a_check_with_no_policy_says_so(running):
    status, payload = post(running, "/api/policy/check", multipart(clean_artifact()))
    assert status == 400
    assert payload["error"]["code"] == "missing_policy"


def test_a_check_whose_policy_is_blank_says_so(running):
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy="   \n  "))
    assert status == 400
    assert payload["error"]["code"] == "missing_policy"


def test_a_check_whose_policy_is_broken_is_refused(running):
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy_document="- not a mapping\n"))
    assert status == 400
    assert payload["error"]["code"] == "bad_policy"


def test_a_document_sent_under_the_scan_policy_field_is_not_mistaken_for_one(running):
    """The two fields called `policy` that are not the same thing.

    `/api/scan` has meant the *import* policy by that name since it existed:
    `strict` or `known-bad`, and the same upload carries it when the subject
    is an artifact. A document sent under that name reaches `_scan_options`
    first, which refuses it as an unknown scan policy. That is the right
    answer and a confusing one, so the document has its own field and this
    test is why.
    """
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy=POLICY, on=ON))
    assert status == 400
    assert payload["error"]["code"] in ("bad_policy", "missing_policy")


@pytest.mark.parametrize("subject", ["bundle", "system", "model", "../artifact", "polic y"])
def test_a_subject_kind_outside_the_two_is_refused(running, subject):
    """Stated by the caller, and validated against a fixed set before any of
    it reaches code that reasons with it."""
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy_document=POLICY, subject=subject))
    assert status == 400, payload
    assert payload["error"]["code"] == "bad_subject"


@pytest.mark.parametrize("subject", ["", "artifact", "ARTIFACT", " artifact "])
def test_the_subject_field_is_normalised_before_it_is_matched(running, subject):
    """An empty field means the default, and case and space are forgiven.

    Worth pinning because the alternative, refusing `Artifact`, would be a
    400 for a request that said exactly what it meant.
    """
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy_document=POLICY, subject=subject, on=ON))
    assert status == 200, payload
    assert payload["subject"]["kind"] == "artifact"


def test_a_subject_declared_as_an_agent_that_is_not_one_is_refused(running):
    status, payload = post(running, "/api/policy/check",
                           multipart(clean_artifact(), policy_document=POLICY, subject="agent"))
    assert status == 400
    assert payload["error"]["code"] in ("bad_declaration", "declaration_not_text")


def test_a_policy_past_the_field_ceiling_is_refused(running):
    """The policy rides as a form field, so it inherits that ceiling rather
    than the 2 GiB one an artifact gets."""
    huge = POLICY + ("\n# pad" * (web.MAX_FIELD_BYTES // 5))
    status, _ = post(running, "/api/policy/check", multipart(clean_artifact(), policy_document=huge))
    assert status in (400, 413)


@pytest.mark.parametrize("route", ["/api/policy/show", "/api/policy/check"])
def test_the_policy_routes_refuse_a_cross_origin_post(running, route):
    status, payload = post(running, route, multipart(POLICY.encode("utf-8"), policy_document=POLICY),
                           Origin="https://evil.example")
    assert status == 403
    assert payload["error"]["code"] == "cross_origin"


@pytest.mark.parametrize("route", ["/api/policy/show", "/api/policy/check"])
def test_the_policy_routes_refuse_a_rebound_host(running, route):
    status, payload = post(running, route, multipart(POLICY.encode("utf-8"), policy_document=POLICY),
                           Host="evil.example")
    assert status == 403
    assert payload["error"]["code"] == "bad_host"


@pytest.mark.parametrize("route", ["/api/policy/show", "/api/policy/check"])
def test_the_policy_routes_answer_no_get(running, route):
    connection = http.client.HTTPConnection(running[0], running[1], timeout=30)
    try:
        connection.request("GET", route, headers={"Host": f"{running[0]}:{running[1]}"})
        assert connection.getresponse().status == 404
    finally:
        connection.close()


def test_no_decision_document_carries_a_score(running):
    """The refusal this project is built on, checked on the newest surface.

    A decision is ALLOW, DENY or REVIEW with the rules that caused it. A
    percentage anywhere in this payload would be the first one in the tool.
    """
    status, payload = post(running, "/api/policy/check",
                           multipart(gadget_artifact(), "trojan.pkl", policy_document=POLICY, on=ON))
    assert status == 200
    blob = json.dumps(payload).lower()
    for word in ("\"score\"", "\"grade\"", "\"rating\"", "\"percent\""):
        assert word not in blob, f"the decision payload carries {word}"
