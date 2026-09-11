"""What this environment accepts, kept apart from what cryptography proved.

Design note D-226. `attest/trust.py` answers a question about mathematics: did
this signature verify against this key, does this chain reach an anchor you
supplied. This file answers a question about an organisation: is that signer
one we accept, does a model from this registry have to be pinned, may we use an
MCP server from a publisher who does not publish digests.

They are different questions and 2.1 already refused to merge them - a verified
signature never implied a trusted signer. What it did not have was a place to
write the second one down, so "trusted" meant "a fingerprint was in the keyring
file somebody passed on the command line", which is a trust decision recorded
in a shell history.

Three rules shape this module.

**Absence is UNKNOWN, never UNTRUSTED.** An environment with no trust policy has
not refused to trust anything; it has not been asked. A tool that read "no
policy" as "trust nothing" would produce a DENY on every first run and teach
people to pass `--no-verify`.

**A rule that could not be evaluated says so.** The result carries three states
and a list of reasons, and the policy language reads the state through
`trust_state` - which raises `Unevaluable` and becomes REVIEW when there is
nothing to read. That is the same discipline as every other predicate.

**It decides, it does not verify.** Nothing here checks a signature. It is
handed what the verifier concluded and applies the local rules to it, so the
two halves can be tested separately and neither can quietly start doing the
other's job.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .miniyaml import loads as parse_yaml

SCHEMA_VERSION = "trust-policy/v1"


class TrustPolicyError(ValueError):
    """A trust policy that cannot be loaded. Never a warning."""


class TrustState(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


_DIGEST = re.compile(r"^(sha256:)?[0-9a-f]{7,64}$")


@dataclass(frozen=True)
class SourceRule:
    connector: str
    require_revision_pin: bool = False
    require_declared_digest: bool = False


@dataclass(frozen=True)
class McpRule:
    publisher: str = ""
    require_digest: bool = False
    require_publisher: bool = False


@dataclass
class TrustPolicy:
    """The declared answer to "what does this environment accept"."""

    trusted_signers: list[str] = field(default_factory=list)
    trusted_tsa_roots: list[str] = field(default_factory=list)
    source_rules: list[SourceRule] = field(default_factory=list)
    mcp_rules: list[McpRule] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "trusted_signers": [{"fingerprint": item} for item in sorted(self.trusted_signers)],
            "trusted_tsa_roots": sorted(self.trusted_tsa_roots),
            "source_rules": [
                {
                    "connector": rule.connector,
                    "require_revision_pin": rule.require_revision_pin,
                    "require_declared_digest": rule.require_declared_digest,
                }
                for rule in self.source_rules
            ],
            "mcp_rules": [
                {
                    "publisher": rule.publisher,
                    "require_digest": rule.require_digest,
                    "require_publisher": rule.require_publisher,
                }
                for rule in self.mcp_rules
            ],
        }


@dataclass
class TrustResult:
    """What the trust policy concluded, and why.

    `reasons` explains the state and nothing else. `notes` holds the rules
    that did not apply - a trusted_signers list on a subject that carries no
    signer, say. Keeping them apart matters at the top of a terminal: a reader
    scanning the first line of an UNTRUSTED result has to see what failed, not
    a note about a rule that was never relevant.
    """

    state: TrustState
    reasons: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Rules that applied to this subject and could not be decided, because the
    # caller supplied nothing to decide them against. Defect DEF-85: a rule
    # in this list used to leave no trace at all, so a policy requiring a
    # published digest returned TRUSTED with `checked: ['source:huggingface']`
    # and the reason "every applicable rule was satisfied" - about a rule that
    # had never run.
    unevaluated: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reasons": self.reasons,
            "checked": self.checked,
            "notes": self.notes,
            "unevaluated": self.unevaluated,
        }


def load(path: Path) -> TrustPolicy:
    return load_text(Path(path).read_text(encoding="utf-8"), source=str(path))


def load_text(text: str, source: str = "") -> TrustPolicy:
    try:
        document = parse_yaml(text)
    except ValueError as exc:
        raise TrustPolicyError(f"trust policy does not parse: {exc}") from exc
    if not isinstance(document, dict):
        raise TrustPolicyError("a trust policy must be a mapping at the top level")

    declared = str(document.get("schema_version", SCHEMA_VERSION))
    if declared != SCHEMA_VERSION:
        raise TrustPolicyError(
            f"this document declares {declared!r} and this release reads {SCHEMA_VERSION!r}"
        )

    signers: list[str] = []
    for index, item in enumerate(document.get("trusted_signers") or [], 1):
        fingerprint = item.get("fingerprint") if isinstance(item, dict) else item
        if not isinstance(fingerprint, str) or not fingerprint:
            raise TrustPolicyError(f"trusted_signers[{index}] has no fingerprint")
        signers.append(fingerprint)

    source_rules: list[SourceRule] = []
    for index, item in enumerate(document.get("source_rules") or [], 1):
        if not isinstance(item, dict) or not item.get("connector"):
            raise TrustPolicyError(f"source_rules[{index}] needs a `connector`")
        source_rules.append(
            SourceRule(
                connector=str(item["connector"]),
                require_revision_pin=bool(item.get("require_revision_pin", False)),
                require_declared_digest=bool(item.get("require_declared_digest", False)),
            )
        )

    mcp_rules: list[McpRule] = []
    for item in document.get("mcp_rules") or []:
        if not isinstance(item, dict):
            raise TrustPolicyError("each mcp_rule must be a mapping")
        mcp_rules.append(
            McpRule(
                publisher=str(item.get("publisher", "")),
                require_digest=bool(item.get("require_digest", False)),
                require_publisher=bool(item.get("require_publisher", False)),
            )
        )

    return TrustPolicy(
        trusted_signers=signers,
        trusted_tsa_roots=[str(item) for item in document.get("trusted_tsa_roots") or []],
        source_rules=source_rules,
        mcp_rules=mcp_rules,
        source=source,
    )


def check(
    policy: TrustPolicy | None,
    *,
    signer_fingerprint: str = "",
    connector: str = "",
    revision: str = "",
    declared_digests: bool | None = None,
    mcp_servers: list[Any] | None = None,
) -> TrustResult:
    """Apply the local rules to what the verifier and the connectors reported.

    Returns UNKNOWN when there is no policy, and that is the important case.
    An environment that has not written its trust rules down has not refused
    anything, and a tool that reported UNTRUSTED there would be asserting a
    decision nobody made.
    """
    if policy is None:
        return TrustResult(
            state=TrustState.UNKNOWN,
            reasons=["no trust policy was supplied, so this environment has not said what it accepts"],
        )

    reasons: list[str] = []
    notes: list[str] = []
    checked: list[str] = []
    unevaluated: list[str] = []
    failed = False

    if signer_fingerprint:
        checked.append("signer")
        if policy.trusted_signers and signer_fingerprint not in policy.trusted_signers:
            failed = True
            reasons.append(
                f"the signer {signer_fingerprint[:19]} is not in this environment's trusted_signers"
            )
    elif policy.trusted_signers:
        # A policy that names signers and a subject with none is not a
        # refusal, it is a gap: nothing was signed, so nothing failed the
        # check. The caller decides whether an unsigned subject is acceptable,
        # through an ordinary policy rule about signatures.
        notes.append("this subject carries no signer, so the trusted_signers list did not apply")

    for rule in policy.source_rules:
        if connector and rule.connector != connector:
            continue
        if not connector:
            continue
        checked.append(f"source:{rule.connector}")
        if rule.require_revision_pin and not _pinned(revision):
            failed = True
            reasons.append(
                f"{rule.connector} requires an immutable revision and this one is "
                f"{revision or 'absent'}"
            )
        if rule.require_declared_digest:
            if declared_digests is None:
                unevaluated.append(
                    f"{rule.connector} requires the source to publish digests, and this run did "
                    "not say whether it does"
                )
            elif not declared_digests:
                failed = True
                reasons.append(
                    f"{rule.connector} requires the source to publish digests and it did not"
                )

    for server in mcp_servers or []:
        applicable = [
            rule
            for rule in policy.mcp_rules
            if not rule.publisher or rule.publisher == getattr(server, "publisher", "")
        ]
        if not applicable:
            continue
        checked.append(f"mcp:{server.name}")
        # `mcp_rule`, not `rule`: the source-rule loop above binds `rule` to a
        # SourceRule, and these are McpRules with different fields.
        for mcp_rule in applicable:
            if mcp_rule.require_digest and not server.pinned:
                failed = True
                reasons.append(f"{server.name} must carry a digest and its reference is a tag")
            if mcp_rule.require_publisher and not getattr(server, "publisher", ""):
                failed = True
                reasons.append(f"{server.name} must record a publisher and it does not")

    if not checked:
        return TrustResult(
            state=TrustState.UNKNOWN,
            reasons=["no rule in this trust policy applied to this subject"],
            checked=checked,
            notes=notes + reasons,
            unevaluated=unevaluated,
        )
    if failed:
        return TrustResult(
            state=TrustState.UNTRUSTED,
            reasons=reasons,
            checked=sorted(set(checked)),
            notes=notes,
            unevaluated=unevaluated,
        )
    if unevaluated:
        # Something that applies could not be decided, so this environment has
        # not accepted the subject - it has not finished asking. UNKNOWN is
        # the third state and this is what it is for. See DEF-85.
        return TrustResult(
            state=TrustState.UNKNOWN,
            reasons=[
                "a rule that applies to this subject could not be evaluated with what this run "
                "supplied"
            ],
            checked=sorted(set(checked)),
            notes=notes + reasons,
            unevaluated=unevaluated,
        )
    return TrustResult(
        state=TrustState.TRUSTED,
        reasons=["every applicable rule was satisfied"],
        checked=sorted(set(checked)),
        notes=notes,
    )


def _pinned(revision: str) -> bool:
    return bool(revision) and bool(_DIGEST.fullmatch(revision))
