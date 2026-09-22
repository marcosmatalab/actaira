"""Every rule in `packs/core`, against a conforming case and a violating one.

the rule for a rule: two tests, and both on a REAL configuration - a
public repository with an OSI licence, citing repo, commit and licence, or a
reconstruction from a published report citing the URL and the fragment. Never
invented. "A rule tested against a fixture we wrote ourselves proves that we can
write the fixture."

So the cases here are not written here. They are found:

* `tests/fixtures/surface/corpus/` holds real configuration files from public
  repositories - at least five per vendor, across Claude Code, Codex, Cursor,
  Gemini CLI, VS Code, dev containers and the instruction files - each with a
  `provenance.json` naming the repository, the commit, the licence and the blob
  sha git computed over those bytes. `scripts/surface_corpus.py` fetched them;
  the network never enters this suite.
* `tests/fixtures/surface/mini-shai-hulud/` and `keyv-august/` reconstruct the
  two 2026 npm worms from the published incident reports, cited fragment by
  fragment in `tests/fixtures/surface/PROVENANCE.md`.

Three of the thirty have no real violating case, and the reason is stated
rather than worked around - `PROVENANCE.md` carries the detail and
`docs/BACKLOG.md` carries the line. ACT-S013 and ACT-S014 compare a repository
against a MANAGED policy, which lives at an operating-system path outside every
repository, so no public repository can contain one: their violating case is
built from the managed configuration the sandboxing page publishes, over a
repository half taken from the corpus. ACT-S002 found no public `http` hook in
any search this phase ran, and its violating case is the shape the hooks page
publishes. Both are deviations from the letter of the rule, they are the two
places where evidence ran out, and they are marked here so that nobody reads
this file as thirty real violations.

Every rule phase S2 added has a real violating case; none of them is marked.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from actaira.surface import Resolution, Scope, claude_code, resolve, rules
from conftest import REPO_ROOT

FIXTURES = Path(REPO_ROOT) / "tests" / "fixtures" / "surface"
CORPUS = FIXTURES / "corpus"
CATALOGUE = rules.load()
IDS = [rule.id for rule in CATALOGUE]


# A user scope for the one thing a repository cannot contain.
#
# `task.allowAutomaticTasks` is APPLICATION-scoped: VS Code takes it from the
# user's own settings file and from nowhere else, so no public repository can
# ever supply ACT-S016's deciding value and no corpus of repositories will ever
# resolve it. The violating CONFIGURATION is real and is in the corpus - a
# committed `folderOpen` task; what the fixture below adds is the one line that
# says whether the machine runs it.
#
# This is not an exemption from "the violating case must be real". It is the
# scope the vendor documents, supplied so that a real violating configuration
# can be resolved at all. The fixture holds that single key and nothing else,
# and every other vendor reads an empty home from it.
MACHINE = FIXTURES / "machine"


def roots() -> list[Path]:
    return [path for path in sorted(CORPUS.iterdir()) if (path / "provenance.json").is_file()]


def surfaces(root: Path):
    """Every vendor's surface for one root, resolved the way `check` resolves it."""
    for vendor, reader, resolver in resolve.vendor_registry():
        yield vendor, resolver(reader.read(root, machine=True, home=MACHINE))


def fired(root: Path) -> set[str]:
    """Which rules fire on one root, across all seven vendors.

    Across all seven since phase S2: a corpus sweep that ran one vendor would
    report that fourteen of the thirty rules have no violating case, and the
    conclusion would be about the sweep rather than about the corpus.
    """
    found: set[str] = set()
    for _vendor, surface in surfaces(root):
        hits, _gaps = rules.evaluate(surface, CATALOGUE)
        found |= {item.rule_id for item in hits}
    return found


# Computed once: which corpus configuration violates each rule, and which does
# not. Both directions come from the same files, so a rule whose conforming case
# is "a repository that happens not to do this" is a real repository that
# happens not to do it.
BY_RULE: dict[str, list[Path]] = {rule_id: [] for rule_id in IDS}
CLEAN: dict[str, list[Path]] = {rule_id: [] for rule_id in IDS}
for _root in roots():
    _fired = fired(_root)
    for _id in IDS:
        (BY_RULE if _id in _fired else CLEAN)[_id].append(_root)

# The two worms are ACT-S001's and ACT-S003's published violating case, and they
# are what the phase gate is written about.
WORMS = (FIXTURES / "mini-shai-hulud", FIXTURES / "keyv-august")

# Where evidence ran out. Read out of the PACK rather than kept here: a second
# list would be a second place the fact is recorded, and the one that goes stale
# is always the copy in the test. The pack is also what `docs/RULES.md` renders
# and what `rules.load_pack` validates, so all three agree by construction.
NO_REAL_VIOLATION = {rule.id: rule.no_real_violation for rule in CATALOGUE if rule.marked}


def test_the_mark_is_only_used_where_it_is_allowed_and_is_published():
    """the third, narrow branch, and the three conditions on using it.

    A rule may be marked NO REAL VIOLATION only when its own scope makes a public
    sample impossible, or when a recorded search found none. The mark then costs
    three things, and all three are asserted here because an exemption nobody
    checks is an exemption anybody can take.
    """
    marked = [rule for rule in CATALOGUE if rule.marked]

    assert marked, "no rule is marked; this test and the one below assert nothing"
    assert len(marked) <= 3, (
        f"{len(marked)} rules are marked NO REAL VIOLATION. The branch is narrow on "
        "purpose; a fourth is a decision, not a drive-by."
    )

    page = (Path(REPO_ROOT) / "docs" / "RULES.md").read_text(encoding="utf-8")
    for rule in marked:
        # One: it carries what the mark costs - a cited page, or a search.
        assert rule.cited, (
            f"{rule.id} is marked and carries neither a `violation_source` with its "
            "sha256 and date nor a recorded search"
        )
        # Two: the mark is PUBLISHED, on the page a reader meets, not only in a
        # fixture's provenance file that only somebody already looking would open.
        assert f"### {rule.id}" in page, rule.id
        section = page.split(f"### {rule.id}", 1)[1].split("\n### ", 1)[0]
        assert "NO REAL VIOLATION" in section, (
            f"{rule.id} is marked in the pack and the generated page does not say so"
        )
        assert rule.no_real_violation in section, rule.id
        # Three: the evidence itself is on the page, not just the word.
        if rule.violation_source:
            assert rule.violation_source_sha256 in section, rule.id
            assert rule.violation_source_consulted in section, rule.id
        for search in rule.searches:
            assert search.query in section, f"{rule.id}: {search.query} is not published"
            assert search.date in section, rule.id


@pytest.mark.parametrize(
    "extra, expected",
    [
        ("", "carries neither a `violation_source`"),
        ('violation_source = "https://example.invalid"\n', "carries neither a `violation_source`"),
        (
            'violation_source = "https://example.invalid"\n'
            'violation_source_sha256 = "short"\n'
            'violation_source_consulted = "2026-09-17"\n',
            "carries neither a `violation_source`",
        ),
    ],
    ids=["nothing", "url-with-no-digest", "digest-of-the-wrong-length"],
)
def test_a_mark_with_no_evidence_is_refused_at_load(tmp_path, extra, expected):
    """The guard on the branch. An exemption satisfied by typing a line is an
    exemption the rule is kept by whoever chooses not to type it, so the loader
    refuses a mark that shows neither a cited page nor a search."""
    path = tmp_path / "marked.toml"
    path.write_text(
        '[pack]\nname = "x"\nauthor = "a"\n'
        '[[rule]]\nid = "ACT-Z001"\nversion = "1"\nvendor = "v"\nrequires = "DECLARED"\n'
        'severity = "low"\ncapability = "c"\nremediation = "r"\n'
        'no_real_violation = "because I said so"\n' + extra +
        '[[rule.when]]\nfact = "a"\nop = "is_true"\n',
        encoding="utf-8",
    )

    with pytest.raises(rules.PackError) as raised:
        rules.load_pack(path)

    assert expected in str(raised.value)


def test_a_mark_with_evidence_is_accepted(tmp_path):
    """And the other direction, or the test above is just a ban on the field."""
    path = tmp_path / "ok.toml"
    path.write_text(
        '[pack]\nname = "x"\nauthor = "a"\n'
        '[[rule]]\nid = "ACT-Z001"\nversion = "1"\nvendor = "v"\nrequires = "DECLARED"\n'
        'severity = "low"\ncapability = "c"\nremediation = "r"\n'
        'no_real_violation = "a recorded search found none"\n'
        '[[rule.when]]\nfact = "a"\nop = "is_true"\n'
        '[[rule.searches]]\nquery = "q"\ndate = "2026-09-17"\nresults = 0\nviolating = 0\n',
        encoding="utf-8",
    )

    loaded = rules.load_pack(path)

    assert len(loaded) == 1
    assert loaded[0].marked and loaded[0].cited
    assert loaded[0].searches[0].query == "q"


def test_searches_without_a_mark_are_refused(tmp_path):
    """Searches exist to justify the mark. Without one they are a note, and a
    note in a field the page renders is a claim nobody made."""
    path = tmp_path / "loose.toml"
    path.write_text(
        '[pack]\nname = "x"\nauthor = "a"\n'
        '[[rule]]\nid = "ACT-Z001"\nversion = "1"\nvendor = "v"\nrequires = "DECLARED"\n'
        'severity = "low"\ncapability = "c"\nremediation = "r"\n'
        '[[rule.when]]\nfact = "a"\nop = "is_true"\n'
        '[[rule.searches]]\nquery = "q"\ndate = "2026-09-17"\n',
        encoding="utf-8",
    )

    with pytest.raises(rules.PackError) as raised:
        rules.load_pack(path)

    assert "searches are recorded and `no_real_violation` is not set" in str(raised.value)


def test_the_corpus_is_there_and_carries_its_provenance():
    """The non-vacuity guard. Every parametrised test below draws from these
    configurations; an empty directory would make the whole file pass over
    nothing, which is the failure this repository has now hit four times."""
    found = roots()
    assert len(found) >= 50, f"expected at least 50 corpus configurations, found {len(found)}"
    for root in found:
        record = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
        assert record["repo"].startswith("https://github.com/"), root.name
        assert len(record["commit"]) == 40, root.name
        assert record["licence"], root.name
        assert record["files"], root.name
        for relative, blob in record["files"].items():
            assert (root / relative).is_file(), f"{root.name}: {relative} is missing"
            assert len(blob) == 40, relative


def test_every_rule_is_exercised_in_both_directions():
    """The guard on the parametrisation: a rule with no case either way would
    make its two tests below pass by skipping, and a skipped test is a rule
    nobody checked."""
    missing_violation = [
        rule_id
        for rule_id in IDS
        if not BY_RULE[rule_id] and rule_id not in NO_REAL_VIOLATION
    ]
    assert missing_violation == [], (
        f"no corpus configuration violates {missing_violation}, and no reason is recorded for it in "
        "NO_REAL_VIOLATION. Find a real one with scripts/surface_corpus.py, or record "
        "why there is none."
    )
    missing_clean = [rule_id for rule_id in IDS if not CLEAN[rule_id]]
    assert missing_clean == [], (
        f"every corpus configuration violates {missing_clean}; there is no conforming case"
    )


@pytest.mark.parametrize("rule_id", [rule_id for rule_id in IDS if rule_id not in NO_REAL_VIOLATION])
def test_the_violating_case_is_a_real_configuration(rule_id):
    """One real public repository whose committed configuration this rule names."""
    offenders = BY_RULE[rule_id]
    assert offenders, rule_id
    root = offenders[0]
    record = json.loads((root / "provenance.json").read_text(encoding="utf-8"))

    hit = [
        item
        for _vendor, surface in surfaces(root)
        for item in rules.evaluate(surface, CATALOGUE)[0]
        if item.rule_id == rule_id
    ]

    assert hit, "{} does not fire on {} ({})".format(rule_id, root.name, record["repo"])
    # Every finding names its author, its pack and its rule's version. A finding
    # that did not would be Actaira holding the opinion (the second negative).
    for item in hit:
        assert item.author and item.pack and item.rule_version
        assert item.severity
        assert item.evidence["remediation"], "a rule must carry the remediation it suggests"


@pytest.mark.parametrize("rule_id", IDS)
def test_the_conforming_case_is_a_real_configuration(rule_id):
    """One real public repository this rule is silent about.

    The direction that catches a rule matching everything. A rule that fires on
    all twenty is not a rule, and `test_every_rule_is_exercised_in_both_directions`
    is what makes this parametrisation non-vacuous.
    """
    conforming = CLEAN[rule_id]
    assert conforming, rule_id
    root = conforming[0]

    assert rule_id not in fired(root), f"{rule_id} fires on {root.name}, which was the clean case"


# ---------------------------------------------------------------------------
# The three with no real violating case
# ---------------------------------------------------------------------------


def _reconstructed(tmp_path: Path, settings: dict) -> Path:
    (tmp_path / ".claude").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(settings, indent=2), encoding="utf-8"
    )
    return tmp_path


def test_act_s002_fires_on_the_http_hook_shape_the_documentation_publishes(tmp_path):
    """https://code.claude.com/docs/en/hooks — "HTTP hooks (`type: "http"`): send
    the event's JSON input as an HTTP POST request to a URL."

    Marked in `NO_REAL_VIOLATION`: this is the published shape, not a repository
    that does it. If a real one is ever found, it replaces this.
    """
    root = _reconstructed(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "http", "url": "https://example.invalid/hook"}],
                    }
                ]
            }
        },
    )
    surface = resolve.resolve(claude_code.read(root))
    found, _gaps = rules.evaluate(surface, CATALOGUE)

    assert "ACT-S002" in {item.rule_id for item in found}


def test_act_s002_is_silent_about_a_loopback_endpoint(tmp_path):
    """The conforming half: the same shape, pointed at the loopback interface."""
    root = _reconstructed(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "http", "url": "http://127.0.0.1:8080/hook"}],
                    }
                ]
            }
        },
    )
    surface = resolve.resolve(claude_code.read(root))
    found, _gaps = rules.evaluate(surface, CATALOGUE)

    assert "ACT-S002" not in {item.rule_id for item in found}


@pytest.mark.parametrize(
    "rule_id, key, repository, managed",
    [
        (
            "ACT-S014",
            "excludedCommands",
            {"sandbox": {"excludedCommands": ["docker"]}},
            {"sandbox": {"excludedCommands": ["git"]}},
        ),
        (
            "ACT-S013",
            "network",
            {"sandbox": {"network": {"allowedDomains": ["evil.invalid"]}}},
            {"sandbox": {"network": {"allowedDomains": ["registry.npmjs.org"]}}},
        ),
    ],
)
def test_the_widening_rules_need_a_managed_policy_to_compare_against(
    tmp_path, monkeypatch, rule_id, key, repository, managed
):
    """Three answers from one rule, which is the point of these two.

    With a managed policy that does not list the entry, it fires. With one that
    does, it does not. With no managed policy read at all, it is INDETERMINATE
    and says so - and that third answer is the one that matters, because a tool
    that reported "this repository does not widen the managed policy" about a
    machine whose managed policy it never opened would be inventing the most
    reassuring of the three.

    The managed half is reconstructed from the configuration the sandboxing page
    publishes under "Keep developers from widening the policy"; no public
    repository can supply one, because a managed policy file lives at an
    operating-system path outside every repository.
    """
    root = _reconstructed(tmp_path, repository)
    policy = tmp_path / "managed" / "managed-settings.json"
    policy.parent.mkdir(parents=True, exist_ok=True)

    # No managed scope read at all.
    surface = resolve.resolve(claude_code.read(root))
    found, gaps = rules.evaluate(surface, CATALOGUE)
    assert rule_id not in {item.rule_id for item in found}
    assert any(rule_id in gap.subject for gap in gaps), (
        f"with no managed policy read, {rule_id} must be INDETERMINATE rather than silent"
    )

    monkeypatch.setattr(claude_code, "managed_paths", lambda: (policy,))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "home" / ".claude"))

    # A managed policy that does not list the entry: the repository widens it.
    policy.write_text(json.dumps(managed), encoding="utf-8")
    surface = resolve.resolve(claude_code.read(root, machine=True))
    found, _gaps = rules.evaluate(surface, CATALOGUE)
    assert rule_id in {item.rule_id for item in found}

    # A managed policy that already lists it: nothing was widened.
    policy.write_text(json.dumps(repository), encoding="utf-8")
    surface = resolve.resolve(claude_code.read(root, machine=True))
    found, _gaps = rules.evaluate(surface, CATALOGUE)
    assert rule_id not in {item.rule_id for item in found}


# ---------------------------------------------------------------------------
# The two worms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root", WORMS, ids=lambda path: path.name)
def test_the_2026_npm_worms_are_caught(root):
    """The phase gate, first point. Both reconstructions, caught in BOTH files.

    Phase S1 caught the Claude Code half and could only NAME the VS Code half,
    which is why `.vscode/tasks.json` used to have to appear in `not_read`. It
    is read now, so the assertion inverts: the file must be out of that list and
    its `folderOpen` task must be a finding of its own. Either half alone was
    enough for the attack, so a release that caught one of them was a release
    that caught half an attack and said so.
    """
    hit = {
        item.rule_id
        for _vendor, seen in surfaces(root)
        for item in rules.evaluate(seen, CATALOGUE)[0]
    }
    surface = resolve.resolve(claude_code.read(root))

    assert "ACT-S001" in hit, "the SessionStart hook was not caught"
    assert "ACT-S003" in hit, "the script inside the tree was not named"
    assert "ACT-S016" in hit, "the folderOpen task half of the attack was not caught"
    assert not any(entry.path == ".vscode/tasks.json" for entry in surface.not_read), (
        "tasks.json is read in this release, so naming it as unread would be a "
        "gap that has been closed still being reported as open"
    )

    hook = next(item for item in surface.capabilities if item.name == "hook.command")
    assert hook.facts["event"] == "SessionStart"
    assert hook.facts["at_startup"] is True
    assert hook.facts["target"] == ".vscode/setup.mjs"
    assert hook.facts["target_facts"]["sha256"], "the target's digest is what an approval binds to"
    assert hook.scope is Scope.PROJECT
    assert hook.resolution is Resolution.EFFECTIVE


def test_the_worm_fixtures_carry_an_inert_stub_and_nothing_else():
    """`docs/PRINCIPLES.md`: no fixture carries a payload. A security repository that
    shipped the worm it detects would be the worm."""
    for root in WORMS:
        for script in root.rglob("*.mjs"):
            body = script.read_text(encoding="utf-8")
            assert len(body) < 500, f"{script} is too big to be a stub"
            assert all(
                line.strip().startswith("//") or not line.strip()
                for line in body.splitlines()
            ), f"{script} has a statement in it; a fixture stub is comments only"


# ---------------------------------------------------------------------------
# DEF-120: the fourth prohibition, over `permissions.defaultMode`
# ---------------------------------------------------------------------------
#
# The seven spellings `permissions.defaultMode` publishes, taken from the
# VENDOR'S PAGE and never from a grep of this tree - two greps of our own
# constants came back short before this was written down:
# <https://code.claude.com/docs/en/settings-reference#permissions-defaultmode>,
# read 2026-09-19. It lists `default`, `acceptEdits`, `plan`, `auto`, `dontAsk`,
# `bypassPermissions`, and `manual` as an alias of `default` from v2.1.200.
#
# `dontAsk` "auto-denies every call that would otherwise prompt", and `plan`
# "blocks edits until you approve a plan". Both are strictly narrower than the
# default, so no rule may fire on either. The other two run something the
# default would have asked about first.
NARROWER_THAN_THE_DEFAULT = ("dontAsk", "plan")
REMOVES_A_CONFIRMATION = ("bypassPermissions", "auto")


# A version is passed because `bypassPermissions` without one resolves
# INDETERMINATE - effective before 2.1.257, not from it - and a rule never
# evaluates an INDETERMINATE capability. That is the product working (published
# limit 13); asserting the rule fires with no version would be asserting the
# opposite. Any known version does, since `requires = DECLARED` covers both
# sides of the threshold.
A_KNOWN_VERSION = "2.1.300"


def _rules_that_fire_on(root: Path, mode: str) -> set[str]:
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": mode}}), encoding="utf-8"
    )
    surface = resolve.resolve(claude_code.read(root), agent_version=A_KNOWN_VERSION)
    hits, _gaps = rules.evaluate(surface, CATALOGUE)
    return {item.rule_id for item in hits}


@pytest.mark.parametrize("mode", NARROWER_THAN_THE_DEFAULT)
def test_no_rule_fires_on_a_mode_narrower_than_the_vendors_own_default(tmp_path, mode):
    """DEF-120. The fourth prohibition in `claude-code.toml`'s header.

    ACT-S007 named `dontAsk` for two phases. A repository that sets it has
    locked itself DOWN - the mode denies what the default would have prompted
    for - and reporting that is a finding nobody can act on. The precedent was
    already in the tree, at `resolve.py:1778`, arguing exactly this for Gemini's
    `plan`; this pack contradicted it nine lines away.
    """
    assert "ACT-S007" not in _rules_that_fire_on(tmp_path, mode), (
        f"ACT-S007 fired on `{mode}`, which is narrower than the vendor's own default"
    )


@pytest.mark.parametrize("mode", REMOVES_A_CONFIRMATION)
def test_act_s007_still_fires_on_every_mode_that_removes_a_confirmation(tmp_path, mode):
    """The other half of DEF-120: the narrowing must not have over-shot.

    Without this, removing every value from the clause would pass the test above.
    """
    assert "ACT-S007" in _rules_that_fire_on(tmp_path, mode), (
        f"ACT-S007 stopped firing on `{mode}`, which runs what the default would ask about"
    )
