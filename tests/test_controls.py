"""The control layer's own guards: the mapping, the boundary, and the languages.

Three files in this repository decide whether its claims are true rather than
merely written, and this is one of them. A dangling edge between a control and
an obligation is invisible at runtime: the dashboard is green and nothing in
the system disagrees. So every edge is walked in both directions here, and
every piece of prose the layer publishes is checked in both languages.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from actaira.controls import registry
from actaira.controls.model import Control, ControlResult, Method, Outcome, localized_boundary
from actaira.governance.catalog import ALL_OBLIGATIONS, Checkability
from actaira.i18n.catalog import load as load_catalog

CONTROLS = registry.all_controls()
CONTROL_IDS = {c.id for c in CONTROLS}
OBLIGATIONS = {o.id: o for o in ALL_OBLIGATIONS}
LANGS = ("en", "es")

# The tier a control's method is allowed to serve. A deterministic control
# bound to an organizational obligation means one of the two is misclassified,
# and the catalogue is the thing that should have changed.
METHOD_TIERS = {
    Method.DETERMINISTIC: {Checkability.MACHINE_CHECKABLE},
    Method.GENERATED: {Checkability.GENERATABLE},
    Method.JUDGED: {Checkability.EVIDENCE_JUDGED},
}


def test_there_is_at_least_one_control():
    assert CONTROLS, "the registry imported nothing; a control module failed to load"


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
def test_every_control_names_obligations_that_exist(control: Control):
    for obligation_id in control.obligation_ids:
        assert obligation_id in OBLIGATIONS, (
            f"{control.id} claims to bear on {obligation_id}, which is not in the catalogue"
        )


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_every_obligation_names_controls_that_exist(obligation):
    """The other direction, which is the one that quietly overstates coverage."""
    for control_id in obligation.controls:
        assert control_id in CONTROL_IDS, (
            f"{obligation.id} claims control {control_id}, which is not registered"
        )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
def test_a_control_only_serves_a_tier_its_method_can_serve(control: Control):
    allowed = METHOD_TIERS[control.method]
    for obligation_id in control.obligation_ids:
        tier = OBLIGATIONS[obligation_id].checkability
        assert tier in allowed, (
            f"{control.id} is {control.method.value} and is bound to {obligation_id}, "
            f"which the catalogue calls {tier.value}. One of the two is wrong."
        )


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_a_tier_that_promises_a_control_has_one(obligation):
    if obligation.checkability is Checkability.ORGANIZATIONAL:
        assert not obligation.controls
        return
    assert obligation.controls, (
        f"{obligation.id} is {obligation.checkability.value} and has no control behind it. "
        "A tier is a claim about what the tool can do; an empty one is that claim unbacked."
    )


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_an_organizational_obligation_carries_a_written_reason(obligation):
    """"Not covered" with no reason is indistinguishable from "not built yet"."""
    if obligation.checkability is not Checkability.ORGANIZATIONAL:
        return
    assert len(obligation.why_not) > 80, (
        f"{obligation.id} is organizational and its why_not is missing or too short to be a reason"
    )


@pytest.mark.parametrize("obligation", ALL_OBLIGATIONS, ids=lambda o: o.id)
def test_every_obligation_explains_its_tier_in_both_languages(obligation):
    for lang in LANGS:
        row = load_catalog(lang).get("governance", {}).get(obligation.id, {})
        assert row.get("why_not"), f"{obligation.id} has no why_not in {lang}.json"


# ---------------------------------------------------------------------------
# The boundary
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
@pytest.mark.parametrize("lang", LANGS)
def test_every_control_states_its_boundary_in_both_languages(control: Control, lang: str):
    row = load_catalog(lang).get("controls", {}).get(control.id, {})
    assert row.get("covers"), f"{control.id} has no `covers` in {lang}.json"
    assert row.get("does_not_cover"), f"{control.id} has no `does_not_cover` in {lang}.json"


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
def test_the_spanish_boundary_is_not_the_english_one(control: Control):
    """For a capability row, identity is correctness. For a translation, identity
    is the defect.

    This repository has shipped a Spanish section carrying English text and
    passing an equality test, which is where that sentence comes from. The
    check is here so it cannot happen again on this surface.
    """
    english = localized_boundary(control.id, "en")
    spanish = localized_boundary(control.id, "es")
    assert spanish[0] != english[0], f"{control.id} `covers` is untranslated"
    assert spanish[1] != english[1], f"{control.id} `does_not_cover` is untranslated"


@pytest.mark.parametrize("lang", LANGS)
def test_the_catalogue_invents_no_controls(lang: str):
    named = set(load_catalog(lang).get("controls", {}))
    assert not named - CONTROL_IDS, (
        f"{lang}.json describes controls that are not registered: {sorted(named - CONTROL_IDS)}"
    )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
def test_a_control_carries_its_boundary_on_every_outcome(control: Control, tmp_path):
    """Including INCONCLUSIVE, which is the one that used to lose it.

    An empty target makes most controls come back inconclusive, which is
    exactly the path that shipped with no scope attached until design note
    D-45. The result a caller gets here must still say what was and was not
    being answered.
    """
    from actaira.controls import engine

    result = control(engine.load_target(tmp_path, role="provider"))
    assert isinstance(result, ControlResult)
    assert result.covers, f"{control.id} returned {result.outcome.value} with no `covers`"
    assert result.does_not_cover, (
        f"{control.id} returned {result.outcome.value} with no `does_not_cover`"
    )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
def test_a_generated_control_never_claims_satisfied(control: Control, tmp_path):
    from actaira.controls import engine

    if control.method is not Method.GENERATED:
        return
    result = control(engine.load_target(tmp_path, role="provider"))
    assert result.outcome is not Outcome.SATISFIED


SCORE_WORDS = ("score", "percent", "compliant", "rating", "grade", "readiness", "maturity")


def _score_like_keys(node, trail=()):
    """Every KEY in the payload whose name reads as a score, with its path.

    Keys and not values, deliberately, and the difference is the point. The
    Annex IV text this layer quotes contains the word "compliant" because the
    Regulation does, and a guard that banned the word from the output would ban
    the tool from quoting the law. What must never appear is a *field* that
    reports a score, so the walk looks at names, and the numeric walk below
    looks for the shape of a score wherever it might hide.
    """
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).lower()
            if any(word in lowered for word in SCORE_WORDS):
                found.append(("/".join([*trail, str(key)]), value))
            found.extend(_score_like_keys(value, (*trail, str(key))))
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            found.extend(_score_like_keys(value, (*trail, str(index))))
    return found


def _fractions(node, trail=()):
    """Floats, which is the shape a fabricated score takes when it hides."""
    found = []
    if isinstance(node, float):
        found.append("/".join(trail))
    elif isinstance(node, dict):
        for key, value in node.items():
            found.extend(_fractions(value, (*trail, str(key))))
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            found.extend(_fractions(value, (*trail, str(index))))
    return found


def test_a_control_run_counts_and_never_divides(tmp_path):
    from actaira.controls import engine

    run = engine.run(engine.load_target(tmp_path, role="provider"))
    payload = run.to_dict()

    offenders = [path for path, _ in _score_like_keys(payload) if not path.endswith("counts_not_a_score")]
    assert not offenders, f"a control run emitted a score-like field: {offenders}"
    assert not _fractions(payload), f"a control run emitted a fraction: {_fractions(payload)}"
    assert sum(run.counts().values()) == len(run.results)


def test_the_score_guard_can_actually_fail():
    """A guard nobody proved could fail is decoration. This one can."""
    assert _score_like_keys({"summary": {"compliance_score": 87}})
    assert _fractions({"summary": {"ratio": 0.87}})


def test_duplicate_registration_is_refused():
    def _never(_target: object) -> None:  # pragma: no cover - never invoked
        raise AssertionError("a duplicate registration must be refused before this runs")

    existing = CONTROLS[0].id
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(Control(id=existing, obligation_ids=(), method=Method.DETERMINISTIC, run=_never))


# ---------------------------------------------------------------------------
# DEF-97: a dependency named in four places and declared in none
# ---------------------------------------------------------------------------
def test_the_marking_robustness_control_names_the_library_it_needs():
    """Pillow is in the `dev` extra, and the control abstains without it.

    Four locations in the source told the reader Pillow was declared and
    `pyproject.toml` did not list it, so a clean `pip install -e ".[dev]"`
    produced a checkout where this control reported INCONCLUSIVE for a
    missing library while the documentation said the library was there. Both
    halves are asserted: the declaration exists, and the control still names
    what it needs rather than failing, because "I could not check" and "it is
    not marked" are different answers.
    """
    import re
    import tomllib

    from conftest import REPO_ROOT

    declared = tomllib.loads((Path(REPO_ROOT) / "pyproject.toml").read_text(encoding="utf-8"))
    dev = declared["project"]["optional-dependencies"]["dev"]
    assert any(re.match(r"(?i)pillow\b", item) for item in dev), (
        "Pillow is named as a dev dependency in the source and the docs; declare it here"
    )

    control = registry.get("ACT-C-15-MARK-ROBUSTNESS")
    assert "Pillow" in (control.run.__doc__ or ""), (
        "the control must say which library it needs, so a reader can tell an "
        "incomplete environment from a broken control"
    )
