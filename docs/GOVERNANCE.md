# The EU AI Act, as something a machine can run

Actaira models a set of obligations from Regulation (EU) 2024/1689, decides
which of them bind **a given role on a given date**, and runs executable
controls that record what was observed. It does not decide whether anyone
complies.

The counts on this page are not repeated from the catalogue: they live in
[`FIGURES.md`](FIGURES.md), written by `make figures` from
`src/actaira/governance/catalog.py`, and in the README under a contract that
refuses a tree where any of them has drifted. What is written here is the
shape of the thing, which is what a number cannot carry.

---

## The three questions, in order

Every governance answer in Actaira is the product of three inputs, and getting
any of them wrong changes the answer:

```
        role                 date              evidence
          |                    |                   |
          v                    v                   v
   who you are in       what is in force     what was actually
   the supply chain     on that day          observed, and by what
          |                    |                   |
          +--------------------+-------------------+
                               |
                               v
                 which obligations bind, which are
                 forthcoming, and which of them any
                 file could ever speak to at all
```

### Role

The Regulation places different duties on different parties, and a tool that
ignores that reports obligations at people they do not have. Actaira models the
roles the Regulation names, and nothing beyond them: there is no invented role
hierarchy, because the Regulation does not have one.

`actaira governance clock --role <role>` prints what binds.

### Date

Obligations apply from different dates, several carry a transitional grace
period, and some are not in force yet. Asking "what applies" without a date is
asking a question with no answer, so the date is an input rather than
`today()`, and a run can be reproduced years later.

A date in the future is a legitimate question: *what will bind us when Annex
III applies?* The clock answers it, and marks those obligations forthcoming
rather than in force.

### Evidence

An obligation binds whether or not Actaira can see anything about it. Actaira
reports what it observed, separately from what binds, and never merges the two
into a single figure.

---

## Checkability tiers

Every obligation carries a tier, and the tier says **what kind of thing could
ever decide it**. This is the part of the model that keeps the tool honest,
because it is written down per obligation rather than inferred.

| Tier | What it means | The rule it carries |
|---|---|---|
| **Machine-checkable** | A deterministic control parses bytes and decides. No model, reproducible anywhere. | May only answer for what it read. |
| **Generatable** | The tool drafts the artifact the obligation asks for. | Outcome is never SATISFIED: a draft nobody signed is not evidence. |
| **Evidence-judged** | Whether a supplied document addresses the obligation is a judgement. A model makes it, a verifier checks every span it cites, and it abstains when it cannot ground the answer. | How often it declines is published, and what was measured was the pipeline. |
| **Organizational** | Nothing readable from a system can show it. | Carries `why_not`, a written reason. |

Two consequences worth stating plainly:

- **Machine-checkable is not compliant.** It means a control could look. What
  it found is a separate fact.
- **Partial evidence is not a satisfied obligation.** The control records what
  it observed and what it did not, and the two are printed together.

Zero obligations are marked as fully supported, and that is a result rather
than an oversight. An obligation reaches that rating only if reading model
files could carry it alone, and none can. Moving one up a tier is a code
change plus a measurement, never an edit to a field: a test fails if an
obligation claims to be machine-checkable with no control bound to it, and
fails if an organizational one carries no written reason.

---

## Why there is no compliance score

Actaira refuses to produce one, and the refusal is enforced rather than
promised: a test greps every finished document for `score`, `grade`, `rating`
and `percent` and fails on any of them.

The argument is short. Weighting obligations of different kinds against each
other needs a number nobody has. A figure like "82% compliant" is built by
choosing those weights silently, and the choice is invisible in the output.
What Actaira publishes instead is the shape of the answer:

```
N applicable obligations
  M have technical evidence from this run
  K are drafted but unsigned, so not evidence
  J are organizational and outside what any file can show
```

Anyone can add those up. Nobody can un-add a percentage.

---

## Controls

A control is a function with a declared obligation, a declared input, and four
possible outcomes. It records what it looked at and what it did not, and a
control that could not read its input reports INCONCLUSIVE naming the reason
rather than failing quietly.

The registry is checked in both directions: an obligation that claims a
control must have one, and a control must name an obligation that exists.

```bash
actaira controls list
actaira controls run <path> --role provider
```

One control needs Pillow, `ACT-C-15-MARK-ROBUSTNESS`, which re-encodes an
image to see whether a marking survives. When Pillow is absent it reports
INCONCLUSIVE naming the missing library, which is the behaviour a control is
supposed to have.

---

## The signed evidence dossier

`actaira governance pack` produces a governance package: the obligations that
bound a role on a date, what each control observed, and the evidence each one
rests on, signed and verifiable offline by somebody who has neither the
artifacts nor this tool.

It is a record of an assessment, not a certificate. The distinction is in the
document itself, which states what was read and what was outside its reach.

---

## What remains organizational, and why that is the honest answer

A large part of the Regulation is about what an organisation *does*: risk
management processes, human oversight arrangements, post-market monitoring,
record-keeping practice. None of that is readable from a model file, and a
tool that reported on it would be reporting on a form somebody filled in.

Those obligations carry `why_not`: a written reason, per obligation, for why
no file can show it. They are not hidden, not scored down, and not quietly
dropped from the denominator. They appear in the output as what they are.

---

## Further reading

- [`CONCEPTS.md`](CONCEPTS.md) for the command index and the vocabulary.
- [`FIGURES.md`](FIGURES.md) for every count on this page, measured.
- [`EVALUATION.md`](EVALUATION.md) for the marking survival measurement and
  the judged tier's abstention behaviour.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) for what the tool assumes and what it
  refuses to assume.
