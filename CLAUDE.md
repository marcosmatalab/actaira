# Instructions for an agent working in this repository

This file is what its name says: instructions for a coding agent in this tree.
It is not the governance document. That is
[`docs/PRINCIPLES.md`](docs/PRINCIPLES.md), and it holds the three claims, the
four negatives, the capture levels, the work rules and what is forbidden. Read
it before changing anything here; nothing below repeats it.

There is a `CLAUDE.md` here at all because this repository's product READS other
people's `CLAUDE.md` files. A tool that audits agent instruction files and
carries none of its own would be making a point about somebody else that it did
not apply to itself.

## Before you change anything

- Read [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md). The four negatives are
  invariants: a change that violates one is rejected without discussion.
- One phase, one objective, one gate, and the gate is written first.
- Every design decision goes in the code with its rejected alternative, in five
  lines or fewer.
- No published figure and no published picture without a command that produces
  it.

## Before you say it is done

The gate is `make all`, and it runs **in WSL, over a clean clone of HEAD**,
never over this working directory. A run over the mounted directory is an
iteration shortcut and answers for a tree nobody receives:

```bash
wsl -e bash -lc 'rm -rf /tmp/actaira-gate \
  && git clone -q /mnt/c/Users/Usuario/Desktop/actaira /tmp/actaira-gate \
  && cd /tmp/actaira-gate \
  && PY=/tmp/actaira-venv/bin/python make all'
```

It is green twice in a row and leaves `git status` empty, or it is not done.

## The two things that go wrong here

Both are written up in [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md) with their
defect numbers, and both are worth carrying in your head while you work.

- **A check that passes while checking something adjacent.** Before trusting a
  green, name what it exercised, not what its name says. When you build a check
  because something broke, in the same pass look for what else has that shape.
- **Two checks over one property with two definitions.** They do not add up,
  they cancel: each passes on its own terms and the failure hides between them.
  One calls the other, or both read the same place.

Every test that proves a negative carries a twin that plants the case and
demands the failure. A test that has never seen the thing happen cannot tell the
property from a plant that never arrives.
