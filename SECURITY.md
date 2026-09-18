# Security policy

Three things: how to report a vulnerability, which versions get fixes, and what
this tree actually consists of. Everything else this page used to say described
the model scanner, which left at 3.0.0, and a security policy that describes a
surface the tree does not have is the same defect as a compatibility page doing
it. The scanner's threat model, its section on the crafted artifacts its corpus
generated, and its build-attestation recipe are at tag `v2.3.0` and on
`archive/model-scanner`, unedited.

The threat model for the new input is [below](#threat-model-reading-somebody-elses-repository).
It was deliberately held open until phase S1 so that it would describe code that
exists rather than code that was intended.

## Reporting a vulnerability

**This snapshot publishes no disclosure channel, and inventing one here would
be worse than saying so.** Actaira is a local repository: there is no hosted
issue tracker, no advisory page and no monitored address that belongs to the
project rather than to whoever is holding this copy. A security policy that
printed an address nobody reads would fail in exactly the way this project
exists to refuse - a green tick over something that was never checked.

So: **whoever distributes this tree is the one who has to open a channel, and
naming it is a precondition of distributing it.** Until then, report to the
person who gave you this copy, through whatever channel you already have with
them.

What helps, in rough order of usefulness:

1. The input, or a script that generates it. A generator is easier to review
   than a binary, and it lets a hostile input be described rather than
   attached. Please do not attach a working exploit against somebody else's
   repository or machine.
2. The exact command and the output you got, against the output you expected.
3. The version: `actaira --version`, and which snapshot of the source you are
   running, since there is no commit to name.

**What to expect.** This is a single-maintainer project with no company behind
it, so the honest commitment is: acknowledgement within seven days, an
assessment within thirty, and a fix released as soon as one exists. There is no
bug bounty. If you want credit in the release notes, say so; if you want none,
say that instead.

**Disclosure.** Coordinated, with a default of 90 days from the first
acknowledgement, shortened by agreement once a fix is out. If a fix takes
longer than that, the delay will be explained rather than used to postpone your
disclosure indefinitely.

## Supported versions

| Version | Supported |
|---|---|
| 3.0.x | yes |
| 2.x | no, and it is a different tool: see `archive/model-scanner` |
| 1.x, 0.x | no |

This table is about which code receives fixes, and not about documents. A
package written by an earlier version still verifies here, and a contract
published by one is still readable:
[`docs/CONTRACTS.md`](docs/CONTRACTS.md) records which schema versions are
current and which are superseded and kept.

## What is in this tree

Seven commands, and the scope of a report is what they do.

- **`actaira check`** reads agent configuration files out of a repository, and
  with `--machine` out of the user and managed scopes too. It executes nothing
  it reads and opens no socket. Its input is the one nobody on your side wrote,
  so it has a threat model of its own
  [below](#threat-model-reading-somebody-elses-repository).
- **`actaira diff`** reads TWO such inputs and compares them. It is the only
  command here that runs another program, and the programs are `git ls-tree` and
  `git cat-file`: it materialises each ref's tree into a temporary directory it
  made, and it never checks either ref out. It shares the threat model below and
  widens it, because the attacker now also chooses what `git` is asked about and
  what lands in that directory; the rows that are its own say so.
- **`actaira seal`** writes a signed baseline of a surface. It carries no
  content: a path and the names a third party chose travel as
  `H(salt || domain || value)` and the salt stays in the output directory,
  beside the package and never inside it.
- **`actaira scan`** reads session transcripts an agent already wrote to disk.
  The input is somebody's conversation, so arguments and results travel as
  salted digests unless `--with-content` is passed.
- **`actaira watch`** runs your command with an MCP proxy interposed and
  assembles what the proxy saw. It launches a child process that you named.
- **`actaira verify`** checks an attestation package offline. It opens no
  socket, and a test fails the suite if it does.
- **`actaira keygen`** creates, rotates and revokes an Ed25519 signing key on
  disk.

Three properties are worth reporting a violation of. **Nothing on the decision
path reads the clock, the network or the disk beyond what it was handed.**
**No command writes outside the output directory it was given**, and none
modifies the agent configuration or environment it read. And **no record claims
more than its capture level allows**: an L0 transcript was written by the
audited agent about itself, and it says so rather than being presented as
evidence.

A finding that is not about those, or about the offline and no-content
guarantees above, is a bug rather than a vulnerability, and
[`docs/BACKLOG.md`](docs/BACKLOG.md) is where it goes.

## Threat model: reading somebody else's repository

`actaira check` is the first command whose input nobody on your side wrote. It
runs on a clone of a pull request, on a dependency you vendored, on a repository
a colleague sent you a link to. Every byte it reads - the settings files, the
paths inside them, the skill definitions, the git index - is chosen by whoever
opened that pull request.

**`actaira diff` runs on the same input twice over, and adds two things to it.**
It asks `git` about a repository the attacker contributed to, and it writes that
repository's blobs into a directory. Neither is in the paragraph above and both
are in the table below, because a threat model that stopped at the command it
was first written for is a threat model about the previous release.

The whole argument for how `diff` obtains those trees is in
`src/actaira/surface/diff.py`, design notes D-293 and D-294, and is not repeated
here: only `ls-tree` and `cat-file`, argv as a list and never a shell, `--`
before every ref, `--no-pager --no-optional-locks -c core.fsmonitor=false -c
core.hooksPath=<nonexistent>`, and no checkout of any kind. What follows is what
an attacker gets to try against that, and what stops each one.

That inverts the usual reading of this project's refusals. "Actaira never runs
what it reads" is not only a claim about honesty; it is the control that stops
this command being the delivery mechanism for the thing it was pointed at.

### The attacker, and what they want

Somebody who can put a file in a repository you will read. They are not
assumed to have anything else: no account on your machine, no network position,
no ability to make you type a command other than `actaira check` or
`actaira diff`. In the `diff` case they additionally choose the CONTENT OF THE
TREE at one of the two refs, and - where you pass a ref from the pull request
itself, which is what the GitHub Action does - part of the argument list.

What they want, in the order the defences below are argued:

1. **Execution.** Get `check` to run something they wrote.
2. **Disclosure.** Get `check` to read a file outside the repository and put its
   contents somewhere they can see - a CI log, a JSON artifact, a PR comment.
3. **Denial.** Get `check` to hang, exhaust memory, or crash, so the answer
   never arrives and the pull request goes in unreviewed.
4. **A false clean answer.** Get `check` to report nothing wrong about a
   repository that is. This is the worst of the four, because the other three
   are visible and this one is not.

### The defences, each with the test that holds it down

| What they try | What stops it | Test |
|---|---|---|
| A hook, helper or MCP entry whose command runs their script | Nothing in the package executes what it reads, ever. Of a referenced script `check` records four facts - exists, inside the tree, tracked by git, sha256 - and no fifth | `test_surface.py::test_nothing_the_configuration_names_is_ever_run` plants a script that would leave a sentinel behind and asserts the sentinel is absent, while asserting the digest was still taken |
| A path like `../../../etc/shadow`, so a fact about a file outside the tree reaches the report | Every path is resolved and compared against the resolved root before it is opened; outside is a recorded fact, not a read | `test_a_path_that_leaves_the_tree_is_reported_as_outside_it` |
| A symlink in the tree pointing at `/etc`, which a textual `..` check would call inside | Both sides are `Path.resolve()`d, not `os.path.abspath`ed | `test_a_symlink_out_of_the_tree_is_outside_it` (POSIX; skipped on Windows, where creating a symlink needs a privilege) |
| A path that is absolute on another platform - a UNC share `\\host\share`, a drive letter `C:/...` - so a POSIX reader joins it to the root and calls it inside | A path absolute in any platform's syntax is outside, checked before the join | `test_a_path_absolute_on_another_platform_is_outside_here_too`, over nine paths including a backslash that is a legal POSIX filename |
| A settings file large enough to exhaust memory | A byte ceiling checked with `stat` before the bytes are requested, so a hostile file costs a stat | `test_a_settings_file_over_the_ceiling_is_a_cause_and_not_a_read` |
| A deep or enormous `.claude/skills/` tree | Depth and file-count ceilings, and the ceiling is reported when it bites rather than silently truncating | `test_surface_rules.py` corpus walk, and `claude_code.frontmatter_files` |
| A document whose shape is wrong at any level - a list where an object belongs, `null` where a handler belongs | Every level is checked before it is walked; a wrong shape is a stated cause | `test_a_hostile_shape_anywhere_is_survived`, eight documents, and `test_a_settings_document_of_the_wrong_shape_is_a_cause_and_not_a_crash` |
| A corrupt `.git/index`, to crash the tracked-file lookup | Parsed defensively with explicit bounds; a version this release does not read returns a cause, never a `False` | `test_the_git_index_is_read_rather_than_git_being_run` |
| A secret planted in a hook command or URL, so `check` copies it into a CI log | No literal command, URL or header is printed without `--with-content`; a literal is reduced to a sha256 at the reader | `test_no_literal_reaches_the_report_without_with_content`, with one high-entropy and one low-entropy secret, over both the console and the JSON |
| A malformed settings file, hoping it is read as empty and reported as "no hooks" | An unparsed file never reaches a consumer as a mapping; it is INDETERMINATE with the cause | `test_invalid_json_is_indeterminate_and_never_an_empty_configuration` |
| Configuration this release does not read, hoping silence is taken for absence | Every file seen and not read is printed in the report's "not read" list | `test_the_2026_npm_worms_are_caught` asserts `.vscode/tasks.json` appears there |

Four more belong to `diff`, and each one is a thing the attacker can only try
because that command asks `git` about their tree and writes what it answers.

| What they try, against `diff` | What stops it | Test |
|---|---|---|
| A path in their tree that would write outside the extraction: `../escaped`, `/etc/shadow`, `a/../../b` | Every listed path is checked component by component and then resolved against the destination before anything is written. Git's own tree format forbids these, and that is a statement about a producer rather than about this input | `test_diff.py::test_a_listed_path_that_would_escape_the_extraction_is_not_written`, over five spellings, with a legitimate path asserted to survive so the check is not a ban on writing |
| A symlink in their tree pointing at `/etc`, so the next write under it lands outside | A symlink's blob is materialised as an ORDINARY FILE holding the target text. No link is ever created, so there is no link for a later write to follow | `test_diff.py::test_a_diff_runs_no_git_hook_and_leaves_the_tree_byte_for_byte` digests the whole tree before and after; nothing outside the temporary directory is written at all |
| A branch or tag named `--upload-pack=...` or `--exec=sh`, so the ref becomes a git option | A ref beginning with `-` is refused before git is invoked, and `--` is passed on every command line as well. Two layers, because the separator is one edit away from being dropped by somebody adding an argument | `test_diff.py::test_a_ref_that_starts_with_a_dash_is_refused`, over three spellings, asserting both the module's refusal and exit code `2` from the command line |
| A tree with a million files, or a gigabyte of them, so the command exhausts the disk or the memory of the runner | A file-count ceiling and a byte ceiling, both read off `git ls-tree -l` BEFORE a byte is written, so a tree that is refused costs one command and leaves no half-written directory. Each round of `cat-file` is bounded by bytes rather than by object count, because the answer is buffered whole | `test_diff.py::test_a_tree_over_the_file_ceiling_is_refused_and_nothing_is_written`, which also asserts nothing was written |
| A `post-checkout`, `pre-commit` or fsmonitor hook in their repository, hoping the comparison checks a ref out | Neither ref is checked out and no git subcommand that runs a hook is ever invoked. `tests/test_diff.py::test_only_two_git_subcommands_are_ever_run` reads the module's own source and fails on a third | `test_diff.py::test_a_diff_runs_no_git_hook_and_leaves_the_tree_byte_for_byte` plants five hooks that would each leave a sentinel, and a second test gives the same plant a real `git checkout` so a plant that could never fire cannot make the first one vacuous |

### What this model does not cover

- **`--with-content` is your decision.** It exists because an operator
  sometimes needs the literal, and with it the literals go wherever the output
  goes. Do not pass it in CI.
- **`--machine` reads your own home directory and the managed policy.** It is
  off by default and should stay off when the subject is a pull request: a
  repository cannot change either scope, so reading them answers nothing about
  it and puts your own configuration in the report.
- **The configuration is not the behaviour.** Nothing here detects an attack
  that leaves no file. Published limit 11, limit 12 for what a vendor pushes
  from a server, and they are limits rather than gaps to be closed.
- **A clean report is not safety.** Published limit 9: no rule fired means no
  rule named it, and a repository can be badly configured for a reason none of
  the rules describes.
- **`diff` trusts `git` to be `git`.** It runs whatever `git` is on the PATH of
  the machine it runs on. Nothing here verifies that binary, and nothing could
  without a trust anchor this tool does not ship. If your PATH is under an
  attacker's control you have lost already, and that is outside this model.
- **A sealed baseline says nothing about who approved it.** `seal` signs what
  the surface WAS; binding that digest to a person and expiring their approval
  when it moves is the register phase P1 is about, and it does not exist.
- **The corpus script reaches the network, and it is not the tool.**
  `scripts/surface_corpus.py` is run by a person, outside the package and
  outside the suite. `tests/netguard.py` is armed and a release check asserts it
  still bites.
