# The seven commands

The complete reference. [`README.md`](../README.md) carries `check` and `diff`,
which are the two most people run; this page carries all seven, including the
four that sign, verify, record and key.

The list is seven and it is capped at eight. Adding an eighth is a decision;
a ninth requires removing one. `tests/test_cli.py` fails on a name promised
here that the parser does not have, and on one the parser has that nothing
promises.

```
actaira check     read this repo's agent configuration and resolve what it permits
actaira diff      say what capability changed between two moments
actaira seal      sign a baseline of the surface, carrying no content
actaira verify    verify a signed package offline
actaira keygen    create, rotate or revoke a signing key
actaira scan      read the sessions an agent already recorded on this machine (L0)
actaira watch     record a run from outside the agent, through an MCP proxy (L1)
```

The exit codes every one of them can produce are published in
[`COMPATIBILITY.md`](COMPATIBILITY.md), and a pipeline may branch on them.

---

## `actaira check` - what an agent can do here

`check` reads the agent configuration in this repository, resolves what it
actually permits across scopes and across vendors, and applies the rule packs.
It reads Claude Code, Codex CLI, Cursor, Gemini CLI, `.vscode/tasks.json` and
`.vscode/settings.json`, `devcontainer.json`, and the AGENTS.md, CLAUDE.md and
GEMINI.md instruction files, against 32 documented rules.

Each vendor is resolved against the precedence its own documentation publishes,
because those ladders disagree: Claude Code puts the user's file above the
project's, Gemini CLI puts the project's above the user's, and VS Code puts the
workspace above both. A repository's surface is therefore the UNION of the seven
per-vendor surfaces, and two vendors configuring the same MCP server are two
capabilities with the same digest rather than one row belonging to neither.

What still is not read is printed, not skipped - including the two scopes that
never leave a file at all: Cursor's team hooks, configured in a dashboard and
synced to members, and Codex's MDM and cloud-delivered requirements. Those are
INDETERMINATE with the cause named, never reported as absent.

```
actaira check                                   # this repository
actaira check --machine                         # and the user and managed scopes
actaira check --agent-version claude-code=2.1.257
actaira check --json                            # a surface/v1 document
actaira check --html report.html                # one self-contained file, no network
```

Three things it will not do. It never runs what it reads: of a script a hook
names it records four facts - whether it exists, whether it is inside the tree,
whether git tracks it, and its sha256 - and never a fifth. It prints no literal
command, URL or header without `--with-content`, because a settings file can
carry a secret and this report is pasted into CI logs. And it never guesses: a
capability whose answer depends on an agent version nobody stated comes back
INDETERMINATE with the threshold named, counted apart from everything else.

Exit codes: `0` nothing fired and nothing was unresolved, `1` a rule fired, `3`
nothing fired and something could not be resolved.

## `actaira diff` - what changed

```
actaira diff main HEAD                          # two refs in this repository
actaira diff --repo ../other main feature       # somewhere else
actaira diff --from-dir a --to-dir b            # two trees, no git
actaira diff main HEAD --html report.html       # and the same report as a page
actaira diff main HEAD --sarif actaira.sarif    # SARIF 2.1.0 for a code host
```

Neither ref is checked out. The two trees are read with `git ls-tree` and
`git cat-file`, which run no hook, apply no filter and no textconv driver, and
are written into a temporary directory that is removed on the way out. Your
working tree is not touched, your HEAD does not move, and a `post-checkout` hook
in the repository being examined is never given the chance to run - which would
be executing somebody else's code in order to answer a question about somebody
else's code. A ref that starts with a dash is refused with exit code `2`.

Five kinds of change, and a sixth thing that is not one of them. A capability
APPEARED, DISAPPEARED, WIDENED, NARROWED or CHANGED; and if either side could
not be resolved, the change is INDETERMINATE, listed separately with its cause
and never counted with the five. Widened and narrowed only exist where a fact's
own name says which value is the wider one, such as `guardrail_removed` going
from false to true. Everywhere else the answer is CHANGED, with both digests, so
a reviewer can decide for themselves rather than be told what to think about a
vendor's settings.

Exit codes: `1` a rule fired on something that was added or widened, `3` no rule
fired and something could not be resolved, `0` otherwise, `2` a usage error. A
finding that was already there and is still there is not one of these: that is
what `check` is for, and a command that answers "what changed" must not object to
what did not.

### The worked example, and the one both READMEs show a picture of

`scripts/demo_keyv.py` builds a throwaway repository with two commits, clean
and then compromised with the 4 August 2026 keyv wave reconstructed from the
published reports, and diffs them. It exits 1, because a rule fired on
something that arrived.

```console
$ python3 scripts/demo_keyv.py    # exits 1: a rule fired on something that arrived

What changed between HEAD~1 and HEAD

APPEARED: 1
  + claude-code  hook.command  .claude/settings.json  [project]
      after  effective  63a9a33e2cd93139
      ! ACT-S001  A hook runs a command on a session-start event, so opening a session runs it before anybody has read anything.
        rule written by  Actaira core core / high
        suggested by the rule: Remove the hook, or move it to ~/.claude/settings.json where it is yours rather than the repository's. A hook on a session-start event runs before you have read anything.
      ! ACT-S003  A hook runs a script inside this repository, so whoever can land a commit decides what it runs.
        rule written by  Actaira core core / medium
        suggested by the rule: Tie your approval to the script's sha256 rather than its path: the file at that path can change after you read it, and the hook will run whatever is there.

Could not be resolved on one side or the other: 2
  ? ACT-S016 on task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)
  ? a change to vscode task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)

Identical on both sides: 0
Seen and not read by this release: 7

Configuration DECLARES; it does not prove behaviour. A hook that is written is not a hook that ran, and one that is absent does not prove nothing ran (published limit 11).
```

`--lang es` is the same run in Spanish, and it is here rather than only in
`README.es.md` so that one harness compares both against the tool:

```console
$ python3 scripts/demo_keyv.py --lang es    # exits 1: una regla disparó sobre algo que llegó

Que ha cambiado entre HEAD~1 y HEAD

APARECE: 1
  + claude-code  hook.command  .claude/settings.json  [project]
      despues  effective  63a9a33e2cd93139
      ! ACT-S001  Un hook ejecuta un comando en un evento de arranque de sesión, así que abrir una sesión lo ejecuta antes de que nadie haya leído nada.
        regla escrita por  Actaira core core / high
        sugerido por la regla: Remove the hook, or move it to ~/.claude/settings.json where it is yours rather than the repository's. A hook on a session-start event runs before you have read anything.
      ! ACT-S003  Un hook ejecuta un script de este repositorio, así que quien pueda meter un commit decide qué se ejecuta.
        regla escrita por  Actaira core core / medium
        sugerido por la regla: Tie your approval to the script's sha256 rather than its path: the file at that path can change after you read it, and the hook will run whatever is there.

No se pudo resolver en uno de los dos lados: 2
  ? ACT-S016 on task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)
  ? a change to vscode task.command
      `task.allowAutomaticTasks` decides whether this runs; it is APPLICATION-scoped, so only the user's own settings file can set it, and no scope this run read says either way (run with --machine)

Identicas en los dos lados: 0
Visto y no leído en esta versión: 7

La configuración DECLARA; no demuestra comportamiento. Un hook escrito no es un hook que se ejecutó, y uno ausente no prueba que no se ejecutara nada (límite publicado 11).
```

---

## `actaira seal` - a signed baseline with no content in it

```bash
actaira keygen                                  # once
actaira seal --repo . --key ~/.actaira/signing-key.pem --out baseline/
actaira verify baseline/surface-seal.zip
```

`seal` writes a signed package holding a `seal/v1` document: every capability's
vendor, name, scope, resolution and merge rule, a salted reference to the file it
came from, and one sha256 over everything it observed. Plus the rules that fired,
each with its author and its pack. Plus counts of what could not be resolved and
what was not read. That is all of it.

**No paths, no commands, no URLs, no server names.** A path becomes
`H(salt || domain || path)`, and the salt stays with you in the output
directory, beside the package and never inside it - the package says so in its
own text. Everything a capability observed becomes one digest of the whole facts
mapping rather than one digest per fact, because `sha256(".env")` is the same
sixteen characters on every machine that has ever existed.

The point of it is the surface digest at the top. Approve that, and the approval
expires by itself the day the surface changes - which is published limit 14 with
the sign flipped, and the reason nothing here is keyed on a file name or a date.

## `actaira verify` - checking without trusting anyone

```bash
actaira verify baseline/surface-seal.zip
actaira verify baseline/surface-seal.zip --trusted-keyring keys.json --require-trust
```

Offline, always. Integrity and identity are separate answers: a package always
carries its own key, so integrity is always checkable, and "nobody vouched for
this key" is reported as exactly that rather than as a failure. Supply
`--trusted-keyring` or `--pubkey` to bind it to a key you already trust.

It also names what it verified. A package whose entries declare `seal/v1` is
checked against that contract's required fields and the version is reported; one
that declares a version this release does not publish fails, rather than being
reported OK with its meaning guessed at. Packages written by the 2.x model
scanner still verify, and declare no contract, which is not a defect in them.

## `actaira keygen` - the signing key

```bash
actaira keygen                      # create
actaira keygen --rotate             # retire the current key, keep verifying old packages
actaira keygen --revoke <key-id>    # nothing it ever signed is accepted again
```

Ed25519. The keyring lives beside the key. This is the key `actaira seal` signs
with; rotation and revocation are exercised end to end by the suite.

## `actaira watch` - recording from outside

`watch` puts an MCP proxy between the agent and its tool servers, runs your
command, and assembles what the proxy saw into one trace.

```console
$ actaira watch -- python -c "print('agent ran')"

agent ran
Recorded session <session-id> at capture level L1
  0 tool call(s) observed from outside the agent
  ! [end_not_recorded] nothing recorded the end of this session, so what came
    after the last event was not observed
  ! [not_interposed] nothing readable recorded which MCP servers this session
    was configured with, so this tool cannot show that it observed all of them
  ! [proxy_start_failed] no proxy recorded anything for this session. Either the
    agent made no tool call, or it was never routed through the proxy, and this
    tool cannot tell which - so it declares the hole rather than publishing an
    empty clean trace.
  INCOMPLETE: the gaps above are what this run could not observe
  wrote the trace and its digest to actaira-trace
```

Read that output again, because it is the design. Nothing was observed, and the
tool said so three different ways rather than writing a clean empty trace. A
witness that reports silence as "nothing happened" is worse than no witness,
because somebody will rely on it.

`actaira-trace/` then holds the trace as JSON, a `.sha256` beside it, and an
`index.json`. `--out` puts them somewhere else. The session id is a fresh uuid
per run, which is why it is written as `<session-id>` above - every other
character of that block is compared against the real output by
`tests/test_readme_parity.py`.

Point it at a real agent with an MCP configuration and the same command records
the tool calls:

```bash
actaira watch --mcp-config .mcp.json -- claude -p "refactor the auth module"
```

`--with-content` keeps literal arguments and results. Without it, arguments
travel as salted digests: a digest has no false negatives and a secret filter
does.

---

## `actaira scan` - the sessions an agent already wrote

`scan` reads transcripts the agent saved to disk by itself, which is capture
level L0 and therefore **cannot claim authenticity**: the audited party wrote
them. The tool says so on every run rather than leaving it to be worked out.

```bash
actaira scan --demo              # a synthetic session that ships in the package
actaira scan --home ~/.claude    # the agent's own configuration directory
actaira scan --out traces/       # one canonical trace per session
```

`--demo` exists for the reader with no agent installed: it reads a session
shipped inside the wheel, so an install can be shown to work with no network,
no account and no checkout.

---

Where a command writes a document, the document's contract is in
[`CONTRACTS.md`](CONTRACTS.md) and what is promised across versions is in
[`COMPATIBILITY.md`](COMPATIBILITY.md). What none of them can show you is in
[`LIMITS.md`](LIMITS.md).
