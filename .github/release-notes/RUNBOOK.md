# Publishing 3.0.0

Everything in this file needs a credential, a token or a push. Nothing here is
done by the repository, and nothing here is done by an agent: each line is one
a person runs, in this order, having read it.

The texts to paste are beside this file: [`v2.3.0.md`](v2.3.0.md) and
[`v3.0.0.md`](v3.0.0.md).

## Why this order

The history rewrite comes BEFORE every act of publication, and that is the one
thing about this file that is not a preference.

- **PyPI cannot be corrected.** The sdist carries `README.md`, and the README
  carries a `uses: marcosmatalab/actaira@<sha>` and a `rev: <sha>` pointing at
  commits of this repository. The rewrite moves all but one of them. Uploading
  3.0.0 first would publish, permanently and unreplaceably, a page telling
  readers to pin commits that no clone of this repository will have.
- **A tag cut first has to be deleted and cut again.** `v3.0.0` would point at
  a commit that leaves the branch, and deleting a published tag is exactly what
  ACT-S003 tells everybody else not to do.
- **The archive branch has to go first**, before the rewrite and not after: the
  reason it is safe to delete is that it is an ancestor of `main`, and that
  stops being checkable the moment `main` is rebuilt.
- **The backup branch goes last**, after everything that could send you back to
  it has already succeeded.
- **The distributions are built by the runner and not here**, so the build has
  an identity a reader can check rather than a laptop's word. That moves the
  build after the release exists, which is why step 11 creates a release with
  nothing attached and the workflow attaches what it built.
- **The rehearsal comes before the tag.** It runs the same workflow against
  TestPyPI, so what is rehearsed is the thing that will run, and a tag is not
  spent finding out that the publisher form has a typo in it.

`origin/main` is behind this branch by the whole of this piece of work, so the
force-push in step 6 is also the first publication of it. Count it with
`git rev-list --count origin/main..main` rather than trusting this sentence: a
number written here would be wrong by the next commit.

Run the gate first. Not `make all` on the working tree, which answers for a
tree nobody receives:

```bash
wsl -e bash -lc 'rm -rf /tmp/actaira-gate && git clone -q /mnt/c/Users/Usuario/Desktop/actaira /tmp/actaira-gate && cd /tmp/actaira-gate && PY=/tmp/actaira-venv/bin/python make all'
```

## 1. The archive branch

`archive/model-scanner` points at `b61f6346`, which is the same commit as tag
`v2.3.0` and is an ancestor of `main`. It conserves nothing that is not already
conserved twice, and every locator in the tree names the tag now.

**Before the rewrite**, because the second command below is the argument for
deleting it and it can only be asked while `main` still has that history.

```bash
git ls-remote --heads origin                       # main and archive/model-scanner
git rev-list --count origin/main..origin/archive/model-scanner   # 0, or stop
git push origin --delete archive/model-scanner
git branch -D archive/model-scanner                # the local copy
```

Recoverable, if it ever has to be: `git push origin v2.3.0^{commit}:refs/heads/archive/model-scanner`.

## 2. The note on the release that exists

Edit the existing GitHub Release for `v2.3.0` and paste the body of
[`v2.3.0.md`](v2.3.0.md). **Do not re-point the tag and do not mark it a
prerelease.** It was a real release of a real product that was finished and
archived; re-pointing a published tag is the move ACT-S003 tells everybody else
not to make, and calling it a prerelease rewrites the past to look tidier.

## 3. Look at the landing page rendered, on a branch nobody is reading

The demo picture is an SVG drawn from the command's own output.
`scripts/release_check.py` proves it fetches nothing, uses no element a
sanitiser strips and fits its own box at a glyph width wider than any common
monospace face. What no command here can answer is what GitHub's renderer
actually draws, so that is answered with eyes, on a throwaway branch, before
anything is permanent:

```bash
git push origin main:refs/heads/readme-preview
```

Open `https://github.com/marcosmatalab/actaira/blob/readme-preview/README.md`
and look at the picture under "Quickstart": the whole width of the longest
line, the colours, and the rounded frame. Then the Spanish one, in
`README.es.md`.

```bash
git push origin --delete readme-preview
```

If it is wrong there, stop here and fix it: the SVG stays as the source, and
what goes on the page is a PNG rasterised from it by the same command, gated
the same way. Do not carry on to the rewrite with a broken picture, because
every step after this one makes the page harder to change.

## 4. The history rewrite

Forty-five commit messages are written and waiting in
[`../history-rewrite/messages.json`](../history-rewrite/messages.json). They
take the phase scaffolding out of the history and hold every body under fifteen
lines; what the long bodies argued is in `docs/DESIGN.md`, `docs/defects.json`
and `CHANGELOG.md`, which is where a reader can find it without running
`git log`.

`.github/history-rewrite/replay.py` rebuilds the history with them. It replays
each commit's recorded TREE OBJECT rather than applying patches, so the final
tree is identical by construction, and it carries the author and committer
dates over untouched. Without `--apply` it moves nothing.

Run it with the interpreter that can reach `origin`, which on this machine is
the Windows one: `--apply` pushes the backup branch before it moves anything,
and the credentials for that push are in Windows and not in WSL. `python3` is
not a command there.

```bash
python .github/history-rewrite/replay.py            # builds the objects, moves nothing
python .github/history-rewrite/replay.py --apply
```

`--apply` refuses a dirty tree or the wrong branch before it builds anything,
pushes `backup-pre-rewrite` to `origin` BEFORE it moves `main` and stops if
that push fails, compares the moved branch against the backup, writes the
old-to-new SHA map to `.github/history-rewrite/rewritten-shas.tsv`, rewrites
the two `uses:` and the two `rev:` the READMEs publish, and prints the phase's
completion criterion with its answers. It does not force-push and it does not
delete the backup.

**`v2.3.0` stops being an ancestor of `main`.** The tag is early in the history,
so replaying from the root moves every commit after it. What that changes: the
tag's own commit page on GitHub says it belongs to no branch, and the releases
page counts every commit on `main` as being "since" it. What it does not change:
the tag still resolves, its tree is intact, its release and its assets are
untouched, and every `v2.3.0:path/to/file` locator in this tree still
works, which is why those locators name the tag and
not the branch. The alternative was leaving the five pre-tag commits with
bodies of 50, 39, 25, 21 and 20 lines, which is the thing the rewrite exists to
remove.

Then re-measure and commit, in one commit:

```bash
wsl -e bash -lc 'cd /mnt/c/Users/Usuario/Desktop/actaira && PY=/tmp/actaira-venv/bin/python make figures'
git add README.md README.es.md figures.json docs/FIGURES.md .github/history-rewrite/rewritten-shas.tsv
git commit -m "Point the documented commits at the ones that replaced them"
```

A `make` target over this directory rather than over a clone, because what has
to change is this directory. That is the one thing the mounted-directory run is
for: regenerating. Gating is the clone, above and below.

`make figures` is not optional here and the reason is worth knowing: the stamp
in `figures.json` is carried over when nothing was measured differently, and a
message rewrite changes nothing that is measured. It would go on naming a
commit the branch no longer has, and the release gate refuses that. The carry
is conditional on the recorded commit still being on the branch, so this run
moves it.

## 5. The gate, over the rewritten history

```bash
wsl -e bash -lc 'rm -rf /tmp/actaira-gate && git clone -q /mnt/c/Users/Usuario/Desktop/actaira /tmp/actaira-gate && cd /tmp/actaira-gate && PY=/tmp/actaira-venv/bin/python make all'
git status --porcelain      # empty but for the plan
```

Green, or `git reset --hard backup-pre-rewrite` and nothing has been published.
This is the last point at which that sentence is true.

## 6. The force-push

```bash
git fetch origin
git push --force-with-lease origin main
```

`--force-with-lease` and not `--force`: if anything was pushed in the meantime
it fails instead of overwriting it. The backup is already on the remote from
step 4, which is what makes this recoverable by somebody who is not you.

`git fetch` first, and it is not a formality. `--force-with-lease` compares the
remote against YOUR `origin/main`, which is a local note of what the remote
looked like the last time you asked. A stale note makes the guarantee
decorative: it would let you overwrite a push you have never seen, which is the
exact thing the flag is there to refuse. Fetching moves the note, so the
comparison is against what is actually there.

## 7. CI, green on the rewritten branch

Watch the run to the end before going further:

```bash
gh run watch "$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Seven jobs: lint, the suite on three interpreters, the package, the consistency
gate, zizmor, the Action used two ways, and the dogfood job that uploads this
repository's own SARIF to code scanning. A red one here is a red one on the
commit everything below is about to be cut from.

## 8. Before the first release only: the signing key and the two environments

Three settings, once. Everything after this assumes them.

**Where this section runs: PowerShell, on Windows, NOT inside `wsl`.** The tag
in step 10 is signed by the Windows git, which reads the `.ssh` and
`.gitconfig` of the Windows profile. A key made inside WSL lives in the WSL
home, where that git does not look, and the failure is a missing file rather
than a wrong one. Every command in this file that belongs in WSL is written
with `wsl -e`; this one is the other kind, and says so rather than leaving it
to be worked out.

### The signing key

Look before creating anything. `ssh-keygen` offers to overwrite the file it is
given and takes yes for an answer, and on this machine that file is the key you
log in with:

```powershell
Get-ChildItem $HOME\.ssh
```

Then a SEPARATE key, for signing only. They are different jobs: one proves who
is pushing, the other proves who cut a tag, and putting both on one file means
a careless prompt costs the access as well as the signature.

```powershell
ssh-keygen -t ed25519 -C "matagarciamarcos@gmail.com" -f $HOME\.ssh\id_ed25519_signing
git config --global gpg.format ssh
git config --global user.signingkey $HOME\.ssh\id_ed25519_signing.pub
```

`ssh-keygen` asks for a passphrase. Empty means `git tag -s` signs without
asking; a passphrase means it asks every time, in whatever terminal it is
running in, and there is no agent set up here to remember it.

### Registering it on GitHub as a signing key

`gh` does not hold `admin:ssh_signing_key` unless it was asked for at login.
Without the refresh, the next line fails with a permissions error that does not
name the permission:

```powershell
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add $HOME\.ssh\id_ed25519_signing.pub --type signing --title "actaira release signing"
```

`--type signing` is not decoration: authentication keys and signing keys are
two separate lists on the account, and a key in only the first lets you push
while GitHub writes **Verified** on nothing.

### Believing your own signature on this machine

`git tag -v` answers out of a file of identities git is willing to believe.
Without it, verification says "no principal matched" about a tag it signed
itself a minute earlier:

```powershell
git config --global gpg.ssh.allowedSignersFile $HOME\.ssh\allowed_signers
Add-Content -Encoding ascii -Path $HOME\.ssh\allowed_signers -Value "matagarciamarcos@gmail.com $(Get-Content $HOME\.ssh\id_ed25519_signing.pub)"
```

`-Encoding ascii` deliberately. Windows PowerShell writes UTF-16 with a byte
order mark by default, ssh reads that file as bytes, and the first line then
matches nobody.

**The two environments the publish jobs run in.** Repository settings →
Environments → New environment, twice, named exactly `pypi` and `testpypi`. No
protection rules are required; what they are for is that PyPI's publisher form
names one of them, so a workflow run that is not the release workflow cannot
mint a token for it.

**The two trusted publishers.** On PyPI and on TestPyPI, under the account's
Publishing page, add a *pending publisher* (the project does not exist yet and
that is what pending means), with exactly:

| field | value |
|---|---|
| PyPI project name | `actaira` |
| Owner | `marcosmatalab` |
| Repository name | `actaira` |
| Workflow name | `release.yml` |
| Environment name | `pypi` on PyPI, `testpypi` on TestPyPI |

The workflow's FILENAME is part of the trust, so renaming
`.github/workflows/release.yml` later breaks publishing until the form is
changed. That is written here because the failure arrives at upload time and
reads like a permissions problem.

## 9. The rehearsal, to TestPyPI, from the workflow that will do it for real

Not `twine` from a laptop: the point of a rehearsal is to exercise the thing
that will run, and what will run is the workflow.

```bash
gh workflow run release.yml
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

It builds on the runner, attests the two distributions, and publishes them to
TestPyPI through Trusted Publishing. Then install from there into an empty
environment, with nothing from this checkout:

```bash
wsl -e bash -lc 'rm -rf /tmp/rehearsal && python3 -m venv /tmp/rehearsal && /tmp/rehearsal/bin/pip install --quiet --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ actaira'
wsl -e bash -lc '/tmp/rehearsal/bin/actaira --version'
wsl -e bash -lc 'cd /tmp && /tmp/rehearsal/bin/actaira scan --demo'
```

`actaira 3.0.0`, and then the demo session read out of the installed package
with no agent on the machine. **A version uploaded to PyPI can never be
replaced**, so this is not optional.

`gh workflow run` only offers a workflow that is already on the default
branch, which is why this comes after the force-push and not before it.

**If the rehearsal fails, where it failed decides what to do.** The TestPyPI
job carries `skip-existing`, which the PyPI job deliberately does not: a
rehearsal is meant to be repeatable and a publication is meant to happen once.

- **Before the upload** - the build, the attestation, `twine check`: nothing
  was sent. Fix it and run it again.
- **After the upload, in the install** - a wrong index URL, no network, a typo
  in the command: TestPyPI now holds 3.0.0 and will never take those bytes
  again, which is what `skip-existing` is for. Run it again; the upload step
  passes over what is already there and you get back to the install.
- **After the upload, because the distribution itself is wrong**: the bytes on
  TestPyPI cannot be replaced and neither can the version number, so that
  rehearsal is spent. Do NOT bump the version to buy another one - the version
  is the thing half the checks in this tree compare against. Verify the fixed
  build by installing the workflow's own artifact instead, which is the same
  bytes the runner built and attested:

  ```powershell
  gh run download "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --name dist --dir $HOMEctaira-rehearsal
  ```

  ```bash
  wsl -e bash -lc 'rm -rf /tmp/rehearsal && python3 -m venv /tmp/rehearsal && /tmp/rehearsal/bin/pip install --quiet /mnt/c/Users/Usuario/actaira-rehearsal/actaira-3.0.0-py3-none-any.whl'
  wsl -e bash -lc 'cd /tmp && /tmp/rehearsal/bin/actaira scan --demo'
  ```

  Into the home directory and not into the checkout: an untracked folder in
  the working tree is the one thing step 5 asks you to confirm is not there.

  That skips the index round trip and nothing else. PyPI's upload is then the
  first time those bytes are published anywhere, which is exactly what it is,
  and the attestation is what lets somebody else check that claim.

What the rehearsal does NOT exercise is the `attach` job: uploading the
assets to a release needs a release, and there is not one yet. That is the one
step of step 11 that runs for the first time when it runs for real, and it is
also the only one that is repeatable - `gh release upload --clobber` replaces
what is there, so a failure is a re-run rather than a burnt version.

## 10. The tag, signed

```bash
git tag -s v3.0.0 -m "Actaira 3.0.0: change control for what your AI agents can do"
git tag -v v3.0.0          # "Good \"git\" signature for matagarciamarcos@gmail.com"
git push origin v3.0.0
```

`-s` and not `-a`. An annotated tag says who claims to have cut it; a signed
one lets somebody else check the claim, and GitHub puts **Verified** beside it
on the tag and on the release.

## 11. The release, and the build that comes from the runner

Create it from the notes in this directory, with **no files attached**:

```bash
gh release create v3.0.0 --title "Actaira 3.0.0" \
    --notes-file .github/release-notes/v3.0.0.md \
    --verify-tag
```

Publishing it starts `.github/workflows/release.yml`, which builds the wheel
and the sdist on the runner with the same `make package` a laptop runs, signs a
provenance attestation for both, attaches them and `SHA256SUMS` to the release,
and then publishes to PyPI.

**The release is public with no files attached for the few minutes that takes,
and that is the workflow working rather than failing.** Anybody looking at the
releases page in that window sees notes and no downloads. Watch it to the end:

```bash
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

**Why the runner and not this machine.** The attestation is worth something
because the identity that signs it belongs to a workflow in this repository and
cannot be borrowed by whoever is typing. A laptop build can be checksummed and
not attested, and a repository whose subject is supply chains publishing a
wheel that nobody can trace back to a commit is the thing a hostile reader
looks for first.

**Why Trusted Publishing and not a token.** Decided rather than defaulted:

- it removes the long-lived credential. A `~/.pypirc` on a laptop is exactly
  the standing secret this repository tells other people to look for;
- it is what makes the PyPI side verifiable at all. `gh-action-pypi-publish`
  mints PEP 740 attestations when it publishes through Trusted Publishing and
  cannot when it publishes with a token, so with a token the release would
  carry provenance and the index would carry none;
- the failure mode is cheap. A misconfigured publisher is rejected by PyPI
  before anything is uploaded: nothing is published, the version is not
  consumed, you fix the form and re-run. The irreversible step - a version name
  being taken - happens only on a successful upload, which is equally true of
  twine.

What it costs is two forms filled in before the first upload, which is step 8.
A token upload (`twine upload`) still works and is what to fall back to if PyPI's
publisher form cannot be used on the day; if that happens, the line in the
release notes about verifying the PyPI artifact has to come out, because it
would no longer be true.

## 12. Verify what was published, the way a stranger would

`gh` and `git` are the Windows ones here, like everywhere else in this file
that is not marked `wsl -e`; `sha256sum` is not a Windows command, so that one
line is marked and reads the same directory through `/mnt/c`.

```powershell
gh release download v3.0.0 --dir $HOME\actaira-verify --repo marcosmatalab/actaira
cd $HOME\actaira-verify
gh attestation verify actaira-3.0.0-py3-none-any.whl --repo marcosmatalab/actaira
gh attestation verify actaira-3.0.0.tar.gz --repo marcosmatalab/actaira
git -C C:\Users\Usuario\Desktop\actaira tag -v v3.0.0
```

```bash
wsl -e bash -lc 'cd /mnt/c/Users/Usuario/actaira-verify && sha256sum -c SHA256SUMS'
```

The same four checks are in the release notes, in the POSIX spelling a reader
on any other machine would use, so that nobody has to be told they exist.

## 13. About, topics and website

Repository settings, About:

> Change control for what your AI coding agents can do. Reads the config Claude
> Code, Codex, Cursor, Gemini CLI and VS Code load, resolves what it actually
> permits across scopes and vendors, and says what changed between two commits.
> Offline, no telemetry, nothing scored. GitHub Action and pre-commit hook
> included.

Topics, twelve, which is where GitHub stops showing them well:
`ai-agents`, `agent-security`, `mcp`, `claude-code`, `supply-chain-security`,
`static-analysis`, `sarif`, `devsecops`, `github-action`, `pre-commit-hook`,
`attestation`, `python`.

Website: `https://pypi.org/project/actaira/`. No page of its own: a report of
this repository fires no rule, so a published demo would be a demo where
nothing happens.

## 14. Marketplace

It pins the tag, and the tag is only final once step 10 has survived everything
after it. GitHub releases page, "Publish this Action to the GitHub
Marketplace", accept the terms, pick the category. `action.yml` already carries
the `branding` block it asks for.

## 15. The backup

Last. Everything that could send you back to it has already succeeded.

```bash
git push origin --delete backup-pre-rewrite
git branch -D backup-pre-rewrite
```

`.github/history-rewrite/rewritten-shas.tsv` stays in the tree after this: it
is the only remaining way to resolve a SHA quoted somewhere outside this
repository to the commit that replaced it.
