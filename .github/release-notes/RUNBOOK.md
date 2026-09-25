# Publishing 3.0.0

Everything in this file needs a credential, a token or a push. Nothing here is
done by the repository: each line is one
a person runs, in this order, having read it.

The texts to paste are beside this file: [`v2.3.0.md`](v2.3.0.md) and
[`v3.0.0.md`](v3.0.0.md).

## Why this order

The rename comes before the rewrite, and the rewrite before every act of
publication. Neither of those two is a preference.

- **The rename is first** because the replay rebuilds every commit, and a tree
  renamed afterwards is the same work done twice. The rename landed in the
  history as ordinary commits; what the replay does to them is what it does to
  all the others.

- **A release is read the day it is cut.** The sdist carries `README.md`, and
  the README carries a `uses: marcosmatalab/seamark@<sha>` and a `rev: <sha>`
  pointing at commits of this repository. The rewrite moves all but one of
  them. Cutting 3.0.0 first would attach a page telling readers to pin commits
  that no clone of this repository will have.
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
  build after the release exists, which is why step 13 creates a release with
  nothing attached and the workflow attaches what it built.
- **The rehearsal comes before the tag.** It builds and installs the package
  with the same target the release workflow runs, so a tag is not spent finding
  out that the wheel does not install.
- **Nothing goes to a package index.** The tool installs from its tag, and the
  release carries the attested wheel and sdist. `scripts/release_check.py`
  refuses a workflow that uploads anywhere else (design note D-306).

`origin/main` is behind this branch by the whole of this piece of work, so the
force-push in step 8 is also the first publication of it. Count it with
`git rev-list --count origin/main..main` rather than trusting this sentence: a
number written here would be wrong by the next commit.

Run the gate first. Not `make all` on the working tree, which answers for a
tree nobody receives:

```bash
wsl -e bash -lc 'rm -rf /tmp/seamark-gate && git clone -q /mnt/c/Users/<you>/Desktop/seamark /tmp/seamark-gate && cd /tmp/seamark-gate && PY=/tmp/seamark-venv/bin/python make all'
```

## 1. Rename the repository on GitHub

Settings → General → Repository name → `seamark` → **Rename**.

GitHub keeps everything: the issues, the releases, the tags, the watchers, and
a redirect from the old URL for both git and the web. Nothing below leans on
that redirect - every URL in this tree already names the new one - because a
redirect is a courtesy that stops working the day somebody creates a repository
with the old name.

Do it first, and the reason is the one that runs through this whole file:
everything after it is written against the name, and doing it last would mean
doing the two hours in between twice.

## 2. Move the checkout, with the editor closed

The tree, its tooling and every command below name
`C:\Users\<you>\Desktop\seamark`. The folder on this machine is still
called `actaira`.

**Close any editor or tool that has this folder open before you run
this.** A process that is holding the directory writes its next file into a
path that has moved, and what it leaves behind is half of something in a place
nobody is looking.

```powershell
Rename-Item C:\Users\<you>\Desktop\actaira seamark
cd C:\Users\<you>\Desktop\seamark
git remote set-url origin https://github.com/marcosmatalab/seamark.git
git remote -v
git status --porcelain
```

`git remote -v` prints the new URL twice and `git status` prints nothing: the
move is a rename of a directory, and git keeps no absolute path of its own
inside a repository.

Then the virtualenv the gate runs out of, which lives in `/tmp` and therefore
does not survive a restart of WSL. This is the one command in this file that
has to be re-run after a reboot, and the gate says `No such file or directory`
if it has not been:

```bash
wsl -e bash -lc 'rm -rf /tmp/seamark-venv && python3 -m venv /tmp/seamark-venv && /tmp/seamark-venv/bin/pip install --quiet -e "/mnt/c/Users/<you>/Desktop/seamark[dev]"'
```

## 3. The archive branch

`archive/model-scanner` points at `50e6f81a`, which is the same commit as tag
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

## 4. The note on the release that exists

Edit the existing GitHub Release for `v2.3.0` and paste the body of
[`v2.3.0.md`](v2.3.0.md). **Do not re-point the tag and do not mark it a
prerelease.** It was a real release of a real product that was finished and
archived; re-pointing a published tag is the move ACT-S003 tells everybody else
not to make, and calling it a prerelease rewrites the past to look tidier.

## 5. Look at the landing page rendered, on a branch nobody is reading

The demo picture is an SVG drawn from the command's own output.
`scripts/release_check.py` proves it fetches nothing, uses no element a
sanitiser strips and fits its own box at a glyph width wider than any common
monospace face. What no command here can answer is what GitHub's renderer
actually draws, so that is answered with eyes, on a throwaway branch, before
anything is permanent:

```bash
git push origin main:refs/heads/readme-preview
```

Open `https://github.com/marcosmatalab/seamark/blob/readme-preview/README.md`
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

## 6. The history rewrite

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
wsl -e bash -lc 'cd /mnt/c/Users/<you>/Desktop/seamark && PY=/tmp/seamark-venv/bin/python make figures'
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

## 7. The gate, over the rewritten history

```bash
wsl -e bash -lc 'rm -rf /tmp/seamark-gate && git clone -q /mnt/c/Users/<you>/Desktop/seamark /tmp/seamark-gate && cd /tmp/seamark-gate && PY=/tmp/seamark-venv/bin/python make all'
git status --porcelain      # empty but for the plan
```

Green, or `git reset --hard backup-pre-rewrite` and nothing has been published.
This is the last point at which that sentence is true.

## 8. The force-push

```bash
git fetch origin
git push --force-with-lease origin main
```

`--force-with-lease` and not `--force`: if anything was pushed in the meantime
it fails instead of overwriting it. The backup is already on the remote from
step 6, which is what makes this recoverable by somebody who is not you.

`git fetch` first, and it is not a formality. `--force-with-lease` compares the
remote against YOUR `origin/main`, which is a local note of what the remote
looked like the last time you asked. A stale note makes the guarantee
decorative: it would let you overwrite a push you have never seen, which is the
exact thing the flag is there to refuse. Fetching moves the note, so the
comparison is against what is actually there.

## 9. CI, green on the rewritten branch

Watch the run to the end before going further:

```bash
gh run watch "$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Seven jobs: lint, the suite on three interpreters, the package, the consistency
gate, zizmor, the Action used two ways, and the dogfood job that uploads this
repository's own SARIF to code scanning. A red one here is a red one on the
commit everything below is about to be cut from.

## 10. Before the first release only: the signing key

Three settings, once. Everything after this assumes them.

**Where this section runs: PowerShell, on Windows, NOT inside `wsl`.** The tag
in step 12 is signed by the Windows git, which reads the `.ssh` and
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
gh ssh-key add $HOME\.ssh\id_ed25519_signing.pub --type signing --title "seamark release signing"
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

## 11. The rehearsal, from a clean clone

The same `make package` the release workflow runs, over a clean clone, with
the wheel installed into a throwaway environment and the tool run out of it:

```bash
wsl -e bash -lc 'rm -rf /tmp/seamark-gate && git clone -q /mnt/c/Users/<you>/Desktop/seamark /tmp/seamark-gate && cd /tmp/seamark-gate && /tmp/seamark-venv/bin/pip install -q build && PY=/tmp/seamark-venv/bin/python make package INSTALL=--install'
```

It builds both distributions into `dist/`, asserts what is inside them, and
runs the installed CLI. Nothing is sent anywhere, so a failure here is fixed
and run again. What it does NOT exercise is the `attach` job, which needs a
release to write to; that job is repeatable (`gh release upload --clobber`),
so a failure there is a re-run.

## 12. The tag, signed

```bash
git tag -s v3.0.0 -m "Seamark 3.0.0: change control for what your AI agents can do"
git tag -v v3.0.0          # "Good \"git\" signature for matagarciamarcos@gmail.com"
git push origin v3.0.0
```

`-s` and not `-a`. An annotated tag says who claims to have cut it; a signed
one lets somebody else check the claim, and GitHub puts **Verified** beside it
on the tag and on the release.

## 13. The release, and the build that comes from the runner

Create it from the notes in this directory, with **no files attached**:

```bash
gh release create v3.0.0 --title "Seamark 3.0.0" --notes-file .github/release-notes/v3.0.0.md --verify-tag
```

Publishing it starts `.github/workflows/release.yml`, which builds the wheel
and the sdist on the runner with the same `make package` a laptop runs, signs a
provenance attestation for both, and attaches them and `SHA256SUMS` to the
release. Nothing is uploaded to a package index.

**The release is public with no files attached for the few minutes that takes,
and that is the workflow working rather than failing.** Anybody looking at the
releases page in that window sees notes and no downloads.

Watch it to the end:

```bash
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

**Why the runner and not this machine.** The attestation is worth something
because the identity that signs it belongs to a workflow in this repository and
cannot be borrowed by whoever is typing. A laptop build can be checksummed and
not attested, and a repository whose subject is supply chains publishing a
wheel that nobody can trace back to a commit is the thing a hostile reader
looks for first.

## 14. Verify what was published, the way a stranger would

`gh` and `git` are the Windows ones here, like everywhere else in this file
that is not marked `wsl -e`; `sha256sum` is not a Windows command, so that one
line is marked and reads the same directory through `/mnt/c`.

```powershell
gh release download v3.0.0 --dir $HOME\seamark-verify --repo marcosmatalab/seamark
cd $HOME\seamark-verify
gh attestation verify seamark-3.0.0-py3-none-any.whl --repo marcosmatalab/seamark
gh attestation verify seamark-3.0.0.tar.gz --repo marcosmatalab/seamark
git -C C:\Users\<you>\Desktop\seamark tag -v v3.0.0
```

```bash
wsl -e bash -lc 'cd /mnt/c/Users/<you>/seamark-verify && sha256sum -c SHA256SUMS'
wsl -e bash -lc 'rm -rf /tmp/from-tag && python3 -m venv /tmp/from-tag && /tmp/from-tag/bin/pip install -q "git+https://github.com/marcosmatalab/seamark@v3.0.0" && /tmp/from-tag/bin/seamark --version'
```

The last line is the install the README and the notes publish, run the way a
stranger runs it: from the tag, into an empty environment.

The same four checks are in the release notes, in the POSIX spelling a reader
on any other machine would use, so that nobody has to be told they exist.

## 15. About, topics and website

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

Website: `https://github.com/marcosmatalab/seamark/releases/latest`. No page of its own: a report of
this repository fires no rule, so a published demo would be a demo where
nothing happens.

**Everything else on GitHub that carries a name, so that none of it is found
later.** The repository name is step 1. The About text and the website field
are the two above, and neither of them is set by the rename. None of the twelve
topics names the product, so the list is unchanged. The Marketplace listing is
created from the repository in step 16 and takes the new name with it. There
are no Actions secrets to rename, because nothing here uses one.

The one that looks like a mistake and is not: the Security tab. Code scanning
files findings under the category the upload declares, and that category is now
`seamark`. Anything uploaded under the old one stays where it is, as a second
category with no new results, until GitHub ages it out. Nothing to do; it is
worth knowing before it looks like two tools.

## 16. Marketplace

It pins the tag, and the tag is only final once step 12 has survived everything
after it. GitHub releases page, "Publish this Action to the GitHub
Marketplace", accept the terms, pick the category. `action.yml` already carries
the `branding` block it asks for.

## 17. The backup

Last. Everything that could send you back to it has already succeeded.

```bash
git push origin --delete backup-pre-rewrite
git branch -D backup-pre-rewrite
```

`.github/history-rewrite/rewritten-shas.tsv` stays in the tree after this: it
is the only remaining way to resolve a SHA quoted somewhere outside this
repository to the commit that replaced it.
