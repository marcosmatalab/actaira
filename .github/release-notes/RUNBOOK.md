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

`origin/main` is ten commits behind this branch, so the force-push in step 6 is
also the first publication of all of this work.

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

```bash
python3 .github/history-rewrite/replay.py            # builds the objects, moves nothing
python3 .github/history-rewrite/replay.py --apply
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
git push --force-with-lease origin main
```

`--force-with-lease` and not `--force`: if anything was pushed in the meantime
it fails instead of overwriting it. The backup is already on the remote from
step 4, which is what makes this recoverable by somebody who is not you.

## 7. CI, green on the rewritten branch

Watch the run to the end before going further:

```bash
gh run watch "$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Seven jobs: lint, the suite on three interpreters, the package, the consistency
gate, zizmor, the Action used two ways, and the dogfood job that uploads this
repository's own SARIF to code scanning. A red one here is a red one on the
commit everything below is about to be cut from.

## 8. The tag

```bash
git tag -a v3.0.0 -m "Actaira 3.0.0: change control for what your AI agents can do"
git push origin v3.0.0
```

## 9. The distributions, built after the rewrite

Built now and not earlier, because the sdist carries the README and the README
carries the commits the rewrite moved.

```bash
wsl -e bash -lc 'cd /mnt/c/Users/Usuario/Desktop/actaira && PY=/tmp/actaira-venv/bin/python make clean && PY=/tmp/actaira-venv/bin/python make package'
wsl -e bash -lc 'cd /mnt/c/Users/Usuario/Desktop/actaira && /tmp/actaira-venv/bin/python -m twine check dist/*.whl dist/*.tar.gz'
cat dist/SHA256SUMS          # written by the target, and attached below
```

`make package` needs the `package` extra (`pip install -e ".[package]"`) and
twine needs `pip install twine`; neither is in `dev`, because a packaging tool
must not be able to break an install of the package.

## 10. The release

```bash
gh release create v3.0.0 --title "Actaira 3.0.0" \
    --notes-file .github/release-notes/v3.0.0.md \
    dist/actaira-3.0.0-py3-none-any.whl dist/actaira-3.0.0.tar.gz dist/SHA256SUMS
```

## 11. TestPyPI, then PyPI

The name is free: `curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/actaira/json`
answered 404 on 2026-09-22.

TestPyPI first, and install from there into an empty environment before
touching the real index. **A version uploaded to PyPI can never be replaced**,
so the rehearsal is not optional. It rehearses the same files that are already
attached to the release above, which is the right way round: a release asset
can be replaced and a PyPI version cannot.

The token goes where the upload runs. These run in WSL, because that is where
`dist/` was built, so the token belongs in `~/.pypirc` inside WSL or in
`TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-...` in front of the command.

```bash
wsl -e bash -lc 'cd /mnt/c/Users/Usuario/Desktop/actaira && /tmp/actaira-venv/bin/python -m twine upload --repository testpypi dist/*.whl dist/*.tar.gz'
wsl -e bash -lc 'rm -rf /tmp/rehearsal && python3 -m venv /tmp/rehearsal && /tmp/rehearsal/bin/pip install --quiet --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ actaira'
wsl -e bash -lc '/tmp/rehearsal/bin/actaira --version'
wsl -e bash -lc 'cd /tmp && /tmp/rehearsal/bin/actaira scan --demo'
```

The third command prints `actaira 3.0.0` and the fourth reads the demo session
out of the installed package, with no checkout and nothing configured. Then,
and only if both did that:

```bash
wsl -e bash -lc 'cd /mnt/c/Users/Usuario/Desktop/actaira && /tmp/actaira-venv/bin/python -m twine upload dist/*.whl dist/*.tar.gz'
```

## 12. About, topics and website

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

## 13. Marketplace

It pins the tag, and the tag is only final once step 8 has survived everything
after it. GitHub releases page, "Publish this Action to the GitHub
Marketplace", accept the terms, pick the category. `action.yml` already carries
the `branding` block it asks for.

## 14. The backup

Last. Everything that could send you back to it has already succeeded.

```bash
git push origin --delete backup-pre-rewrite
git branch -D backup-pre-rewrite
```

`.github/history-rewrite/rewritten-shas.tsv` stays in the tree after this: it
is the only remaining way to resolve a SHA quoted somewhere outside this
repository to the commit that replaced it.
