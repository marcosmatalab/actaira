# Publishing 3.0.0

Everything in this file needs a credential, a token or a push. Nothing here is
done by the repository, and nothing here is done by an agent: each line is one
a person runs, in this order, having read it.

The texts to paste are beside this file: [`v2.3.0.md`](v2.3.0.md) and
[`v3.0.0.md`](v3.0.0.md).

Run the gate first. Not `make all` on the working tree, which answers for a
tree nobody receives:

```bash
wsl -e bash -lc 'rm -rf /tmp/actaira-gate && git clone -q /mnt/c/Users/Usuario/Desktop/actaira /tmp/actaira-gate && cd /tmp/actaira-gate && PY=/tmp/actaira-venv/bin/python make all'
```

## 1. The archive branch

`archive/model-scanner` points at `b61f6346`, which is the same commit as tag
`v2.3.0` and is an ancestor of `main`. It conserves nothing that is not already
conserved twice, and every locator in the tree names the tag now.

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

## 3. PyPI

The name is free: `curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/actaira/json`
answered 404 on 2026-09-22.

```bash
make clean && make package          # builds into dist/ and asserts what is inside
python -m twine check dist/*.whl dist/*.tar.gz
```

TestPyPI first, and install from there into an empty environment before
touching the real index. **A version uploaded to PyPI can never be replaced**,
so the rehearsal is not optional:

```bash
python -m twine upload --repository testpypi dist/*.whl dist/*.tar.gz
python -m venv /tmp/rehearsal
/tmp/rehearsal/bin/pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ actaira
/tmp/rehearsal/bin/actaira --version     # actaira 3.0.0
cd /tmp && /tmp/rehearsal/bin/actaira scan --demo
```

Then, and only if that worked:

```bash
python -m twine upload dist/*.whl dist/*.tar.gz
```

## 4. The tag and the release

**After the history rewrite, not before.** Rewriting `main` changes every SHA,
so a tag cut first would point at a commit that is no longer on the branch.

```bash
git tag -a v3.0.0 -m "Actaira 3.0.0: change control for what your AI agents can do"
git push origin v3.0.0
gh release create v3.0.0 --title "Actaira 3.0.0" \
    --notes-file .github/release-notes/v3.0.0.md \
    dist/actaira-3.0.0-py3-none-any.whl dist/actaira-3.0.0.tar.gz dist/SHA256SUMS
```

## 5. The history rewrite

Forty-four commit messages are written and waiting in
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
git diff main <the new head printed above> --stat    # has to be empty
python3 .github/history-rewrite/replay.py --apply    # moves main, keeps a backup ref
```

Then check what it was for, and only then push:

```bash
git log --format='%B' | grep -ci 'work rule\|budget\|adversarial pass'   # 0
git log --format='%H' | while read h; do git log -1 --format='%B' $h | wc -l; done | sort -rn | head -1   # <= 15
git push origin backup-pre-rewrite-<sha>        # first, and not optional
git push --force-with-lease origin main
```

`--force-with-lease` and not `--force`: if anything was pushed in the meantime
it fails instead of overwriting it.

Then update the two SHAs the documentation pins, which the rewrite moved:
`README.md` and `README.es.md` each show a `uses:` and a `rev:`. Re-resolve with
`git log --format=%H`, commit, and only then delete the backup:

```bash
git push origin --delete backup-pre-rewrite-<sha>
git branch -D backup-pre-rewrite-<sha>
```

## 6. About, topics and website

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

## 7. Marketplace

Last, because it pins the tag and the tag is only final after step 5. GitHub
releases page, "Publish this Action to the GitHub Marketplace", accept the
terms, pick the category. `action.yml` already carries the `branding` block it
asks for.
