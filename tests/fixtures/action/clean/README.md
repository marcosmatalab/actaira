# A repository with no agent configuration at all

This is the FIRST side of the Action's own test in CI, and the second is
`tests/fixtures/surface/keyv-august/`. Between them they exercise the two exit
codes that decide what the Action does to a pull request: `0` here against
itself, and `1` when the keyv wave's configuration arrives on top.

It holds one file on purpose. A directory with nothing in it cannot be committed
to git, and the empty side has to be a real directory the Action can be pointed
at with `from-dir`.
