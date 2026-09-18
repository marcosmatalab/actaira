# A user scope, for the one setting a repository cannot carry

`task.allowAutomaticTasks` is APPLICATION-scoped: VS Code reads it from the
user's own settings file and from nowhere else. So no public repository can
supply it, and a corpus made of repositories can never resolve whether a
committed `folderOpen` task actually runs.

This directory is that missing scope and nothing else. It holds one key, in
the three per-operating-system layouts the settings documentation publishes
so the same fixture resolves wherever the suite runs. It is NOT a violating
configuration and it is not cited as one: the violating configurations are
the real repositories under `corpus/` that commit a `folderOpen` task, each
with its own `provenance.json`. This only says what the machine does with
them.

Source for the layouts and the scope:
<https://code.visualstudio.com/docs/configure/settings>, and the key's
`ConfigurationScope.APPLICATION` in VS Code's own
`src/vs/workbench/contrib/tasks/browser/task.contribution.ts`. Both are
cited with their digest and date in `surface/resolve.VSCODE_ROWS`.
