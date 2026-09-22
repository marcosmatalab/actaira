"""The merge semantics, as a table of cited rows.

Design note D-273. Every merge decision is a ROW here, never an `if` somewhere
in a resolver. A row carries the key or family it governs, the rule, the URL it
came from, a digest of that page as retrieved, the date it was read, and the
sentence that says it. `tests/test_surface.py` fails on a row missing any of
those, and that test is itself exercised against a row with the citation
removed so it cannot be passing by never looking.

Rejected: citing "the Claude Code documentation" once at the top of the file.
The pages change independently, a rule that moved is indistinguishable from a
rule we misread, and the whole product claim is that a capability names the
documented rule that resolved it. One citation for thirteen rules is one
citation short of twelve.

Why a DIGEST and not a version number. These pages publish no version string
and no last-updated date, checked across all eight on the consultation date
below. So the honest anchor is the page as retrieved: sha256 over the markdown
the vendor served, plus the date. That is limit 14 applied to our own sources
rather than only to the user's, because an approval over a page NAME is an
approval over whatever is at that name tomorrow. Where a page states an agent
version that governs a rule, `since` carries it as well, because that number is
the one the answer actually depends on.

This file is the bottom of the package: it imports nothing from its siblings
and everything that resolves imports it. It was the first seven hundred lines
of `resolve.py`, which is how that file came to be two thousand and three of
them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# The one sibling this file reads, and it reads one string from it. `row_for`
# falls back to Claude Code's ladder when a vendor has no table of its own, and
# the name of that vendor is written once, in the module that reads for it. A
# literal here would be the second copy of a fact, which is the shape work rule
# 10 refuses; `claude_code` imports neither this module nor `emit`, so nothing
# is circular.
from .claude_code import VENDOR

# The date every row below was read. One constant, because they were read in one
# sitting and a per-row date that is always the same value is a field nobody
# maintains.
CONSULTED = "2026-09-17"

# The version from which `bypassPermissions` stopped taking effect from a
# repository file. It is the canonical declared-versus-effective case and the
# only threshold this release needs: before it, a committed `.claude/settings.json`
# could start a session with every prompt skipped.
BYPASS_NEEDS_USER_SCOPE_FROM = (2, 1, 257)


class Kind(StrEnum):
    """How one key combines across scopes."""

    PRECEDENCE = "highest scope that sets it wins"
    LIST_UNION = "the lists from every scope are combined"
    MANAGED_ONLY = "only a managed source may set it"
    STRICTEST_WINS = "the most restrictive value from any scope wins"
    NOT_FROM_REPOSITORY = "a repository file cannot set it"
    TRUST_GATED = "a repository file sets it, and it waits for workspace trust"
    NOT_TRUST_GATED = "a repository file sets it and it applies before any trust step"
    HOST_SIDE = "a repository file sets it and it runs on the host, outside the container"
    APPROVAL_GATED = "a repository file sets it, and it waits for a one-time approval dialog"
    NO_DOCUMENTED_ORDER = "the vendor documents both scopes and no precedence between them"


@dataclass(frozen=True)
class MergeRow:
    """One documented merge rule, with the citation that makes it checkable."""

    keys: tuple[str, ...]
    kind: Kind
    url: str
    doc_sha256: str
    consulted: str
    quote: str
    since: str | None = None

    @property
    def cited(self) -> bool:
        """Whether this row may be used at all.

        Four fields and all four non-empty. A row that cannot say where it came
        from is an opinion about somebody else's software, which is the one
        thing CLAUDE.md's second negative forbids outright.
        """
        return bool(
            self.url.strip()
            and len(self.doc_sha256.strip()) == 64
            and self.consulted.strip()
            and self.quote.strip()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "keys": list(self.keys),
            "rule": self.kind.value,
            "url": self.url,
            "doc_sha256": self.doc_sha256,
            "consulted": self.consulted,
            "quote": self.quote,
            "since": self.since,
        }


SETTINGS = "https://code.claude.com/docs/en/settings"
SETTINGS_REF = "https://code.claude.com/docs/en/settings-reference"
PERMISSIONS = "https://code.claude.com/docs/en/permissions"
PERMISSION_MODES = "https://code.claude.com/docs/en/permission-modes"
HOOKS = "https://code.claude.com/docs/en/hooks"
SANDBOXING = "https://code.claude.com/docs/en/sandboxing"
MANAGED = "https://code.claude.com/docs/en/managed-settings"
MCP = "https://code.claude.com/docs/en/mcp"

D_SETTINGS = "bc2cccf058099f4fd91436d73df0ef6a80533860a87e906048c9f1c44e9de7f6"
D_SETTINGS_REF = "8fdd564085ed6e40e0f4e1ba962c9cdc483b85c33fd2ef59806cfed4f081fc66"
D_PERMISSIONS = "eab3c45e44187c7be90a7566d21233835354237c9b41ac36906ea45114cc21cb"
D_PERMISSION_MODES = "77bbe7bccf66d50594d1c2209b209ee652d01c99580705917a88f24976d7eab2"
D_HOOKS = "e19530ebc7709e76ace04022835e8dc55c46247152f1e4b3449e84c6ebdcb5a4"
D_SANDBOXING = "f4aea577087c100af55310a11beb32fc079684124c00d34d487bd7c9be9419b6"
D_MANAGED = "da3cf2184feaba41349980bac68ce19f7df6fe7e01d11d9569c6f5bb05a8591d"
D_MCP = "67dccd0f48a35655d560f921f3974ed2a8c50fb999a9859439d3748dd8a48221"


CLAUDE_CODE_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*",),
        kind=Kind.PRECEDENCE,
        url=SETTINGS,
        doc_sha256=D_SETTINGS,
        consulted=CONSULTED,
        quote=(
            "When the same key appears in more than one place, Claude Code uses the value "
            "from the highest level that sets it."
        ),
    ),
    MergeRow(
        keys=("permissions.allow", "permissions.ask", "permissions.deny"),
        kind=Kind.LIST_UNION,
        url=SETTINGS,
        doc_sha256=D_SETTINGS,
        consulted=CONSULTED,
        quote=(
            "When you set the same list key, such as `permissions.allow`, in more than one "
            "file, Claude Code combines the lists instead of picking one, so each file can "
            "add entries without removing another file's."
        ),
    ),
    MergeRow(
        keys=("hooks",),
        kind=Kind.LIST_UNION,
        url=HOOKS,
        doc_sha256=D_HOOKS,
        consulted=CONSULTED,
        quote=(
            "Hook entries merge across settings levels rather than replacing each other: "
            "user, project, and local settings add their own hooks without removing managed "
            "ones."
        ),
    ),
    MergeRow(
        keys=("hooks", "env", "apiKeyHelper", "statusLine", "awsAuthRefresh",
              "awsCredentialExport", "otelHeadersHelper", "fileSuggestion"),
        kind=Kind.NOT_TRUST_GATED,
        url=PERMISSIONS,
        doc_sha256=D_PERMISSIONS,
        consulted=CONSULTED,
        quote=(
            "Hooks in settings files, the `env` block and helper commands such as "
            "`apiKeyHelper` [...] Used. Workspace trust never gates a skill's "
            "`allowed-tools` in any session."
        ),
    ),
    MergeRow(
        keys=("permissions.defaultMode",),
        kind=Kind.NOT_FROM_REPOSITORY,
        url=SETTINGS_REF,
        doc_sha256=D_SETTINGS_REF,
        consulted=CONSULTED,
        quote=(
            "`auto` and `bypassPermissions` don't take effect from project or local "
            "settings, so set them in `~/.claude/settings.json` instead. Before v2.1.257, "
            "`bypassPermissions` took effect from any file."
        ),
        since="2.1.257",
    ),
    MergeRow(
        keys=("permissions.allow", "permissions.additionalDirectories"),
        kind=Kind.TRUST_GATED,
        url=PERMISSIONS,
        doc_sha256=D_PERMISSIONS,
        consulted=CONSULTED,
        quote=(
            "`permissions.allow` rules and `permissions.additionalDirectories` entries in a "
            "project's `.claude/settings.json` grant capability, so Claude Code applies them "
            "only after you accept the workspace trust dialog for that folder."
        ),
    ),
    MergeRow(
        keys=("enableAllProjectMcpServers", "enabledMcpjsonServers"),
        kind=Kind.TRUST_GATED,
        url=MCP,
        doc_sha256=D_MCP,
        consulted=CONSULTED,
        quote=(
            "A cloned repository can't approve its own servers: `enableAllProjectMcpServers` "
            "or `enabledMcpjsonServers` committed to the project's `.claude/settings.json` is "
            "ignored in an untrusted folder."
        ),
        since="2.1.196",
    ),
    MergeRow(
        keys=("extraKnownMarketplaces",),
        kind=Kind.TRUST_GATED,
        url=PERMISSIONS,
        doc_sha256=D_PERMISSIONS,
        consulted=CONSULTED,
        quote=(
            "Frontmatter hooks in a project subagent, a project `@skills-dir` plugin, and "
            "`extraKnownMarketplaces` entries from the repository [...] Not used, and no "
            "dialog is offered."
        ),
    ),
    MergeRow(
        keys=("allowManagedMcpServersOnly", "allowManagedHooksOnly",
              "allowManagedPermissionRulesOnly"),
        kind=Kind.MANAGED_ONLY,
        url=SETTINGS_REF,
        doc_sha256=D_SETTINGS_REF,
        consulted=CONSULTED,
        quote=(
            "Scope: Managed. (The settings index marks these keys Managed rather than "
            "`Any file`, so a repository file that sets one has not set it.)"
        ),
    ),
    MergeRow(
        keys=("disableClaudeAiConnectors", "isolatePeerMachines", "enableArtifact",
              "crossSessionInbound", "maxEffortLevel"),
        kind=Kind.STRICTEST_WINS,
        url=SETTINGS,
        doc_sha256=D_SETTINGS,
        consulted=CONSULTED,
        quote=(
            "For a few keys whose values restrict a session, Claude Code honors a "
            "restrictive value from a scope that otherwise couldn't override managed "
            "settings."
        ),
    ),
    MergeRow(
        keys=("sandbox.excludedCommands", "sandbox.filesystem.allowRead",
              "sandbox.filesystem.allowWrite"),
        kind=Kind.LIST_UNION,
        url=SANDBOXING,
        doc_sha256=D_SANDBOXING,
        consulted=CONSULTED,
        quote=(
            "For array keys such as `excludedCommands` and `allowRead`, Claude Code merges "
            "entries from every scope the session loads, so a developer can append entries "
            "that widen the policy. [...] `excludedCommands` has no equivalent managed-only "
            "lockdown."
        ),
    ),
    MergeRow(
        keys=("sandbox.network.allowedDomains",),
        kind=Kind.LIST_UNION,
        url=SANDBOXING,
        doc_sha256=D_SANDBOXING,
        consulted=CONSULTED,
        quote=(
            "Set `allowManagedReadPathsOnly` to `true` in managed settings so that only "
            "`allowRead` entries from managed settings are honored. [...] To lock network "
            "domains to the managed values the same way, set `allowManagedDomainsOnly`."
        ),
    ),
    MergeRow(
        keys=("sandbox.enabled", "sandbox.failIfUnavailable",
              "sandbox.allowUnsandboxedCommands"),
        kind=Kind.PRECEDENCE,
        url=SANDBOXING,
        doc_sha256=D_SANDBOXING,
        consulted=CONSULTED,
        quote=(
            "For boolean keys such as `enabled` and `failIfUnavailable`, Claude Code uses "
            "the managed value and ignores anything a developer sets locally."
        ),
    ),
    MergeRow(
        keys=("managed-settings.json",),
        kind=Kind.MANAGED_ONLY,
        url=MANAGED,
        doc_sha256=D_MANAGED,
        consulted=CONSULTED,
        quote=(
            "File-based: `managed-settings.json`, an optional `managed-settings.d/` "
            "directory, and `managed-mcp.json` in the system directory: "
            "`/Library/Application Support/ClaudeCode/` on macOS, `/etc/claude-code/` on "
            "Linux and WSL, and `C:\\Program Files\\ClaudeCode\\` on Windows."
        ),
    ),
)


# ---------------------------------------------------------------------------
# The other vendors, each with its own ladder and its own citations
# ---------------------------------------------------------------------------
#
# Design note D-288. Phase S2's central claim is that a repository's surface is
# the UNION of per-vendor surfaces, never a merge of them. Each vendor below
# carries its own precedence row, because the ladders genuinely disagree:
# Claude Code puts user above project, Gemini CLI puts project above user, VS
# Code puts workspace above user, and Cursor puts an enterprise file above a
# dashboard above both. A single table would have to pick one, and picking one
# is inventing a rule three vendors do not document.
#
# Every row below was read on CONSULTED_S2 and its `doc_sha256` is the sha256 of
# the bytes that URL served on that date, which anybody can recompute with
# `curl -sL <url> | sha256sum`. That is published limit 14 turned on our own
# sources: an approval over a page NAME is an approval over whatever is at that
# name tomorrow.

CONSULTED_S2 = "2026-09-18"

VSCODE_TASKS = "https://code.visualstudio.com/docs/debugtest/tasks"
VSCODE_SETTINGS = "https://code.visualstudio.com/docs/configure/settings"
VSCODE_TRUST = "https://code.visualstudio.com/docs/editing/workspaces/workspace-trust"
VSCODE_SOURCE = (
    "https://raw.githubusercontent.com/microsoft/vscode/main/src/vs/workbench/contrib/"
    "tasks/browser/task.contribution.ts"
)
DEVCONTAINER_REF = "https://containers.dev/implementors/json_reference/"
DEVCONTAINER_SPEC = "https://containers.dev/implementors/spec/"
CODEX_REF = "https://learn.chatgpt.com/docs/config-file/config-reference"
CODEX_ADVANCED = "https://learn.chatgpt.com/docs/config-file/config-advanced"
CODEX_MANAGED = "https://learn.chatgpt.com/docs/enterprise/managed-configuration"
CURSOR_HOOKS = "https://cursor.com/docs/agent/hooks"
CURSOR_MCP = "https://cursor.com/docs/context/mcp"
CURSOR_RULES = "https://cursor.com/docs/context/rules"
GEMINI_CONFIG = "https://geminicli.com/docs/reference/configuration/"
GEMINI_ENTERPRISE = "https://geminicli.com/docs/cli/enterprise/"
GEMINI_MEMPORT = "https://geminicli.com/docs/reference/memport/"
CLAUDE_MEMORY = "https://code.claude.com/docs/en/memory"

D_VSCODE_TASKS = "1020b0628b70503ef6cf5860cd49c97fbb7c78e6e0fe360fe3df385cd8665102"
D_VSCODE_SETTINGS = "353c5af42d6ee80792cc96a30f2ce6d36ae80743f0081e71504021d4a7209a19"
D_VSCODE_TRUST = "bcd9e47304715feaaf56d96205f2625bd4749c08d582c9f5d5853c5f6694d12f"
D_VSCODE_SOURCE = "7b4f89f3a3b7d70ac49248df62e344d94df0b0116fd7aed08834c7c62570b060"
D_DEVCONTAINER_REF = "94eb9c3e26e5b99eb8142d187e2e48a4f104e17118cbfe51f447edaadc7a251a"
D_DEVCONTAINER_SPEC = "74351741fb3e7f601d457c1dc1cc6c791ee465f93348165b26a0fc3c0e0c9046"
D_CODEX_REF = "bfd241aa018f5a354a8b0956017d5b0874681e95f61774676de5f00970b547b2"
D_CODEX_ADVANCED = "87862a4bd2bcb9369725819f6c0268d4585182704121222ec473f712862f89cb"
D_CODEX_MANAGED = "af41107dd76caa243d4fb7db5b9f204a5f53dd29e3b94f939521b2c2400d9a03"
D_CURSOR_HOOKS = "af842fc1a466027cad13c41aed62625aae2c24a525de3e751674463541e1289c"
D_CURSOR_MCP = "9e95980c0e55bcf6da608d1217db8bdaf1d39fbf24482cf118acd77617472748"
D_CURSOR_RULES = "b1d9b9d19418ded59f6d8eb3f9f685ff300f187d880af6e4624fcbd1576d560f"
D_GEMINI_CONFIG = "e520589f601e2e4923a1eee5e0e1381ff15fd120cf644e2bf47530461284c423"
D_GEMINI_ENTERPRISE = "e3adac9b08d593efc59e87f649da239bb90377b0e6039b20c4eb8476655b815a"
D_GEMINI_MEMPORT = "63844d36a8a8c9af4813896b105f95022aaf09a6ef909b57825afe8dcb017f60"
D_CLAUDE_MEMORY = "258410ca479aa9cf914848ff143ab9ef6056a1e7d8f22f587aa6f15d7134d144"


VSCODE_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*",),
        kind=Kind.PRECEDENCE,
        url=VSCODE_SETTINGS,
        doc_sha256=D_VSCODE_SETTINGS,
        consulted=CONSULTED_S2,
        quote=(
            "In the following list, later scopes override earlier scopes: Default settings "
            "[...] User settings [...] Remote settings [...] Workspace settings [...] "
            "Workspace Folder settings."
        ),
    ),
    MergeRow(
        keys=("tasks",),
        kind=Kind.NOT_TRUST_GATED,
        url=VSCODE_TASKS,
        doc_sha256=D_VSCODE_TASKS,
        consulted=CONSULTED_S2,
        quote=(
            "Workspace or folder specific tasks are configured from the `tasks.json` file "
            "in the `.vscode` folder for a workspace. [...] `folderOpen`: The task will be "
            "run when the containing folder is opened."
        ),
    ),
    MergeRow(
        keys=("task.allowAutomaticTasks",),
        kind=Kind.NOT_FROM_REPOSITORY,
        url=VSCODE_SOURCE,
        doc_sha256=D_VSCODE_SOURCE,
        consulted=CONSULTED_S2,
        quote=(
            "description: nls.localize('task.allowAutomaticTasks', \"Enable automatic "
            "tasks - note that tasks won't run in an untrusted workspace.\"), "
            "default: 'off', scope: ConfigurationScope.APPLICATION, restricted: true"
        ),
    ),
    MergeRow(
        keys=("settings.application-scope",),
        kind=Kind.NOT_FROM_REPOSITORY,
        url=VSCODE_SETTINGS,
        doc_sha256=D_VSCODE_SETTINGS,
        consulted=CONSULTED_S2,
        quote=(
            "Not all user settings are available as workspace settings. For example, "
            "application-wide settings related to updates and security can not be "
            "overridden by Workspace settings."
        ),
    ),
    MergeRow(
        keys=("runOptions.runOn",),
        kind=Kind.TRUST_GATED,
        url=VSCODE_TRUST,
        doc_sha256=D_VSCODE_TRUST,
        consulted=CONSULTED_S2,
        quote=(
            "Restricted Mode tries to prevent automatic code execution by disabling or "
            "limiting the operation of several VS Code features: AI agents, terminal, "
            "tasks, debugging, workspace settings, and extensions."
        ),
    ),
)


DEVCONTAINER_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*",),
        kind=Kind.PRECEDENCE,
        url=DEVCONTAINER_SPEC,
        doc_sha256=D_DEVCONTAINER_SPEC,
        consulted=CONSULTED_S2,
        quote=(
            "`.devcontainer/devcontainer.json`, `.devcontainer.json`, "
            "`.devcontainer/<folder>/devcontainer.json` [...] It is valid that these files "
            "may exist in more than one location, so consider providing a mechanism for "
            "users to select one when appropriate."
        ),
    ),
    MergeRow(
        keys=("initializeCommand",),
        kind=Kind.HOST_SIDE,
        url=DEVCONTAINER_REF,
        doc_sha256=D_DEVCONTAINER_REF,
        consulted=CONSULTED_S2,
        quote=(
            "A command string or list of command arguments to run on the host machine "
            "during initialization, including during container creation and on subsequent "
            "starts."
        ),
    ),
    MergeRow(
        keys=("onCreateCommand", "updateContentCommand", "postCreateCommand",
              "postStartCommand", "postAttachCommand"),
        kind=Kind.NOT_TRUST_GATED,
        url=DEVCONTAINER_REF,
        doc_sha256=D_DEVCONTAINER_REF,
        consulted=CONSULTED_S2,
        quote=(
            "This command [...] executes inside the container immediately after it has "
            "started for the first time."
        ),
    ),
    MergeRow(
        keys=("mounts",),
        kind=Kind.NOT_TRUST_GATED,
        url=DEVCONTAINER_REF,
        doc_sha256=D_DEVCONTAINER_REF,
        consulted=CONSULTED_S2,
        quote=(
            "Cross-orchestrator way to add additional mounts to a container. Each value is "
            "a string that accepts the same values as the Docker CLI `--mount` flag."
        ),
    ),
    MergeRow(
        keys=("privileged", "capAdd", "securityOpt", "runArgs"),
        kind=Kind.NOT_TRUST_GATED,
        url=DEVCONTAINER_REF,
        doc_sha256=D_DEVCONTAINER_REF,
        consulted=CONSULTED_S2,
        quote=(
            "Cross-orchestrator way to cause the container to run in privileged mode "
            "(`--privileged`). [...] Cross-orchestrator way to add capabilities typically "
            "disabled for a container. [...] Cross-orchestrator way to set container "
            "security options."
        ),
    ),
)


CODEX_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*",),
        kind=Kind.PRECEDENCE,
        url=CODEX_ADVANCED,
        doc_sha256=D_CODEX_ADVANCED,
        consulted=CONSULTED_S2,
        quote=(
            "Base user config (`~/.codex/config.toml`), profile overlay "
            "(`~/.codex/profile-name.config.toml`), project-scoped config "
            "(`.codex/config.toml` from root to working directory), CLI overrides "
            "(`--config`, `--profile`, dedicated flags)."
        ),
    ),
    MergeRow(
        keys=("hooks",),
        kind=Kind.TRUST_GATED,
        url=CODEX_ADVANCED,
        doc_sha256=D_CODEX_ADVANCED,
        consulted=CONSULTED_S2,
        quote="Project-local hooks load only when the project `.codex/` layer is trusted.",
    ),
    MergeRow(
        keys=("projects.trust_level",),
        kind=Kind.NOT_FROM_REPOSITORY,
        url=CODEX_REF,
        doc_sha256=D_CODEX_REF,
        consulted=CONSULTED_S2,
        quote=(
            "Mark a project or worktree as trusted or untrusted (\"trusted\" | "
            "\"untrusted\"). Untrusted projects skip project-scoped `.codex/` layers."
        ),
    ),
    MergeRow(
        keys=("notify", "model_providers", "profile", "otel"),
        kind=Kind.NOT_FROM_REPOSITORY,
        url=CODEX_REF,
        doc_sha256=D_CODEX_REF,
        consulted=CONSULTED_S2,
        quote=(
            "Project-scoped config can't override machine-local provider, auth, host-owned "
            "app request metadata, notification, configuration profile selection, or "
            "telemetry routing keys."
        ),
    ),
    MergeRow(
        keys=("allow_managed_hooks_only",),
        kind=Kind.MANAGED_ONLY,
        url=CODEX_MANAGED,
        doc_sha256=D_CODEX_MANAGED,
        consulted=CONSULTED_S2,
        quote=(
            "`allow_managed_hooks_only` [...] skips hooks from user, project, session, and "
            "plugin sources, but still loads hooks from `requirements.toml`. Requirements "
            "(`requirements.toml`): Unix: `/etc/codex/requirements.toml`; Windows: "
            "`%ProgramData%\\OpenAI\\Codex\\requirements.toml`."
        ),
    ),
    MergeRow(
        keys=("sandbox_mode", "approval_policy"),
        kind=Kind.PRECEDENCE,
        url=CODEX_REF,
        doc_sha256=D_CODEX_REF,
        consulted=CONSULTED_S2,
        quote=(
            "`sandbox_mode`: `read-only`, `workspace-write`, `danger-full-access`. "
            "`approval_policy`: `on-request`, `never` [...] use `on-request` for "
            "interactive runs or `never` for non-interactive runs."
        ),
    ),
    MergeRow(
        keys=("mcp_servers",),
        kind=Kind.PRECEDENCE,
        url=CODEX_REF,
        doc_sha256=D_CODEX_REF,
        consulted=CONSULTED_S2,
        quote=(
            "`mcp_servers.<id>.command`: Launcher command for an MCP stdio server. "
            "`mcp_servers.<id>.args`: Arguments passed to the MCP stdio server command."
        ),
    ),
)


CURSOR_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*", "hooks"),
        kind=Kind.PRECEDENCE,
        url=CURSOR_HOOKS,
        doc_sha256=D_CURSOR_HOOKS,
        consulted=CONSULTED_S2,
        quote=(
            "Priority order (highest to lowest): Enterprise -> Team -> Project -> User. "
            "Project: `<project-root>/.cursor/hooks.json`. User: `~/.cursor/hooks.json`."
        ),
    ),
    MergeRow(
        keys=("hooks.team",),
        kind=Kind.MANAGED_ONLY,
        url=CURSOR_HOOKS,
        doc_sha256=D_CURSOR_HOOKS,
        consulted=CONSULTED_S2,
        quote=(
            "Team (Enterprise): Configured in the web dashboard and synced to all team "
            "members automatically."
        ),
    ),
    MergeRow(
        keys=("mcpServers",),
        kind=Kind.NO_DOCUMENTED_ORDER,
        url=CURSOR_MCP,
        doc_sha256=D_CURSOR_MCP,
        consulted=CONSULTED_S2,
        quote=(
            "Create `.cursor/mcp.json` in your project for project-specific tools. [...] "
            "Create `~/.cursor/mcp.json` in your home directory for tools available "
            "everywhere."
        ),
    ),
    MergeRow(
        keys=("rules",),
        kind=Kind.PRECEDENCE,
        url=CURSOR_RULES,
        doc_sha256=D_CURSOR_RULES,
        consulted=CONSULTED_S2,
        quote="Team Rules -> Project Rules -> User Rules",
    ),
)


GEMINI_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*",),
        kind=Kind.PRECEDENCE,
        url=GEMINI_CONFIG,
        doc_sha256=D_GEMINI_CONFIG,
        consulted=CONSULTED_S2,
        quote=(
            "Configuration is applied in the following order of precedence (lower numbers "
            "are overridden by higher numbers): 1. Default values, 2. System defaults file, "
            "3. User settings file, 4. Project settings file, 5. System settings file, "
            "6. Environment variables, 7. Command-line arguments."
        ),
    ),
    MergeRow(
        keys=("mcpServers",),
        kind=Kind.LIST_UNION,
        url=GEMINI_ENTERPRISE,
        doc_sha256=D_GEMINI_ENTERPRISE,
        consulted=CONSULTED_S2,
        quote=(
            "The lists of servers from all three levels are combined into a single list. "
            "[...] If a server with the same name is defined at multiple levels [...] the "
            "definition from the highest-precedence level is used."
        ),
    ),
    MergeRow(
        keys=("mcpServers.trust",),
        kind=Kind.PRECEDENCE,
        url=GEMINI_CONFIG,
        doc_sha256=D_GEMINI_CONFIG,
        consulted=CONSULTED_S2,
        quote="Trust this server and bypass all tool call confirmations.",
    ),
    MergeRow(
        keys=("tools.discoveryCommand", "tools.callCommand"),
        kind=Kind.PRECEDENCE,
        url=GEMINI_CONFIG,
        doc_sha256=D_GEMINI_CONFIG,
        consulted=CONSULTED_S2,
        quote=(
            "`tools.discoveryCommand`: Command to run for tool discovery. "
            "`tools.callCommand`: Custom shell command for invoking discovered tools."
        ),
    ),
)


INSTRUCTIONS_ROWS: tuple[MergeRow, ...] = (
    MergeRow(
        keys=("*", "import"),
        kind=Kind.APPROVAL_GATED,
        url=CLAUDE_MEMORY,
        doc_sha256=D_CLAUDE_MEMORY,
        consulted=CONSULTED_S2,
        quote=(
            "An import in a project-level memory file is external when its path resolves "
            "outside your working directory [...] The first time Claude Code encounters "
            "external imports in a project, it shows an approval dialog listing the files. "
            "If you decline, the imports stay disabled and the dialog doesn't appear again."
        ),
    ),
    MergeRow(
        keys=("import.syntax",),
        kind=Kind.NOT_TRUST_GATED,
        url=CLAUDE_MEMORY,
        doc_sha256=D_CLAUDE_MEMORY,
        consulted=CONSULTED_S2,
        quote=(
            "CLAUDE.md files can import additional files using `@path/to/import` syntax. "
            "[...] Both relative and absolute paths are allowed. [...] Import parsing skips "
            "Markdown code spans and fenced code blocks."
        ),
    ),
    MergeRow(
        keys=("import.gemini",),
        kind=Kind.NOT_TRUST_GATED,
        url=GEMINI_MEMPORT,
        doc_sha256=D_GEMINI_MEMPORT,
        consulted=CONSULTED_S2,
        quote=(
            "You can modularize your context files by importing other Markdown files using "
            "the `@path/to/file.md` syntax. The import processor supports both relative and "
            "absolute paths."
        ),
    ),
)


# Every vendor's table, by the vendor string its reader stamps on a capability.
MERGE_TABLES: dict[str, tuple[MergeRow, ...]] = {
    "claude-code": CLAUDE_CODE_ROWS,
    "vscode": VSCODE_ROWS,
    "devcontainer": DEVCONTAINER_ROWS,
    "codex": CODEX_ROWS,
    "cursor": CURSOR_ROWS,
    "gemini-cli": GEMINI_ROWS,
    "instructions": INSTRUCTIONS_ROWS,
}

# What the report publishes: every row of every table, in a stable order so two
# runs over one tree produce the same bytes.
MERGE_TABLE: tuple[MergeRow, ...] = tuple(
    row for vendor in sorted(MERGE_TABLES) for row in MERGE_TABLES[vendor]
)


def row_for(key: str, vendor: str = VENDOR) -> MergeRow:
    """The row that governs one key FOR ONE VENDOR, falling back to its ladder.

    The vendor is an argument and not a default lookup across one flat table,
    which is D-286's point made structural: `permissions` means one thing to
    Claude Code and `hooks` means a different thing to Cursor, and a single
    table keyed on the spelling alone would let one vendor's documented rule
    resolve another vendor's capability. Each vendor's fallback is that
    vendor's own published precedence row, so every capability names a rule
    that exists on one of ITS pages.
    """
    table = MERGE_TABLES.get(vendor) or CLAUDE_CODE_ROWS
    for row in table:
        if key in row.keys and row.kind is not Kind.PRECEDENCE:
            return row
    for row in table:
        if key in row.keys:
            return row
    return table[0]


def rule_name(row: MergeRow) -> str:
    """A short stable handle for a row, printed beside every capability."""
    return "{}:{}".format(row.url.rsplit("/", 1)[-1], row.keys[0])


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_version(spoken: str | None) -> tuple[int, int, int] | None:
    """`2.1.257` -> (2, 1, 257). Anything else is None, which means unknown.

    Unknown is a first-class answer here and never a default to the newest
    plausible release. Published limit 13: the merge semantics depend on the
    agent's version, and resolving with the version that seems most likely is
    exactly the invention the third negative forbids.
    """
    if not spoken:
        return None
    found = VERSION.match(spoken.strip().lstrip("v"))
    if not found:
        return None
    return (int(found.group(1)), int(found.group(2)), int(found.group(3)))


def spell(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)
