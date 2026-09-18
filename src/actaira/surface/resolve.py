"""The merge semantics, as a table of cited rows, and a pure function over it.

Design note D-273. Every merge decision is a ROW here, never an `if` somewhere
in the resolver. A row carries the key or family it governs, the rule, the URL
it came from, a digest of that page as retrieved, the date it was read, and the
sentence that says it. `tests/test_surface.py` fails on a row missing any of
those, and that test is itself exercised against a row with the citation removed
so it cannot be passing by never looking.

Rejected: citing "the Claude Code documentation" once at the top of the file.
The pages change independently, a rule that moved is indistinguishable from a
rule we misread, and the whole product claim is that a capability names the
documented rule that resolved it. One citation for thirteen rules is one
citation short of twelve.

Why a DIGEST and not a version number. These pages publish no version string and
no last-updated date - checked across all eight on the consultation date below.
So the honest anchor is the page as retrieved: sha256 over the markdown
`code.claude.com` served, plus the date. That is limit 14 applied to our own
sources rather than only to the user's - an approval over a page NAME is an
approval over whatever is at that name tomorrow. Where a page states an agent
version that governs a rule, `since` carries it as well, because that number is
the one the answer actually depends on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from . import (
    REPOSITORY_SCOPES,
    Capability,
    NotRead,
    Resolution,
    Scope,
    Surface,
    Unresolved,
)
from .claude_code import STARTUP_EVENTS, VENDOR, Reading, digest_of, hook_handlers

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


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

UNPINNED = ("npx", "uvx", "bunx", "pnpm", "npm", "yarn")
REMOTE_TRANSPORTS = ("http", "streamable-http", "sse", "ws", "websocket")


def _trust_state(reading: Reading, scope: Scope) -> tuple[Resolution, str | None]:
    """What workspace trust does to a capability from this scope.

    Only a repository scope waits. A value in the user or managed scope is the
    operator's own and the trust dialog is not about it, so it resolves.
    """
    if scope not in REPOSITORY_SCOPES:
        return Resolution.EFFECTIVE, None
    if reading.trusted is True:
        return Resolution.EFFECTIVE, None
    if reading.trusted is False:
        return Resolution.DECLARED, "the workspace trust dialog has not been accepted"
    return (
        Resolution.DECLARED,
        "waits for the workspace trust dialog; the trust state was not read "
        "(run with --machine to read it)",
    )


def _default_mode(
    reading: Reading, scope: Scope, mode: str, version: tuple[int, int, int] | None
) -> tuple[Resolution, str | None]:
    """The canonical declared-versus-effective case, and the only one with a threshold.

    `bypassPermissions` in a committed `.claude/settings.json` started every
    session with the prompts skipped until v2.1.257 and does nothing from
    v2.1.257. With no version, that is not a question this tool gets to answer:
    it names the threshold and returns INDETERMINATE.
    """
    if scope not in REPOSITORY_SCOPES:
        return Resolution.EFFECTIVE, None
    if mode == "auto":
        return (
            Resolution.DECLARED,
            "`auto` does not take effect from project or local settings at any version",
        )
    if mode != "bypassPermissions":
        return Resolution.EFFECTIVE, None
    if version is None:
        return (
            Resolution.INDETERMINATE,
            "the agent version is unknown: effective before {0}, not from {0}".format(
                spell(BYPASS_NEEDS_USER_SCOPE_FROM)
            ),
        )
    if version < BYPASS_NEEDS_USER_SCOPE_FROM:
        return (
            Resolution.EFFECTIVE,
            f"version {spell(version)} is before {spell(BYPASS_NEEDS_USER_SCOPE_FROM)}, where a repository file could still set it",
        )
    return (
        Resolution.DECLARED,
        f"does not take effect from project or local settings from version {spell(BYPASS_NEEDS_USER_SCOPE_FROM)}",
    )


def _emit(
    found: list[Capability],
    *,
    name: str,
    scope: Scope,
    source: str,
    key: str,
    resolution: Resolution,
    condition: str | None = None,
    facts: dict[str, Any] | None = None,
    vendor: str = VENDOR,
) -> None:
    row = row_for(key, vendor)
    found.append(
        Capability(
            name=name,
            vendor=vendor,
            scope=scope,
            source=source,
            resolution=resolution,
            merge_rule=rule_name(row),
            condition=condition,
            facts=facts or {},
        )
    )


def _hooks(
    reading: Reading,
    handle: Any,
    found: list[Capability],
    with_content: bool,
    unresolved: list[Unresolved] | None = None,
) -> None:
    from .claude_code import HANDLER_TYPES

    for event, handler in hook_handlers(handle.data):
        kind = handler.get("type")
        if not isinstance(kind, str):
            continue
        if kind not in HANDLER_TYPES:
            # D-290. The capability name is ours, never the file's. A handler
            # type this release does not know is a gap with the type named, not
            # a capability spelled by whoever wrote the settings file.
            if unresolved is not None:
                unresolved.append(
                    Unresolved(
                        subject=f"{event} hook in {handle.display}",
                        cause=(
                            f"handler type {kind!r} is not one this release reads; the "
                            "documented types are " + ", ".join(HANDLER_TYPES)
                        ),
                        source=handle.display,
                    )
                )
            continue
        facts: dict[str, Any] = {
            "event": event,
            "handler": kind,
            "at_startup": event in STARTUP_EVENTS,
        }
        matcher = handler.get("matcher")
        if isinstance(matcher, str):
            facts["matcher"] = matcher
        if kind == "command" and isinstance(handler.get("command"), str):
            command = handler["command"]
            facts["command_sha256"] = digest_of(command)
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(_target_facts(reading, spoken))
            if with_content:
                facts["command"] = command
        if kind == "http" and isinstance(handler.get("url"), str):
            url = handler["url"]
            facts["url_sha256"] = digest_of(url)
            facts["host"] = _host(url)
            facts["loopback"] = _is_loopback(facts["host"])
            if with_content:
                facts["url"] = url
        if kind == "mcp_tool" and isinstance(handler.get("tool"), str):
            facts["tool_sha256"] = digest_of(handler["tool"])
        resolution, condition = Resolution.EFFECTIVE, None
        if handle.scope in REPOSITORY_SCOPES:
            # Not trust-gated: the documentation puts hooks in settings files in
            # the row that is Used before any trust step. This is the fact that
            # makes both 2026 worms work at all, so it is stated rather than
            # assumed.
            condition = "applies before any workspace trust step"
        _emit(
            found,
            name={"command": "hook.command", "http": "hook.http",
                  "mcp_tool": "hook.mcp_tool"}[kind],
            scope=handle.scope,
            source=handle.display,
            key="hooks",
            resolution=resolution,
            condition=condition,
            facts=facts,
        )


def referenced_target(command: str) -> str | None:
    from .claude_code import referenced_path

    return referenced_path(command)


def _target_facts(reading: Reading, spoken: str | None) -> dict[str, Any]:
    if spoken is None:
        return {"target_unknown_because": "no path was recognised in the command"}
    facts = reading.scripts.get(spoken)
    return {"target_facts": facts} if facts else {}


def _host(url: str) -> str:
    without = url.split("://", 1)[-1]
    return without.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def _is_loopback(host: str) -> bool:
    """Whether a hook or server endpoint stays on this machine.

    `0.0.0.0` is in the list and the linter is right that it usually means
    "bind everywhere". It is not a bind address here: it is a DESTINATION
    somebody wrote in a settings file, and as a destination it resolves to the
    local host. Reporting it as remote would be a finding about a host nothing
    reaches.
    """
    return host in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")  # noqa: S104


def _permissions(handle: Any, reading: Reading, found: list[Capability],
                 version: tuple[int, int, int] | None) -> None:
    block = handle.data.get("permissions")
    if not isinstance(block, dict):
        return
    mode = block.get("defaultMode")
    if isinstance(mode, str):
        resolution, condition = _default_mode(reading, handle.scope, mode, version)
        _emit(
            found,
            name="permissions.default_mode",
            scope=handle.scope,
            source=handle.display,
            key="permissions.defaultMode",
            resolution=resolution,
            condition=condition,
            facts={"mode": mode},
        )
    for entry in block.get("allow") or []:
        if not isinstance(entry, str):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        _emit(
            found,
            name="permissions.allow",
            scope=handle.scope,
            source=handle.display,
            key="permissions.allow",
            resolution=resolution,
            condition=condition,
            facts={"rule": entry, "tool": entry.split("(", 1)[0]},
        )
    for entry in block.get("additionalDirectories") or []:
        if not isinstance(entry, str):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        from .claude_code import inside_tree

        _emit(
            found,
            name="permissions.additional_directory",
            scope=handle.scope,
            source=handle.display,
            key="permissions.additionalDirectories",
            resolution=resolution,
            condition=condition,
            facts={"path": entry, "inside_tree": inside_tree(reading.root, entry)},
        )


def _helpers(handle: Any, found: list[Capability], with_content: bool) -> None:
    from .claude_code import COMMAND_KEYS

    for key in COMMAND_KEYS:
        value = handle.data.get(key)
        command = None
        if isinstance(value, str):
            command = value
        elif isinstance(value, dict) and isinstance(value.get("command"), str):
            command = value["command"]
        if command is None:
            continue
        facts: dict[str, Any] = {"key": key, "command_sha256": digest_of(command)}
        if with_content:
            facts["command"] = command
        _emit(
            found,
            name="helper.command",
            scope=handle.scope,
            source=handle.display,
            key=key,
            resolution=Resolution.EFFECTIVE,
            condition=(
                "applies before any workspace trust step"
                if handle.scope in REPOSITORY_SCOPES
                else None
            ),
            facts=facts,
        )


def _managed_sandbox(reading: Reading) -> dict[str, frozenset[str] | None]:
    """What the managed scope already allows, so a widening can be named.

    `None` when no managed file was read at all, and that is the load-bearing
    case: without it, "this entry is not in the managed list" is indistinguishable
    from "we never looked at the managed list", and rules ACT-S013 and ACT-S014
    would fire on every repository that configures a sandbox. They return
    INDETERMINATE instead, because the fact they need is absent.
    """
    seen = [handle for handle in reading.settings if handle.scope is Scope.MANAGED]
    if not any(handle.ok for handle in seen):
        return {"excluded": None, "domains": None}
    excluded: set[str] = set()
    domains: set[str] = set()
    for handle in seen:
        if not handle.ok:
            continue
        block = handle.data.get("sandbox")
        if not isinstance(block, dict):
            continue
        excluded.update(
            item for item in (block.get("excludedCommands") or []) if isinstance(item, str)
        )
        network = block.get("network")
        if isinstance(network, dict):
            domains.update(
                item for item in (network.get("allowedDomains") or []) if isinstance(item, str)
            )
    return {"excluded": frozenset(excluded), "domains": frozenset(domains)}


def _widens(facts: dict[str, Any], entry: str, managed: frozenset[str] | None) -> None:
    """Record whether this entry widens the managed policy, or record nothing.

    Nothing, when no managed scope was read - and that is the whole point of
    writing it this way rather than storing `None`. A fact recorded as null is a
    fact somebody looked up and could not settle, and a clause testing it comes
    back False; a fact that is ABSENT comes back INDETERMINATE (D-275). The
    difference decides whether `check` reports "this repository does not widen
    the managed policy" about a machine whose managed policy it never opened,
    which would be an answer to a question nobody asked it.
    """
    if managed is None:
        return
    facts["widens_managed"] = entry not in managed


def _sandbox(
    handle: Any, found: list[Capability], managed: dict[str, frozenset[str] | None]
) -> None:
    block = handle.data.get("sandbox")
    if not isinstance(block, dict):
        return
    # One fact carried by both spellings of the same weakening, so one rule
    # covers both. Two rules would have been two identifiers for one statement,
    # and COMPATIBILITY.md promises an identifier means one thing forever.
    if block.get("enabled") is False:
        _emit(
            found, name="sandbox.disabled", scope=handle.scope, source=handle.display,
            key="sandbox.enabled", resolution=Resolution.EFFECTIVE,
            facts={"enabled": False, "isolation_weakened": True},
        )
    if block.get("allowUnsandboxedCommands") is True:
        _emit(
            found, name="sandbox.unsandboxed_allowed", scope=handle.scope,
            source=handle.display, key="sandbox.allowUnsandboxedCommands",
            resolution=Resolution.EFFECTIVE,
            facts={"allowUnsandboxedCommands": True, "isolation_weakened": True},
        )
    repository = handle.scope in REPOSITORY_SCOPES
    for entry in block.get("excludedCommands") or []:
        if isinstance(entry, str):
            facts: dict[str, Any] = {"command_sha256": digest_of(entry)}
            if repository:
                _widens(facts, entry, managed["excluded"])
            _emit(
                found, name="sandbox.excluded_command", scope=handle.scope,
                source=handle.display, key="sandbox.excludedCommands",
                resolution=Resolution.EFFECTIVE, facts=facts,
            )
    network = block.get("network")
    if isinstance(network, dict):
        for entry in network.get("allowedDomains") or []:
            if isinstance(entry, str):
                facts = {"domain": entry, "wildcard": entry.startswith("*")}
                if repository:
                    _widens(facts, entry, managed["domains"])
                _emit(
                    found, name="sandbox.network_domain", scope=handle.scope,
                    source=handle.display, key="sandbox.network.allowedDomains",
                    resolution=Resolution.EFFECTIVE, facts=facts,
                )


def _mcp(handle: Any, reading: Reading, found: list[Capability], with_content: bool) -> None:
    servers = handle.data.get("mcpServers")
    if not isinstance(servers, dict):
        return
    for name in sorted(servers):
        entry = servers[name]
        if not isinstance(entry, dict):
            continue
        transport = entry.get("type") or ("http" if entry.get("url") else "stdio")
        # `pinned` and `loopback` are always present, null when the question does
        # not apply to this server - a `node server.js` launch is not an unpinned
        # fetch, and a stdio server has no host. Null is an answer the reader
        # recorded; absent would mean nobody looked, and a rule treats those two
        # differently on purpose (D-275).
        facts: dict[str, Any] = {
            "server": name,
            "transport": str(transport),
            "pinned": None,
            "loopback": None,
        }
        if isinstance(entry.get("command"), str):
            launcher = entry["command"].replace("\\", "/").rsplit("/", 1)[-1]
            arguments = [item for item in (entry.get("args") or []) if isinstance(item, str)]
            facts["launcher"] = launcher
            facts["pinned"] = _pinned(launcher, arguments)
            facts["args_sha256"] = digest_of(" ".join(arguments))
            if with_content:
                facts["args"] = arguments
        if isinstance(entry.get("url"), str):
            facts["host"] = _host(entry["url"])
            facts["loopback"] = _is_loopback(facts["host"])
            facts["url_sha256"] = digest_of(entry["url"])
            if with_content:
                facts["url"] = entry["url"]
        facts["remote"] = str(transport).lower() in REMOTE_TRANSPORTS
        resolution, condition = _trust_state(reading, handle.scope)
        _emit(
            found, name="mcp.server", scope=handle.scope, source=handle.display,
            key="enableAllProjectMcpServers", resolution=resolution, condition=condition,
            facts=facts,
        )


def _pinned(launcher: str, arguments: list[str]) -> bool | None:
    """Whether an `npx`-style launch names a version. None when it is not one.

    `@` after the first character is the pin, so `@scope/name@1.2.3` is pinned
    and `@scope/name` is not. None rather than True for a launcher this rule
    does not cover: a plain `node server.js` is not an unpinned fetch, and
    answering False about it would be a finding about a fact nobody observed.
    """
    if launcher not in UNPINNED:
        return None
    for argument in arguments:
        if argument.startswith("-"):
            continue
        return "@" in argument[1:]
    return False


def _approvals(handle: Any, reading: Reading, found: list[Capability]) -> None:
    for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers"):
        value = handle.data.get(key)
        if value in (None, False, []):
            continue
        resolution, condition = _trust_state(reading, handle.scope)
        _emit(
            found, name="mcp.approval", scope=handle.scope, source=handle.display,
            key=key, resolution=resolution, condition=condition,
            facts={"key": key, "value": value if isinstance(value, bool) else list(value)},
        )


def resolve(
    reading: Reading,
    *,
    agent_version: str | None = None,
    with_content: bool = False,
) -> Surface:
    """Everything the reader saw, resolved into capabilities. A pure function.

    Pure over `reading` and `agent_version` and nothing else: no clock, no
    socket, and no disk beyond what the reader already put in `reading`. That is
    what lets the whole decision path be replayed from a fixture, which is what
    makes a golden corpus worth having.
    """
    version = parse_version(agent_version)
    found: list[Capability] = []
    unresolved: list[Unresolved] = list(reading.unresolved)
    managed = _managed_sandbox(reading)

    for handle in reading.settings:
        if not handle.ok:
            continue
        _hooks(reading, handle, found, with_content, unresolved)
        _permissions(handle, reading, found, version)
        _helpers(handle, found, with_content)
        _sandbox(handle, found, managed)
        _approvals(handle, reading, found)
        _mcp(handle, reading, found, with_content)

    for handle in reading.mcp_files:
        if handle.ok:
            _mcp(handle, reading, found, with_content)
            _hooks(reading, handle, found, with_content, unresolved)

    if version is None and any(
        item.resolution is Resolution.INDETERMINATE for item in found
    ):
        unresolved.append(
            Unresolved(
                subject="agent version",
                cause=(
                    "no --agent-version claude-code=X.Y.Z was given and nothing on disk "
                    "states it, so every rule whose answer depends on the version is "
                    "indeterminate (published limit 13)"
                ),
                source="--agent-version",
            )
        )

    return Surface(
        vendor=VENDOR,
        agent_version=spell(version) if version else None,
        capabilities=tuple(found),
        unresolved=tuple(unresolved),
        not_read=tuple(reading.not_read),
    )


# ---------------------------------------------------------------------------
# One resolver per vendor, and the union that is the repository's surface
# ---------------------------------------------------------------------------
#
# Each of these is a pure function of what its reader read, exactly like
# `resolve` above. None of them touches disk, a clock or a socket, which is what
# lets a fixture replay the whole decision path.
#
# Nothing here ever fuses two vendors' capabilities. If Cursor and Claude Code
# configure the same MCP server, that is TWO capabilities with the same
# `args_sha256`, each naming its own vendor, its own file and its own merge
# rule - and the report says so rather than collapsing them into one row that
# belongs to neither. Two vendors running the same command is two things that
# can be removed independently and two approvals that expire independently.


def _vscode(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """VS Code: the tasks, and the setting that decides whether they run.

    The three answers of D-282 are produced here and nowhere else. `allowed` is
    the value a scope we actually READ supplies, so `None` means no scope we
    opened said either way - which is INDETERMINATE, not the documented default.
    """
    from .vscode import (
        ALLOWED,
        AUTOMATIC_TASKS,
        BLOCKED,
        automatic_tasks_setting,
        runs_on,
        task_command,
        tasks_in,
        workspace_claims_automatic_tasks,
    )

    found: list[Capability] = []
    unresolved: list[Unresolved] = list(reading.unresolved)
    allowed, decided_by = automatic_tasks_setting(reading)

    for handle in reading.settings:
        if not handle.ok:
            continue
        for entry in tasks_in(handle.data):
            command = task_command(entry)
            if command is None:
                continue
            when = runs_on(entry)
            automatic = when == "folderOpen"
            facts: dict[str, Any] = {
                "label": entry.get("label") if isinstance(entry.get("label"), str) else None,
                "task_type": entry.get("type") if isinstance(entry.get("type"), str) else None,
                "run_on": when,
                "at_startup": automatic,
                "command_sha256": digest_of(command),
            }
            if with_content:
                facts["command"] = command
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(_target_facts(reading, spoken))

            resolution, condition = Resolution.EFFECTIVE, None
            if automatic:
                if allowed == ALLOWED:
                    facts["automatic_allowed"] = True
                    resolution = Resolution.EFFECTIVE
                    condition = (
                        f"`{AUTOMATIC_TASKS}` is `{ALLOWED}` in {decided_by}, and automatic "
                        "tasks still never run in an untrusted workspace"
                    )
                elif allowed == BLOCKED:
                    facts["automatic_allowed"] = False
                    resolution = Resolution.DECLARED
                    condition = f"`{AUTOMATIC_TASKS}` is `{BLOCKED}` in {decided_by}"
                else:
                    # No `automatic_allowed` fact at all, which is the point:
                    # a rule that needs it comes back INDETERMINATE on its own
                    # rather than being told to (D-275).
                    resolution = Resolution.INDETERMINATE
                    condition = (
                        f"`{AUTOMATIC_TASKS}` decides whether this runs; it is "
                        "APPLICATION-scoped, so only the user's own settings file can set "
                        "it, and no scope this run read says either way (run with --machine)"
                    )
            _emit(
                found,
                name="task.command",
                scope=handle.scope,
                source=handle.display,
                key="tasks",
                resolution=resolution,
                condition=condition,
                facts=facts,
                vendor=reading.vendor,
            )

    # A repository that writes the application-scoped key into `.vscode/`. VS
    # Code does not honour it there, so the capability it declared is not one -
    # and saying nothing would lose the fact that somebody tried.
    for handle in workspace_claims_automatic_tasks(reading):
        _emit(
            found,
            name="settings.ignored_key",
            scope=handle.scope,
            source=handle.display,
            key="task.allowAutomaticTasks",
            resolution=Resolution.DECLARED,
            condition=(
                "the key is APPLICATION-scoped, so VS Code does not take it from a "
                "workspace file; the value in the user's settings is what decides"
            ),
            facts={
                "key": AUTOMATIC_TASKS,
                "value": handle.data.get(AUTOMATIC_TASKS),
                "honoured_here": False,
            },
            vendor=reading.vendor,
        )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(unresolved),
        not_read=tuple(reading.not_read),
    )


def _devcontainer(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """A dev container's lifecycle commands, its mounts and its isolation flags."""
    from .devcontainer import LIFECYCLE, commands_of, mount_source, names_a_credential

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        data = handle.data
        for key, on_host in LIFECYCLE.items():
            for command in commands_of(data.get(key)):
                facts: dict[str, Any] = {
                    "key": key,
                    "on_host": on_host,
                    "command_sha256": digest_of(command),
                }
                if with_content:
                    facts["command"] = command
                spoken = referenced_target(command)
                facts["target"] = spoken
                facts.update(_target_facts(reading, spoken))
                _emit(
                    found,
                    name="lifecycle.command",
                    scope=handle.scope,
                    source=handle.display,
                    key=key,
                    resolution=Resolution.EFFECTIVE,
                    condition=(
                        "runs on the host during initialization, before any container exists"
                        if on_host
                        else "runs inside the container"
                    ),
                    facts=facts,
                    vendor=reading.vendor,
                )

        mounts = data.get("mounts")
        for entry in mounts if isinstance(mounts, list) else []:
            source = mount_source(entry)
            if source is None:
                continue
            credential = names_a_credential(source)
            _emit(
                found,
                name="container.mount",
                scope=handle.scope,
                source=handle.display,
                key="mounts",
                resolution=Resolution.EFFECTIVE,
                facts={
                    "source": source,
                    "credential": credential,
                    "names_credential": credential is not None,
                },
                vendor=reading.vendor,
            )

        for key in ("privileged",):
            if data.get(key) is True:
                _emit(
                    found, name="container.isolation", scope=handle.scope,
                    source=handle.display, key=key, resolution=Resolution.EFFECTIVE,
                    facts={"key": key, "value": True, "isolation_weakened": True},
                    vendor=reading.vendor,
                )
        for key in ("capAdd", "securityOpt"):
            entries = data.get(key)
            for entry in entries if isinstance(entries, list) else []:
                if not isinstance(entry, str):
                    continue
                _emit(
                    found, name="container.isolation", scope=handle.scope,
                    source=handle.display, key=key, resolution=Resolution.EFFECTIVE,
                    facts={"key": key, "value": entry, "isolation_weakened": True},
                    vendor=reading.vendor,
                )

        features = data.get("features")
        for name in sorted(features) if isinstance(features, dict) else []:
            # `pinned` follows the same reading as an npx launch: the `@` after
            # the first character is the version. A feature is fetched at build
            # time, so an unpinned one resolves to whatever is published then.
            spelled = str(name)
            _emit(
                found, name="container.feature", scope=handle.scope,
                source=handle.display, key="features", resolution=Resolution.EFFECTIVE,
                facts={"feature": spelled, "pinned": "@" in spelled[1:]},
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )


def _codex_trust(reading: Any, scope: Scope) -> tuple[Resolution, str | None]:
    """Codex's project layer waits on `projects.<path>.trust_level`.

    Same shape as Claude Code's workspace trust and a different mechanism, so it
    is written out rather than shared: the trust state lives in the user's own
    config file, and a run that did not open it says so instead of assuming.
    """
    if scope not in REPOSITORY_SCOPES:
        return Resolution.EFFECTIVE, None
    if reading.trusted is True:
        return Resolution.EFFECTIVE, None
    if reading.trusted is False:
        return Resolution.DECLARED, "this project's trust_level is `untrusted`, so the .codex/ layer is skipped"
    return (
        Resolution.DECLARED,
        "the project .codex/ layer loads only when trusted, and no trust_level was read "
        "(run with --machine to read ~/.codex/config.toml)",
    )


def _codex(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """Codex CLI: hooks, MCP servers, `notify`, and the sandbox pair."""
    from .codex import FULL_ACCESS, NEVER_ASKS, hook_command
    from .codex import STARTUP_EVENTS as CODEX_STARTUP
    from .codex import hook_handlers as codex_hooks

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        data = handle.data
        resolution, condition = _codex_trust(reading, handle.scope)

        for event, handler in codex_hooks(data):
            command = hook_command(handler)
            if command is None:
                continue
            facts: dict[str, Any] = {
                "event": event,
                "at_startup": event in CODEX_STARTUP,
                "command_sha256": digest_of(command),
            }
            if isinstance(handler.get("matcher"), str):
                facts["matcher"] = handler["matcher"]
            if with_content:
                facts["command"] = command
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(_target_facts(reading, spoken))
            _emit(
                found, name="hook.command", scope=handle.scope, source=handle.display,
                key="hooks", resolution=resolution, condition=condition, facts=facts,
                vendor=reading.vendor,
            )

        notify = data.get("notify")
        command = None
        if isinstance(notify, list):
            parts = [item for item in notify if isinstance(item, str)]
            command = " ".join(parts) if parts else None
        elif isinstance(notify, str):
            command = notify
        if command is not None:
            facts = {"key": "notify", "command_sha256": digest_of(command)}
            if with_content:
                facts["command"] = command
            _emit(
                found, name="helper.command", scope=handle.scope, source=handle.display,
                key="notify",
                # `notify` is on the list of keys a project file cannot set, so a
                # repository that sets one has declared something Codex ignores.
                resolution=(
                    Resolution.DECLARED if handle.scope in REPOSITORY_SCOPES
                    else Resolution.EFFECTIVE
                ),
                condition=(
                    "project-scoped config cannot override notification keys"
                    if handle.scope in REPOSITORY_SCOPES else None
                ),
                facts=facts, vendor=reading.vendor,
            )

        mode = data.get("sandbox_mode")
        if isinstance(mode, str):
            _emit(
                found, name="sandbox.mode", scope=handle.scope, source=handle.display,
                key="sandbox_mode", resolution=Resolution.EFFECTIVE,
                facts={"mode": mode, "guardrail_removed": mode == FULL_ACCESS},
                vendor=reading.vendor,
            )
        policy = data.get("approval_policy")
        if isinstance(policy, str):
            _emit(
                found, name="approval.policy", scope=handle.scope, source=handle.display,
                key="approval_policy", resolution=Resolution.EFFECTIVE,
                facts={"policy": policy, "guardrail_removed": policy == NEVER_ASKS},
                vendor=reading.vendor,
            )

        servers = data.get("mcp_servers")
        for name in sorted(servers) if isinstance(servers, dict) else []:
            entry = servers[name]
            if not isinstance(entry, dict):
                continue
            _emit(
                found, name="mcp.server", scope=handle.scope, source=handle.display,
                key="mcp_servers", resolution=resolution, condition=condition,
                facts=_server_facts(name, entry, with_content=with_content),
                vendor=reading.vendor,
            )

        if data.get("allow_managed_hooks_only") is True and handle.scope is Scope.MANAGED:
            _emit(
                found, name="policy.managed_hooks_only", scope=handle.scope,
                source=handle.display, key="allow_managed_hooks_only",
                resolution=Resolution.EFFECTIVE,
                facts={"key": "allow_managed_hooks_only", "value": True},
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )


def _cursor(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """Cursor: the hooks that are files, and the MCP servers beside them."""
    from .cursor import STARTUP_EVENTS as CURSOR_STARTUP
    from .cursor import hook_command, hook_entries

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        for event, entry in hook_entries(handle.data):
            command = hook_command(entry)
            if command is None:
                continue
            facts: dict[str, Any] = {
                "event": event,
                "at_startup": event in CURSOR_STARTUP,
                "command_sha256": digest_of(command),
            }
            if with_content:
                facts["command"] = command
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(_target_facts(reading, spoken))
            _emit(
                found, name="hook.command", scope=handle.scope, source=handle.display,
                key="hooks", resolution=Resolution.EFFECTIVE,
                condition=(
                    "an enterprise or team hook outranks this one, and the team level is "
                    "not a file"
                    if handle.scope in REPOSITORY_SCOPES else None
                ),
                facts=facts, vendor=reading.vendor,
            )

    for handle in reading.mcp_files:
        if not handle.ok:
            continue
        servers = handle.data.get("mcpServers")
        for name in sorted(servers) if isinstance(servers, dict) else []:
            entry = servers[name]
            if not isinstance(entry, dict):
                continue
            _emit(
                found, name="mcp.server", scope=handle.scope, source=handle.display,
                key="mcpServers", resolution=Resolution.EFFECTIVE,
                facts=_server_facts(name, entry, with_content=with_content),
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )


def _gemini(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """Gemini CLI: MCP servers with their `trust` flag, and the two tool commands."""
    from .gemini import AUTO_EDIT, dig
    from .gemini import COMMAND_KEYS as GEMINI_KEYS
    from .gemini import LEGACY_COMMAND_KEYS as LEGACY_KEYS

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        data = handle.data
        servers = dig(data, "mcpServers")
        for name in sorted(servers) if isinstance(servers, dict) else []:
            entry = servers[name]
            if not isinstance(entry, dict):
                continue
            facts = _server_facts(name, entry, with_content=with_content)
            # Gemini's own key, and the reason this vendor's servers are worth
            # reading separately: one boolean removes every confirmation for
            # one server's tools.
            facts["trusted_by_config"] = entry.get("trust") is True
            if isinstance(entry.get("httpUrl"), str):
                facts["remote"] = True
                facts["host"] = _host(entry["httpUrl"])
                facts["loopback"] = _is_loopback(facts["host"])
                facts["url_sha256"] = digest_of(entry["httpUrl"])
            _emit(
                found, name="mcp.server", scope=handle.scope, source=handle.display,
                key="mcpServers", resolution=Resolution.EFFECTIVE, facts=facts,
                vendor=reading.vendor,
            )

        for key in (*GEMINI_KEYS, *LEGACY_KEYS):
            command = dig(data, key)
            if not isinstance(command, str):
                continue
            legacy = key in LEGACY_KEYS
            facts = {
                "key": key,
                "command_sha256": digest_of(command),
                "spelling": "v1" if legacy else "current",
            }
            if with_content:
                facts["command"] = command
            spoken = referenced_target(command)
            facts["target"] = spoken
            facts.update(_target_facts(reading, spoken))
            _emit(
                found, name="helper.command", scope=handle.scope, source=handle.display,
                key=LEGACY_KEYS.get(key, key),
                # D-291. The v1 spelling is read and NOT resolved: the current
                # schema publishes only the nested name, and whether this
                # release still migrates the flat one is not something the
                # vendor publishes. Answering either way would invent it.
                resolution=Resolution.INDETERMINATE if legacy else Resolution.EFFECTIVE,
                condition=(
                    f"`{key}` is the v1 spelling of `{LEGACY_KEYS[key]}`; the current "
                    "settings schema publishes only the nested name, and whether this "
                    "agent version still reads the flat one is unknown "
                    "(published limit 13)"
                    if legacy else None
                ),
                facts=facts,
                vendor=reading.vendor,
            )

        mode = dig(data, "general.defaultApprovalMode")
        if isinstance(mode, str):
            _emit(
                found, name="approval.policy", scope=handle.scope, source=handle.display,
                key="*", resolution=Resolution.EFFECTIVE,
                # `guardrail_removed`, the same fact name Codex's two keys carry,
                # because it is the same statement. `plan` is read-only and so is
                # a tightening; only `auto_edit` stops the agent asking.
                facts={"policy": mode, "guardrail_removed": mode == AUTO_EDIT},
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )


def _instructions(reading: Any, *, agent_version: str | None = None,
        with_content: bool = False) -> Surface:
    """The three structural facts about an instructions file, and no fourth.

    Nothing here looks at what the file MEANS. An import is a path, a piped
    download is a literal string, and a referenced script gets the same four
    facts a hook's target gets. `test_surface_instructions` asserts that a
    document telling the agent to ignore its instructions produces nothing,
    because classifying that sentence is the second negative.
    """
    from .instructions import outside_tree

    found: list[Capability] = []

    for handle in reading.settings:
        if not handle.ok:
            continue
        data = handle.data
        name = data["file"]
        for spoken in data["imports"]:
            outside = outside_tree(reading.root, spoken)
            facts: dict[str, Any] = {
                "file": name,
                "documented_by": data["documented_by"],
                "path": spoken,
                "outside_tree": outside,
                "is_script": _looks_like_a_script(spoken),
            }
            facts.update(_target_facts(reading, spoken))
            _emit(
                found,
                name="instructions.import",
                scope=handle.scope,
                source=handle.display,
                key="import",
                resolution=Resolution.DECLARED if outside else Resolution.EFFECTIVE,
                condition=(
                    "an import that resolves outside the working directory waits for a "
                    "one-time approval dialog the first time it is met"
                    if outside else None
                ),
                facts=facts,
                vendor=reading.vendor,
            )
        for line in data["piped_download_lines"]:
            _emit(
                found,
                name="instructions.remote_execution",
                scope=handle.scope,
                source=handle.display,
                key="import.syntax",
                resolution=Resolution.DECLARED,
                condition=(
                    "the file declares it; whether anybody runs it is not something a "
                    "configuration reader can see (published limit 11)"
                ),
                facts={
                    "file": name,
                    "documented_by": data["documented_by"],
                    "line": line,
                    "literal_remote_execution": True,
                },
                vendor=reading.vendor,
            )

    return Surface(
        vendor=reading.vendor,
        agent_version=None,
        capabilities=tuple(found),
        unresolved=tuple(reading.unresolved),
        not_read=tuple(reading.not_read),
    )


def _looks_like_a_script(spoken: str) -> bool:
    from .claude_code import SCRIPT_SUFFIXES

    return spoken.lower().endswith(SCRIPT_SUFFIXES)


def _server_facts(name: str, entry: dict[str, Any], *, with_content: bool) -> dict[str, Any]:
    """The facts every vendor's MCP server entry carries, in one place.

    One function and not five copies, because "unpinned" and "remote" mean the
    same thing in every vendor's file even though the surrounding key names
    differ - and five copies is five places for the reading to drift. What does
    NOT move here is the merge rule or the scope: those are per vendor, and they
    are supplied by the caller.
    """
    transport = entry.get("type") or ("http" if entry.get("url") or entry.get("httpUrl") else "stdio")
    facts: dict[str, Any] = {
        "server": name,
        "transport": str(transport),
        "pinned": None,
        "loopback": None,
    }
    if isinstance(entry.get("command"), str):
        launcher = entry["command"].replace("\\", "/").rsplit("/", 1)[-1]
        arguments = [item for item in (entry.get("args") or []) if isinstance(item, str)]
        facts["launcher"] = launcher
        facts["pinned"] = _pinned(launcher, arguments)
        facts["args_sha256"] = digest_of(" ".join(arguments))
        if with_content:
            facts["args"] = arguments
    url = entry.get("url") if isinstance(entry.get("url"), str) else entry.get("httpUrl")
    if isinstance(url, str):
        facts["host"] = _host(url)
        facts["loopback"] = _is_loopback(facts["host"])
        facts["url_sha256"] = digest_of(url)
        if with_content:
            facts["url"] = url
    facts["remote"] = str(transport).lower() in REMOTE_TRANSPORTS
    return facts


# The capabilities this package emits ON PURPOSE with no rule naming them, and
# why each one.
#
# Design note D-292. `tests/test_capability_coverage.py` fails on any (vendor,
# capability) pair the resolvers can emit that no rule names and that is not
# here with a reason. The invariant it enforces is not "there are thirty-two
# rules" - the rule count is a budget, and fifteen or thirty-one would serve
# equally - it is that this tree must not EMIT something nobody names. A
# capability in a report that no rule can ever fire on is a line a reader cannot
# act on and cannot appeal, which is the shape of a tool that publishes noise.
#
# This is a list of exceptions, and CLAUDE.md is right that a list satisfied by
# adding a line is kept by whoever declines to add one. Three things make this
# one cost something instead. A reason is required and is prose, so writing one
# means arguing it. A stale entry FAILS - an entry naming a capability nothing
# emits any more is a defect, not a leftover - so the list cannot silently
# outlive what it excuses. And the test plants a capability with no rule and
# requires the failure, so the guard cannot rot into a no-op.
#
# What is NOT an acceptable reason, stated so the next person has to look at it:
# "no rule yet". That is a rule somebody has not written, and it belongs in
# `docs/BACKLOG.md` with a phase, not here. Every entry below says why naming
# the capability would be wrong, not why it has not happened.
EMITTED_WITHOUT_A_RULE: dict[tuple[str, str], str] = {
    ("vscode", "settings.ignored_key"): (
        "This capability exists BECAUSE the vendor ignores the key. VS Code does not "
        "take an APPLICATION-scoped setting from a workspace file, so the repository "
        "has granted nothing and there is nothing for a rule to name. It is reported "
        "so a reader sees that somebody tried, which is a fact about intent that "
        "belongs in the surface and not in a finding."
    ),
    ("codex", "helper.command"): (
        "`notify` is on the list of keys the reference says a project-scoped config "
        "cannot override, so a repository that sets one has not set it - the "
        "capability is emitted DECLARED with that condition. In the user scope it is "
        "the operator's own command on their own machine. There is no scope in which "
        "a REPOSITORY grants this, which is the only thing a rule here could report."
    ),
    ("codex", "policy.managed_hooks_only"): (
        "A hardening, and the only one this tree reads. An administrator setting "
        "`allow_managed_hooks_only` in `requirements.toml` makes Codex skip user, "
        "project, session and plugin hooks. Naming it would be reporting somebody for "
        "locking their fleet down; it is emitted so the surface shows WHY a "
        "repository's hooks may not apply."
    ),
    ("gemini-cli", "helper.command"): (
        "No real violating configuration exists to test a rule against. `tools."
        "discoveryCommand` and `tools.callCommand` do run a command from a project "
        "file that overrides the user's, so a rule would be justified in principle - "
        "but five recorded searches on 2026-09-18 parsed 56 distinct public "
        "`.gemini/settings.json` files and not one set either key in the spelling the "
        "current schema publishes. CLAUDE.md's standard is that a rule arrives with a "
        "real violating case; writing one against a fixture we wrote ourselves would "
        "prove only that we can write the fixture. The capability is emitted, so "
        "nothing is hidden, and the rule waits for a case. The two repositories that "
        "DO set a tool command use the v1 flat spelling and come back INDETERMINATE "
        "(D-291), so they would not have exercised a rule either."
    ),
}


def vendor_registry() -> tuple[tuple[str, Any, Any], ...]:
    """(vendor, reader module, resolver), built on demand rather than at import.

    On demand because `cli.py` imports this module for `MERGE_TABLE` alone in
    some paths, and importing six readers to print a table is work nobody asked
    for. The tuple is rebuilt each call and is small; the cost is nothing beside
    the disk reads that follow it.
    """
    from . import claude_code as claude_code_mod
    from . import codex as codex_mod
    from . import cursor as cursor_mod
    from . import devcontainer as devcontainer_mod
    from . import gemini as gemini_mod
    from . import instructions as instructions_mod
    from . import vscode as vscode_mod

    return (
        (claude_code_mod.VENDOR, claude_code_mod, _claude_code_surface),
        (codex_mod.VENDOR, codex_mod, _codex),
        (cursor_mod.VENDOR, cursor_mod, _cursor),
        (devcontainer_mod.VENDOR, devcontainer_mod, _devcontainer),
        (gemini_mod.VENDOR, gemini_mod, _gemini),
        (instructions_mod.VENDOR, instructions_mod, _instructions),
        (vscode_mod.VENDOR, vscode_mod, _vscode),
    )


def _claude_code_surface(reading: Any, *, agent_version: str | None = None,
                         with_content: bool = False) -> Surface:
    """`resolve` under the signature every other resolver has.

    An adapter and not a rename: `resolve` is phase S1's published entry point,
    `tests/test_surface.py` calls it by that name, and a registry that needed
    one vendor spelled differently from the other six is a registry with an
    exception in it.
    """
    return resolve(reading, agent_version=agent_version, with_content=with_content)


__all__ = [
    "BYPASS_NEEDS_USER_SCOPE_FROM",
    "EMITTED_WITHOUT_A_RULE",
    "CONSULTED",
    "Kind",
    "MERGE_TABLE",
    "MERGE_TABLES",
    "MergeRow",
    "NotRead",
    "parse_version",
    "resolve",
    "row_for",
    "rule_name",
    "vendor_registry",
]
