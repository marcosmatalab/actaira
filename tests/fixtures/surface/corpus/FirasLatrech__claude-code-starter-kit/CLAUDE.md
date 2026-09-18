# CLAUDE.md — Project Instructions

## Project

<!-- Replace with your project description -->
<!-- Example: E-commerce platform built with Next.js + NestJS + PostgreSQL -->

## Structure

<!-- Replace with your project structure -->
<!-- Example:
```
my-project/
├── apps/
│   ├── api/       # Backend
│   └── web/       # Frontend
├── packages/      # Shared code
└── package.json
```
-->

## Commands

<!-- Replace with your actual commands -->
```bash
# npm run dev          # start dev server
# npm run build        # production build
# npm run lint         # lint entire project
# npm run test         # run all tests
# npm run typecheck    # type check
```

## Global Rules

### File Size Limit

**Every file must stay under 150 lines.** If approaching the limit:
- Components: extract sub-components into the same folder
- Services: split by entity or concern
- Utils: split by domain

### Code Quality

- **No `any`** — use `unknown` and narrow, or define proper types
- **No `console.log`** in production code
- **No barrel exports** (`index.ts`) — import directly from the source file

### Git Commits

- **Never add `Co-Authored-By: Claude`** or any Claude/AI attribution to commit messages
- Commits must appear as authored solely by the developer

## Agent Behavior

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- Write plan to `tasks/todo.md` with checkable items — wait for approval before coding
- If something goes sideways, **STOP and re-plan immediately** — don't keep pushing
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake next time
- Ruthlessly iterate on these lessons until mistake rate drops
- Review `tasks/lessons.md` at session start for relevant project
- If something new was learned, propose adding it to the right doc file — wait for approval

### 4. Verification Before Done
- **Never mark a task complete without proving it works**
- Run typecheck + lint + test before saying "done"
- Ask yourself: "Would a staff engineer approve this?"
- Diff behavior between main and your changes when relevant
- Check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- **Skip this for simple, obvious fixes** — don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests — then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

### 7. Core Principles
- **Simplicity First** — Make every change as simple as possible. Impact minimal code
- **No Laziness** — Find root causes. No temporary fixes. Senior developer standards
- **No Guessing** — Say "I'm not sure" rather than hallucinating. Verify before asserting

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items
2. **Verify Plan**: Check in with user before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to `tasks/todo.md`
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections

### Slash Commands

| Command | What it does |
|---------|-------------|
| `/verify` | Run lint + typecheck + test + build |
| `/learn [topic]` | Capture a new pattern/gotcha into docs |
| `/audit-docs` | Scan codebase vs docs, find undocumented gaps |
| `/security-review [area]` | OWASP security audit (read-only agent) |
| `/review [file]` | Convention compliance check (read-only agent) |
| `/write-tests [file]` | Generate tests matching project patterns |
| `/split-file [file]` | Split oversized files preserving imports |

### Guardrails (Enforced by Hooks)

**PostToolUse** (after every file edit):
- File length must stay under 150 lines
- No `any` type usage
- No `console.log` in production code
- Auto-run linter on edited files

**PreToolUse** (before bash commands):
- Blocks `rm -rf /`, `git push --force main`, `curl | sh`, `DROP TABLE`

**SessionStart** (every session):
- Auto-injects git status, recent commits, current task, and lesson count

### Custom Agents

| Agent | Purpose |
|-------|---------|
| `security-reviewer` | OWASP Top 10 audit (read-only, cannot edit) |
| `code-reviewer` | Convention compliance check (read-only) |
| `test-writer` | Writes tests matching project patterns |
| `refactor-splitter` | Splits files over 150 lines preserving imports |

### Context Tips

- Use `/compact` at ~70% context to keep performance high
- Use `/compact focus on the API changes` to preserve specific context
- Start fresh conversations for unrelated tasks
- Commit working code before starting a new feature

## Compact Instructions

When summarizing during compaction, preserve:
- All code changes made (file paths + what changed)
- Errors encountered and how they were fixed
- Decisions made and why
- Current task progress and next steps
