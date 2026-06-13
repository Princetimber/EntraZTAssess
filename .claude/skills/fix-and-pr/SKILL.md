---
name: fix-and-pr
description: Use this skill in EntraZTAssess when the user explicitly asks to fix repository issues and prepare a PR. It runs a guarded evidence-first fix workflow, uses repo-specific PowerShell verification commands, and never commits, pushes, merges, publishes, or deletes branches without explicit user approval.
---

# Fix and PR Workflow

Use this skill only after the user explicitly asks for a fix workflow that may lead to a pull request. The repository is a read-only Microsoft Entra ID / Intune assessment toolkit, so tenant safety and local-only verification are more important than speed.

## Preconditions

- Load `entraztassess-repo-patterns` and follow the repository-specific module, testing, and documentation rules.
- Inspect `git status` before editing. Treat unrelated modified or untracked files as user-owned and do not revert, stage, or overwrite them.
- Confirm the requested fix is concrete enough to implement. If the request is only investigation, report findings and wait before editing.
- Do not create branches, commits, pushes, PRs, merges, or branch cleanup unless the user explicitly requested that action in the current task.

## Fix Workflow

1. **Discover**: Inspect the closest source files, matching tests, and existing patterns before changing anything.
2. **Plan**: Identify the smallest safe change. Prefer declarative `source/Checks/**/*.psd1`, `source/Settings/settings.psd1`, and `source/Settings/permissions.psd1` edits over procedural code when appropriate.
3. **Fix**: Make minimal changes under `source/`, `tests/`, or documentation files. Never hand-edit generated files under `output/`.
4. **Document**: When behavior, exported commands, checks, settings, permissions, or reporting semantics change, update the required docs in the same branch: `CHANGELOG.md`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, and `README.md` when user-facing behavior changes.
5. **Verify**: Run the narrowest useful checks first, then widen as needed:
   - After `.ps1` or `.psm1` changes: `Invoke-ScriptAnalyzer -Path source/ -Recurse`
   - After code changes: `Invoke-Pester -Path tests`
   - For build/package confidence when needed: `./build.ps1 -tasks build`, `./build.ps1 -tasks test`, or `./build.ps1 -tasks pack`
6. **Review**: Inspect the final diff and confirm only requested files changed.
7. **PR Preparation**: If the user requested a PR, prepare a concise summary, tests run, residual risks, and any known pre-existing failures.

## Git And PR Guardrails

- Do not run release tasks such as `publish_psgallery` or `publish_github` unless explicitly asked.
- Do not commit, push, merge, delete branches, or clean up worktrees unless explicitly asked.
- If a commit is requested, stage only intended files and use a concise conventional-style subject such as `fix: ...`, `docs: ...`, or `test: ...`.
- If a PR is requested, use the current verified diff to write the body. Include what changed, why, tests run, and any skipped checks.
- Never merge the PR or delete the branch as part of this skill unless the user separately and explicitly asks for those operations.

## Safety Rules

- Preserve read-only Graph behavior. Do not add Graph write methods, Graph write scopes, tenant mutation, hidden network calls, or telemetry.
- Route Graph collection through the existing wrapper functions instead of direct `Invoke-MgGraphRequest` calls.
- Do not use `Invoke-Expression`, hardcoded secrets, or broad write permissions.
- Use `Write-ToLog` for module logging.
- Do not weaken or delete failing tests to make validation pass.
- Do not treat pre-existing lint or test failures as fixed by the change; report them separately.
