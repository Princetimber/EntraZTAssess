# Copilot Instructions

This repository is **Get-EntraZTAssess**, a PowerShell 7+ Sampler module for read-only Microsoft Entra ID and Intune Zero Trust assessment. Prefer executable sources, `AGENTS.md`, and `CLAUDE.md` over template-era prose.

## Project Shape

- Source root: `source/`.
- Dev-time module entrypoint: `source/Get-EntraZTAssess.psm1`.
- Module manifest: `source/Get-EntraZTAssess.psd1`, with an explicit `FunctionsToExport` list.
- Generated build output: `output/`; do not hand-edit it.
- Assessment checks are declarative data in `source/Checks/**/*.psd1`.
- Thresholds, weights, retry behavior, redaction, module metadata, and read-only Graph scopes live under `source/Settings/`.
- Public exported commands live in `source/Public/`; private collectors, assessors, scoring, Graph wrappers, and logging helpers live in `source/Private/`.
- Private files may include small wrapper helpers when needed for Pester mockability.

## Commands

```powershell
./build.ps1 -ResolveDependency -tasks build
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -tasks build
./build.ps1 -tasks test
Invoke-Pester -Path tests
Invoke-ScriptAnalyzer -Path source/ -Recurse
./build.ps1 -tasks pack
```

Run ScriptAnalyzer after changing `.ps1` or `.psm1` files. After code changes, run the full test suite, not only adjacent tests.

## Read-Only Rules

This toolkit assesses tenant configuration. Do not add Microsoft Graph write operations, write scopes, background telemetry, or production side effects without explicit approval and matching documentation.

Route Graph reads through `Invoke-ZTAssessGraphRequest` / `Invoke-MgGraphRequestWrapper` so paging, retries, logging, and read-only guardrails stay consistent. Preserve the degraded-mode behavior in `Invoke-ZTAssessCoreCollection` when user collection without `signInActivity` is required.

Use `Write-ToLog` for module logging. It handles file logging, rotation, redaction, and stream mapping.

`tests/QA/ReadOnly.tests.ps1` enforces read-only constraints, including no direct `Invoke-MgGraphRequest`, no write HTTP verbs, no `Invoke-Expression`, no hardcoded secrets, and no Graph write scopes.

## Testing Patterns

Pester tests use v5 patterns and normally import `source/Get-EntraZTAssess.psd1`. Use `Invoke-Pester -Path tests` locally so generated dependency tests under `output/RequiredModules` are not discovered. Unit tests mirror source under `tests/Unit/Public`, `tests/Unit/Private`, and `tests/Unit/Classes`.

Use `tests/Fixtures/FixtureHelper.ps1` helpers such as `New-ZTAssessTestRun`; use `TestDrive` for filesystem writes. Mock `Write-ToLog` in unit tests unless the logger itself is under test. Private tests use `InModuleScope` and wrapper helpers instead of reaching directly into external services.

QA tests validate exported-function help, ScriptAnalyzer, changelog quality, matching unit tests for exported functions, and read-only security rules. The Sampler test task includes the 85% coverage gate from `build.yaml`.

## Documentation Discipline

Keep docs repo-specific and concise. Remove old template examples and generic Sampler-module setup guidance unless they are directly relevant to this repository.

**Mandatory:** every change must keep the documentation in sync in the same branch and commit series: `CHANGELOG.md` (QA-enforced `Unreleased` entry), `CLAUDE.md` (build status, architecture rules, assumptions), `AGENTS.md` (boundaries, security rules, testing patterns), this file, and `README.md` when exported commands or behaviour change. Record new design assumptions where they are made rather than leaving them implicit in code. A change is not complete until the .md files describe the repository as it now is.
