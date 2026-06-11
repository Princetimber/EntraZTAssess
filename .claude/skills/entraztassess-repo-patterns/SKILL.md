---
name: entraztassess-repo-patterns
description: Use this skill when working in the EntraZTAssess repository to follow its PowerShell 7+ Sampler module structure, read-only Microsoft Graph security model, Pester testing conventions, and mandatory documentation maintenance workflow.
---

# EntraZTAssess Repository Patterns

Use this skill when adding, fixing, reviewing, or documenting code in the Get-EntraZTAssess repository. The repository is a PowerShell 7+ Sampler module for read-only Microsoft Entra ID and Intune Zero Trust assessment, not a generic Sampler template.

## Repository Shape

- Treat `source/` as the source of truth. Do not hand-edit generated artifacts under `output/`.
- Public commands live in `source/Public/`; keep one exported function per file with comment-based help.
- Private implementation lives in `source/Private/`; keep Graph, collection, scoring, finding, snapshot, report, and logging helpers there.
- Classes live in `source/Classes/`.
- Assessment checks are data-driven under `source/Checks/**/*.psd1`; settings and permissions live under `source/Settings/settings.psd1` and `source/Settings/permissions.psd1`.
- Help lives under `source/en-US/`.
- Keep `source/Get-EntraZTAssess.psd1` `FunctionsToExport` synchronized with any new public command.

## Discovery Workflow

Before changing code, inspect the closest existing implementation and its tests. Common entry points are:

- `source/Public/Invoke-ZTAssessment.ps1` for orchestration patterns.
- `source/Public/Export-ZTAssessReport.ps1` and private report helpers for offline report generation.
- `source/Private/Invoke-ZTAssessGraphRequest.ps1` and `source/Private/Invoke-MgGraphRequestWrapper.ps1` for Graph read paths.
- `source/Private/Invoke-ZTAssessCollectionSet.ps1` and `source/Private/Invoke-ZTAssessCoreCollection.ps1` for collection behavior and degraded-mode patterns.
- `source/Settings/settings.psd1`, `source/Settings/permissions.psd1`, and nearby `source/Checks/**/*.psd1` files before adding hardcoded logic.

Prefer changing declarative check, settings, and permission data over procedural code when adding or tuning assessment logic.

## Source And Test Pairing

- Public command tests mirror `source/Public/` under `tests/Unit/Public/`.
- Private helper tests mirror `source/Private/` under `tests/Unit/Private/`.
- Class tests mirror `source/Classes/` under `tests/Unit/Classes/`.
- Use Pester v5 patterns: `BeforeDiscovery`, `BeforeAll`, `Describe`, and `It`.
- Use `InModuleScope` for private functions and wrapper helpers for mockability.
- Use `TestDrive` and `tests/Fixtures/FixtureHelper.ps1` helpers such as `New-ZTAssessTestRun` for filesystem tests.
- Mock `Write-ToLog` unless the logger itself is under test.
- Keep QA expectations in mind: `tests/QA/ReadOnly.tests.ps1` enforces read-only guardrails, and `tests/QA/module.tests.ps1` checks exported help, changelog quality, and exported-function tests.

## Read-Only Graph And Security Guardrails

This repository assesses tenant configuration. Preserve read-only behavior.

- Route Microsoft Graph collection through `Invoke-ZTAssessGraphRequest` or `Invoke-MgGraphRequestWrapper` so paging, retries, logging, and read-only checks remain centralized.
- Do not add Graph write methods such as `POST`, `PATCH`, `PUT`, or `DELETE`.
- Do not add Graph write scopes, `ReadWrite` permissions, tenant mutation, background telemetry, or hidden network calls.
- Do not call `Invoke-MgGraphRequest` directly from new assessment code.
- Do not use `Invoke-Expression` or hardcoded secrets.
- Preserve local-only report generation. `Export-ZTAssessReport` reads completed run artifacts and writes local reports; it must not require a Graph connection or make network calls.
- Preserve generated-report redaction semantics: redaction applies to report artifacts only, not raw findings, snapshots, scores, or manifests.

## Documentation Maintenance

Recent history shows documentation changes commonly travel with source and tests. When behavior, exported commands, checks, settings, permissions, or reporting changes, update the relevant docs in the same branch:

- `CHANGELOG.md` with an `[Unreleased]` entry.
- `CLAUDE.md` for build status, architecture rules, workflow examples, and assumptions.
- `AGENTS.md` for module boundaries, security rules, and testing patterns.
- `.github/copilot-instructions.md` for Copilot-facing guidance.
- `README.md` for user-facing usage when exported commands or behavior change.

Record assumptions such as endpoint choice, threshold defaults, license detection behavior, beta endpoint usage, and reporting limitations where they are made.

## Verification Commands

After `.ps1` or `.psm1` changes, run ScriptAnalyzer:

```powershell
Invoke-ScriptAnalyzer -Path source/ -Recurse
```

After code changes, run the full test suite from the repository root rather than discovering generated dependency tests under `output/`:

```powershell
Invoke-Pester -Path tests
```

Sampler build and test commands are:

```powershell
./build.ps1 -ResolveDependency -tasks build
./build.ps1 -tasks build
./build.ps1 -tasks test
./build.ps1 -tasks pack
```

The configured coverage threshold is 85 percent in `build.yaml`.

## Forbidden Actions

- Do not hand-edit `output/` generated artifacts.
- Do not run release or publish tasks unless explicitly asked: `publish_psgallery` and `publish_github` are release operations.
- Do not introduce tenant writes, write scopes, telemetry, broad scopes, or live-production assumptions.
- Do not add `SupportsShouldProcess` to read-only assessment/query functions just for style. Use it for local state-changing functions such as folder, log, or artifact writers.
- Do not weaken or delete QA tests to pass validation.

## Commit And History Conventions

The current branch history favors concise conventional-style subjects, especially `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, and `test:`. Match that style when commits are requested. Common co-change patterns are source plus tests, docs bundle updates, and check/settings updates.

A good commit subject for this artifact would be:

```text
docs: add EntraZTAssess repo-pattern skill
```
