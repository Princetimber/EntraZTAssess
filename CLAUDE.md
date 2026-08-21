# CLAUDE.md

Project context for Claude Code and AI agents.

## Project Overview

**Get-EntraZTAssess** — the *Entra ID Security & Endpoint Zero Trust Assessment* toolkit. A read-only, consultancy-grade PowerShell module (built with the **Sampler** framework) that collects Microsoft Entra ID and Intune configuration via Microsoft Graph, assesses it against a declarative check library, scores maturity and risk, and persists evidence for local report generation.

Build status: **Phase 5 delivery hardening present.** All 14 planned assessment modules implemented: Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring, Defender, ThreatProtection, SecurityCompliance, DataProtection, Collaboration, CloudAppSecurity (115 checks across 20 domains). ThreatProtection, SecurityCompliance, DataProtection, and Collaboration are built on the read-only Exchange Online / Security & Compliance (IPPS) connection surface (see the Authentication rule below). Collaboration's v1 scope deliberately excludes SharePoint tenant sharing settings (`Get-SPOTenant`), which would require a third connection surface (`Connect-SPOService`) this module does not establish. CloudAppSecurity is Graph-only, shares its collected data with Defender (no separate collector), and is explicitly a best-effort Microsoft Secure Score proxy — Microsoft Graph exposes no Defender for Cloud Apps configuration API, so it does not assess MCAS policies, app risk scores, or OAuth app governance; its own check metadata (CAS-003) documents this limitation. Reporting exports local HTML executive/technical reports plus JSON/CSV risk register and JSON remediation roadmap under each run's `Reports` folder, with optional `Export-ZTAssessReport -RedactUserIdentifiers` output redaction for client-safe copies. Consultant runbook, permissions guidance, manifest metadata polish, and CI ScriptAnalyzer pinning are present. Remaining roadmap: richer report packaging such as PDF/Excel/dashboard outputs and signing if required. The authoritative build specification is the *Master Build Specification* document kept with the engagement records.
Public module names stay user-facing; internal check/settings domains map `Applications` to `ApplicationSecurity` and `Monitoring` to `MonitoringDetection`. `Defender` and `CloudAppSecurity` use the same name for both. Defender's device-onboarding check (DF-002) and CloudAppSecurity's setup check (CAS-001) are best-effort proxies derived from the tenant's Secure Score control contribution — Microsoft Graph exposes no direct "onboarded machines" list for Defender for Endpoint, nor any Defender for Cloud Apps configuration API — and both degrade to `NotAssessed` if Microsoft renames or retires the underlying secure score control (candidate names are configurable via `Settings/settings.psd1` → `Defender.OnboardingControlNames` and `CloudAppSecurity.SetupControlNames`).

### Consultant workflow

```powershell
# Auth defaults to certificate-based app-only (CBA); config auto-resolves from
# explicit params -> env vars -> ~/.ztassess/auth.json, else interactive fallback.
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring, Defender
$eng = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-042' -OutputPath ~/Assessments
$run = Invoke-ZTAssessment -EngagementPath $eng.EngagementPath
Get-ZTAssessScore -RunPath $run.RunPath
Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail | Format-Table CheckId, Severity, Title
Export-ZTAssessReport -RunPath $run.RunPath
# For client-distribution copies that should suppress user identifiers:
Export-ZTAssessReport -RunPath $run.RunPath -RedactUserIdentifiers
Disconnect-ZTAssessment
```

## PowerShell Development Standards

- Always run `Invoke-ScriptAnalyzer` after modifying any `.ps1` or `.psm1` files and fix all warnings before committing.
- Use `Write-ToLog` (not `Write-Log`) as the standard logging function across all modules.
- All tests must be cross-platform compatible (macOS and Windows). Avoid Windows-only cmdlets without mocking, hardcoded Windows paths, or reliance on Windows-specific environment variables.
- Never use `-Skip:$IsWindows` (or `-Skip:(-not $IsWindows)`) to gate platform-conditional tests. Instead, extract the platform-specific call into a private helper function and mock it with `Mock -ModuleName` so the test runs everywhere.

## Git & PR Workflow

- When asked to fix and commit, always: (1) make fixes, (2) run all tests, (3) run ScriptAnalyzer, (4) commit to a feature branch, (5) create PR, (6) merge PR, (7) clean up branch.
- Before deleting a branch, ensure HEAD is not checked out on that branch (switch to main first).
- Perform file writes sequentially, not in parallel, to avoid cascade failures.

## Testing

- Always run the full project test suite (`Invoke-Pester -Path tests`) after any code changes, not just the tests for modified files.
- Use project-scoped Pester locally once dependencies have been restored; bare `Invoke-Pester` can discover third-party tests under generated `output/RequiredModules`.
- When tests fail, fix and re-run iteratively until all pass before committing.
- Mock Windows-only cmdlets (e.g., `Get-Service`, `Get-EventLog`) when writing tests that need to run cross-platform.

## Module Structure (Sampler Layout)

### Architecture rules (do not break these)

- **Layering is strict**: collectors only fetch and persist redacted JSON snapshots to `<Run>/Raw/`; assessors are pure functions over snapshots on disk (no network); scoring consumes findings only. This enables offline re-analysis and fixture-based testing.
- **Read-only guarantee**: all Graph traffic flows through `Invoke-ZTAssessGraphRequest` → `Invoke-MgGraphRequestWrapper`, which only permits GET (`ValidateSet`). `tests/QA/ReadOnly.tests.ps1` statically enforces this plus no write scopes in the permission catalogue, no Graph write SDK cmdlets (`New-Mg*`/`Set-Mg*`/`Remove-Mg*`/`Update-Mg*`) under `source/`, and no `Invoke-Expression`. Never bypass the wrapper. The read-only guarantee is unchanged by CBA: the only Graph *write* operations in the repository (app registration and app-role grants) live in the repo-local `EntraZTAssess.Provisioning` module under `scripts/`, outside `source/`, and are run once by an administrator.
- **Authentication defaults to CBA**: `Connect-ZTAssessment` uses certificate-based, app-only authentication by default, with automatic fallback to interactive delegated sign-in when no CBA configuration is found. CBA config resolves from explicit params (`-TenantId`, `-ClientId`, `-CertificateThumbprint`, `-CertificatePath`, `-CertificatePassword`, `-Environment`, `-Organization`) → env vars (`ZTASSESS_TENANTID`, `ZTASSESS_CLIENTID`, `ZTASSESS_CERT_THUMBPRINT`, `ZTASSESS_CERT_PATH`, `ZTASSESS_ENVIRONMENT`, `ZTASSESS_ORGANIZATION`) → the non-secret `~/.ztassess/auth.json` (never stores the certificate password). If config is present but the connection fails, the error surfaces (no silent fallback); `-NoInteractiveFallback` forces a hard failure for headless/CI. macOS/Linux use a password-protected PFX (`-CertificatePath`/`-CertificatePassword`); the store thumbprint path is Windows-only. Parameter sets: `Auto` (default), `AppOnlyThumbprint`, `AppOnlyCertificate`, `Delegated`. Provisioning is the `EntraZTAssess.Provisioning` module (functions `New-ZTAssessCertificate`, `New-ZTAssessAppRegistration`, `Get-ZTAssessExchangeOnlineRoleGuidance`, `Grant-ZTAssessExchangeOnlineRole`), published as its own separately versioned PSGallery package (`Install-Module EntraZTAssess.Provisioning`) rather than bundled with `Get-EntraZTAssess`, so the read-only assessment module never carries write-capable code; its source also lives under `scripts/EntraZTAssess.Provisioning` in this repository for anyone who wants to clone and import it directly instead. The read-only `Get-ZTAssessProvisioningStep` core cmdlet lists the steps. Provisioning-function tests live under `tests/Unit/Provisioning/`. See `docs/Authentication.md`. The provisioning module has a `Private/` folder (dot-sourced by the `.psm1` but not exported) for helpers that make platform-conditional code mockable in tests: `Test-ZTAssessIsWindowsPlatform` wraps `$IsWindows`; `Invoke-ZTAssessSetUnixFileMode` wraps `[System.IO.File]::SetUnixFileMode`. Any new platform-conditional code in provisioning functions must follow this pattern so tests can mock the helper with `Mock -ModuleName` rather than skipping on one OS. It also carries its own bundled copy of the permission catalogue at `scripts/EntraZTAssess.Provisioning/Settings/permissions.psd1` (declared in the manifest `FileList`), kept in sync with `source/Settings/permissions.psd1` and asserted by `tests/Unit/Provisioning/PermissionCatalogueBundling.tests.ps1` — `New-ZTAssessAppRegistration` resolves it relative to its own module root (`$PSScriptRoot/../Settings/permissions.psd1`), not the wider repo, so it works from a PSGallery install where no sibling `source/` folder exists.
- **Exchange Online / Security & Compliance (IPPS) is a second, lazy, read-only connection surface**: some module data (Purview DLP/retention/label policies, Exchange sharing/transport rules, Defender for Office 365 policies) does not exist in Microsoft Graph. `Connect-ZTAssessment` establishes this connection only when a selected module's `Get-ZTAssessModuleCatalog` entry has `RequiresExchangeOnline = $true` (`SecurityCompliance`, `Collaboration`, `DataProtection`, `ThreatProtection`), using one of two auth modes: in app-only mode it's certificate-based, reusing the same certificate as Graph; in device-code mode (`-UseDeviceCode`) it obtains a separate Exchange Online access token via a manual OAuth device-code flow (`Get-ZTAssessExchangeOnlineDeviceCodeToken`, plain `Invoke-RestMethod` calls, no new dependency) — needed because the Security & Compliance session-establishing cmdlet has no device-code switch of its own — and passes that token to both surfaces via `-AccessToken`. The default device-code client ID (`Settings/settings.psd1` → `ExchangeOnline.DeviceCodeClientId`) is the well-known Microsoft first-party "Microsoft Exchange REST API Based PowerShell" public client already used internally by the ExchangeOnlineManagement module's own device-code switch, so no new app registration or permission grant is needed; it's overridable for tenants whose Conditional Access policy blocks well-known native client IDs. It remains unavailable for plain interactive delegated sign-in and never fails the overall connection; a failure or skip is reported via `ExchangeOnlineConnected`/`ExchangeOnlineWarning` on the connection summary and degrades dependent checks to `NotAssessed`. All calls flow through `Invoke-ZTAssessExoRequestWrapper`, which only permits the `Get-*` cmdlets in `Get-ZTAssessExoAllowedCmdletName`; the session itself is scoped to that same allow-list via `-CommandName`. `tests/QA/ReadOnly.tests.ps1` statically enforces both. The **read-only assessment module never grants** the Exchange Online role groups a module needs — `Get-ZTAssessExchangeOnlineRoleGuidance` documents them for the tenant's own Exchange administrator to grant manually. As an admin-run alternative to that manual step, `Grant-ZTAssessExchangeOnlineRole` (in the separately published `EntraZTAssess.Provisioning` package, alongside `New-ZTAssessAppRegistration`) can perform the Exchange Online RBAC role-group grant itself when run by an account with sufficient Exchange Online / Security & Compliance rights; like the rest of that provisioning module it lives outside `source/` because it performs writes. The four modules above currently only exercise this connection surface; their checks/collectors/assessors ship in follow-up phases.
- **Checks are declarative**: one PSD1 per check under `source/Checks/<Domain>/`. Adding a check = new PSD1 + logic in the domain assessor + fixture coverage. Findings are created only via `New-ZTAssessFinding`, which merges check metadata; `NotAssessed` always requires a reason.
- **Graceful degradation**: missing permission/licence/snapshot ⇒ `NotAssessed` finding with reason, never an error. Collector failures warn and continue. Snapshot by-id lookups must skip malformed records with null or blank IDs rather than throwing.
- **Graph SDK calls are wrapped** (`Connect-MgGraphWrapper`, `Get-MgContextWrapper`, etc.) so unit tests never need a live tenant or the SDK installed.
- **Beta endpoints** are isolated in collectors with a `(beta)` comment and must degrade to `NotAssessed` if Microsoft changes them.
- **Reporting is local-only**: `Export-ZTAssessReport` consumes persisted run artifacts and writes `ExecutiveReport.html`, `TechnicalReport.html`, `RiskRegister.json`, `RiskRegister.csv`, and `RemediationRoadmap.json` beneath `<Run>/Reports`. It makes no Graph calls. `-RedactUserIdentifiers` redacts generated report artifacts only and must not modify raw findings, snapshots, scores, or the run manifest. Risk-register and roadmap rows include only Fail/Partial findings and use `Settings/settings.psd1` `RemediationSlaDays` (Critical 7, High 30, Medium 90, Low 180).
- **Build packaging**: `build.yaml` `CopyPaths` must include `Settings` and `Checks` — these hold the declarative check library and thresholds; dropping them from `CopyPaths` silently ships a built module with no checks.

## Common Commands

```powershell
# Optional bootstrap guard: install RequiredModules.psd1 build modules if missing.
# Useful when dependency restore cannot fetch InvokeBuild, PSScriptAnalyzer,
# or other build modules before InvokeBuild is restored.
./Install-BuildDependency.ps1

# First build (resolves dependencies).
# Uses ModuleFast by default; automatically falls back to PSResourceGet if
# pwsh.gallery:443 is unreachable (e.g. on corporate Windows networks).
./build.ps1 -ResolveDependency -tasks build

# Subsequent builds
./build.ps1 -tasks build

# Run tests
./build.ps1 -tasks test
# or directly against project tests:
Invoke-Pester -Path tests

# Lint
Invoke-ScriptAnalyzer -Path source/ -Recurse

# Package
./build.ps1 -tasks pack
```

## Coding Conventions

- **One function per file**, filename matches function name exactly (e.g., `Get-Greeting.ps1`)
- **Advanced functions**: always use `[CmdletBinding()]`
- **SupportsShouldProcess**: required for state-changing operations only (Set-, New-, Remove-, Export-). Never on read-only functions (Get-, Test-, Find-)
- **Comment-based help**: `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE` on all public functions
- **Input validation**: mandatory — use `ValidateSet`, `ValidatePattern`, `ValidateNotNullOrEmpty`
- **Error handling**: `try/catch/finally`, throw actionable errors, never swallow exceptions
- **Naming**: PascalCase for functions (approved Verb-Noun), PascalCase for parameters, camelCase for local variables
- **No hardcoded secrets** — use SecretManagement module or environment variables
- **Never use `Invoke-Expression`**
- **Graph API** (if applicable): handle throttling (429), transient retries (5xx) with backoff, and pagination (`@odata.nextLink`)

## Testing Conventions

- **Pester v5+** with `BeforeDiscovery`/`BeforeAll`/`Describe`/`It` structure
- Test file structure mirrors source structure
- Mock all external dependencies (Graph API, OS commands, etc.)
- QA tests validate: changelog format, ScriptAnalyzer compliance, help documentation quality
- **85% code coverage threshold** (configured in `build.yaml`)

## AI Agent Operating Principles

- Make the smallest safe change that achieves the goal
- Prefer extending existing patterns over introducing new architecture
- Maintain security-first defaults at all times
- Never introduce secrets, tokens, or credentials into code or tests
- Avoid collecting, logging, or exporting sensitive data by default

## AI Agent Iteration Limits

- Do at most 1 planning pass per user request before acting.
- Do at most 2 independent implementation attempts.
- Do at most 2 verification/fix cycles after edits.
- If the same failure appears twice, stop and ask for guidance.
- If 3 materially different approaches fail, stop editing immediately.
- Do not continue autonomous loops without explicit user approval.
- Before handing back, report the attempted approach, current state, blocker, and recommended next action.

## AI Agent Workflow Rules

1. **Discover**
   - Read `README.md`, existing module docs, and relevant scripts
   - Identify existing patterns for logging, error handling, auth, retries, and tests

2. **Plan**
   - State proposed approach and affected files
   - Identify required permissions/scopes if Graph/M365 changes are involved
   - Identify tests that should be added/updated

3. **Implement**
   - Follow PowerShell advanced function patterns
   - Use `SupportsShouldProcess` for change operations
   - Add safe input validation and clear error messages
   - Handle Graph throttling (429), transient failures (5xx), and pagination (if applicable)

4. **Validate**
   - Run lint and tests:
     - `Invoke-ScriptAnalyzer -Path source/ -Recurse`
     - `Invoke-Pester -Path tests`
   - If integration tests exist, they must be opt-in and clearly labeled

5. **Document**
   - Update help/examples when behavior changes
   - Document required Graph scopes/permissions and any operational caveats

## Documentation Maintenance (mandatory)

Every change to this module MUST keep the documentation in sync, in the same
branch and commit series as the change itself:

1. **CHANGELOG.md** — add an entry under `Unreleased` (the QA suite enforces this).
2. **CLAUDE.md** (this file) — update the build status, module structure,
   architecture rules, workflow examples, and assumptions whenever they change.
3. **AGENTS.md** — keep the universal agent context (boundaries, security rules,
   testing patterns) consistent with CLAUDE.md.
4. **.github/copilot-instructions.md** — keep the Copilot summary consistent.
5. **README.md** — update user-facing usage and capability descriptions when
   exported commands or behaviour change.

Record new design assumptions where they are made (for example licence
detection defaults, beta endpoint usage, threshold defaults) rather than
leaving them implicit in code. A change is not complete until the .md files
describe the repository as it now is.

## Prohibited Actions

- Do not add or request broad Graph scopes by default
- Do not use `Invoke-Expression` or unsafe string execution
- Do not assume the agent has access to live systems or production environments
- Do not add telemetry, background network calls, or external dependencies without explicit documentation

## Output Expectations

- Produce review-ready PowerShell: readable, testable, idempotent
- Keep changes minimal; avoid drive-by refactors
- If requirements are unclear, ask concise clarifying questions rather than guessing

## Further Reference

- `.github/copilot-instructions.md` — GitHub Copilot-specific instructions
