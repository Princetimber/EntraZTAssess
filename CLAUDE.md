# CLAUDE.md

Project context for Claude Code and AI agents.

## Project Overview

**Get-EntraZTAssess** — the *Entra ID Security & Endpoint Zero Trust Assessment* toolkit. A read-only, consultancy-grade PowerShell module (built with the **Sampler** framework) that collects Microsoft Entra ID and Intune configuration via Microsoft Graph, assesses it against a declarative check library, scores maturity and risk, and persists evidence for local report generation.

Build status: **Phase 4 reporting MVP present.** Implemented public modules: Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring (92 checks across 14 domains). Reporting currently exports local HTML executive/technical reports plus JSON/CSV risk register and JSON remediation roadmap under each run's `Reports` folder. Remaining roadmap: richer report packaging such as PDF/Excel/dashboard outputs, then Phase 5 hardening/signing/runbook. The authoritative build specification is the *Master Build Specification* document kept with the engagement records.
Public module names stay user-facing; internal check/settings domains map `Applications` to `ApplicationSecurity` and `Monitoring` to `MonitoringDetection`.

### Consultant workflow

```powershell
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring
$eng = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-042' -OutputPath ~/Assessments
$run = Invoke-ZTAssessment -EngagementPath $eng.EngagementPath
Get-ZTAssessScore -RunPath $run.RunPath
Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail | Format-Table CheckId, Severity, Title
Export-ZTAssessReport -RunPath $run.RunPath
Disconnect-ZTAssessment
```

## PowerShell Development Standards

- Always run `Invoke-ScriptAnalyzer` after modifying any `.ps1` or `.psm1` files and fix all warnings before committing.
- Use `Write-ToLog` (not `Write-Log`) as the standard logging function across all modules.
- All tests must be cross-platform compatible (macOS and Windows). Avoid Windows-only cmdlets without mocking, hardcoded Windows paths, or reliance on Windows-specific environment variables.

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

```
Get-EntraZTAssess/
├── source/
│   ├── Get-EntraZTAssess.psd1    # Module manifest (FunctionsToExport kept explicit)
│   ├── Get-EntraZTAssess.psm1    # Dev loader: dot-sources Classes/, Private/, Public/
│   ├── Classes/                  # ZTAssessFinding, ZTAssessPlatformProfile, ZTAssessRunManifest
│   ├── Checks/<Domain>/<Id>.psd1 # Declarative check library (92 checks across 14 domains)
│   ├── Settings/                 # settings.psd1 (thresholds/weights), permissions.psd1 (module→scope map)
│   ├── Public/                   # Exported cmdlets (one per file, ZTAssess noun prefix)
│   ├── Private/                  # Collectors (Invoke-ZTAssess*Collection), assessors (Test-ZTAssess*),
│   │                             # scoring (Measure-ZTAssessScore), Graph helpers, mockable SDK wrappers
│   └── en-US/                    # Help files
├── tests/
│   ├── QA/                       # module.tests.ps1 (exported functions only) + ReadOnly.tests.ps1 gate
│   ├── Fixtures/FixtureHelper.ps1 # Well-configured tenant fixture (all-Pass baseline)
│   └── Unit/                     # Public/, Private/, Classes/ mirror source
├── build.ps1
├── build.yaml                    # CopyPaths must include Settings and Checks
└── RequiredModules.psd1          # NuGet version ranges (requires ModuleFast, enabled)
```

### Architecture rules (do not break these)

- **Layering is strict**: collectors only fetch and persist redacted JSON snapshots to `<Run>/Raw/`; assessors are pure functions over snapshots on disk (no network); scoring consumes findings only. This enables offline re-analysis and fixture-based testing.
- **Read-only guarantee**: all Graph traffic flows through `Invoke-ZTAssessGraphRequest` → `Invoke-MgGraphRequestWrapper`, which only permits GET (`ValidateSet`). `tests/QA/ReadOnly.tests.ps1` statically enforces this plus no write scopes in the permission catalogue and no `Invoke-Expression`. Never bypass the wrapper.
- **Checks are declarative**: one PSD1 per check under `source/Checks/<Domain>/`. Adding a check = new PSD1 + logic in the domain assessor + fixture coverage. Findings are created only via `New-ZTAssessFinding`, which merges check metadata; `NotAssessed` always requires a reason.
- **Graceful degradation**: missing permission/licence/snapshot ⇒ `NotAssessed` finding with reason, never an error. Collector failures warn and continue. Snapshot by-id lookups must skip malformed records with null or blank IDs rather than throwing.
- **Graph SDK calls are wrapped** (`Connect-MgGraphWrapper`, `Get-MgContextWrapper`, etc.) so unit tests never need a live tenant or the SDK installed.
- **Beta endpoints** are isolated in collectors with a `(beta)` comment and must degrade to `NotAssessed` if Microsoft changes them.
- **Reporting is local-only**: `Export-ZTAssessReport` consumes persisted run artifacts and writes `ExecutiveReport.html`, `TechnicalReport.html`, `RiskRegister.json`, `RiskRegister.csv`, and `RemediationRoadmap.json` beneath `<Run>/Reports`. It makes no Graph calls. Risk-register and roadmap rows include only Fail/Partial findings and use `Settings/settings.psd1` `RemediationSlaDays` (Critical 7, High 30, Medium 90, Low 180).

## Common Commands

```powershell
# First build (resolves dependencies)
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

## CI/CD

- **GitHub Actions** (`.github/workflows/ci.yml` and `release.yml`)
  - CI: Runs on push to main and PRs
  - Matrix testing: Linux, Windows, macOS
  - Release: Publishes to PSGallery and GitHub Releases on tag `v*`

- **Azure Pipelines** (`azure-pipelines.yml`)
  - Stages: Build → Test (multi-platform: Linux, Windows PS7, macOS) → Code Coverage → Deploy
  - Deploy publishes to PSGallery and GitHub Releases on `main` branch

## AI Agent Operating Principles

- Make the smallest safe change that achieves the goal
- Prefer extending existing patterns over introducing new architecture
- Maintain security-first defaults at all times
- Never introduce secrets, tokens, or credentials into code or tests
- Avoid collecting, logging, or exporting sensitive data by default

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
