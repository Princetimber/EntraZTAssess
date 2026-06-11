# Get-EntraZTAssess

**Entra ID Security & Endpoint Zero Trust Assessment** — a read-only, consultancy-grade PowerShell 7+ module built with the [Sampler](https://github.com/gaelcolas/Sampler) framework. It connects to Microsoft Graph, collects tenant configuration snapshots, evaluates them against a declarative check library (92 checks across 11 domains), scores maturity and risk, and writes local evidence artifacts for consultant reporting.

**Build status:** Phase 5 delivery hardening present. All 8 assessment modules implemented: Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring. Remaining roadmap: richer report packaging (PDF, Excel, dashboard outputs) if required.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Public Commands](#public-commands)
- [Usage Examples](#usage-examples)
- [Assessment Domains and Checks](#assessment-domains-and-checks)
- [Output Artifacts](#output-artifacts)
- [Module Structure](#module-structure)
- [Build and Test](#build-and-test)
- [Graph and Read-Only Guardrails](#graph-and-read-only-guardrails)
- [Testing Notes](#testing-notes)
- [CI and Release](#ci-and-release)
- [Further Reference](#further-reference)

---

## Requirements

- PowerShell 7.2 or later (cross-platform: Windows, macOS, Linux)
- [Microsoft.Graph](https://www.powershellgallery.com/packages/Microsoft.Graph) SDK — installed automatically via `RequiredModules.psd1`
- Delegated or app-only permissions as listed in [`docs/PermissionsGuidance.md`](docs/PermissionsGuidance.md)

---

## Installation

```powershell
# From PSGallery (once published)
Install-Module -Name Get-EntraZTAssess -Scope CurrentUser

# From source (development)
./build.ps1 -ResolveDependency -tasks build
Import-Module ./output/Get-EntraZTAssess/<version>/Get-EntraZTAssess.psd1
```

---

## Quick Start

```powershell
# 1. Connect to Microsoft Graph with required scopes
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, `
    IdentityGovernance, Applications, HybridIdentity, Monitoring

# 2. Create an engagement folder scaffold
$eng = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' `
    -Reference 'ENG-2026-042' -OutputPath ~/Assessments

# 3. Run the full assessment
$run = Invoke-ZTAssessment -EngagementPath $eng.EngagementPath

# 4. Review scores and findings
Get-ZTAssessScore -RunPath $run.RunPath
Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail | Format-Table CheckId, Severity, Title

# 5. Export reports
Export-ZTAssessReport -RunPath $run.RunPath

# 6. Disconnect
Disconnect-ZTAssessment
```

---

## Public Commands

The module manifest explicitly exports these nine functions:

| Command | Purpose |
|---|---|
| `Connect-ZTAssessment` | Authenticate to Microsoft Graph with scopes for the selected modules |
| `Disconnect-ZTAssessment` | Disconnect the active Graph session |
| `New-ZTAssessEngagement` | Create the local engagement folder scaffold |
| `Invoke-ZTAssessment` | Orchestrate collection, assessment, scoring, and artifact writes |
| `Get-ZTAssessScore` | Retrieve aggregated maturity/risk scores from a completed run |
| `Get-ZTAssessFinding` | Query findings from a completed run, with optional status/severity filters |
| `Export-ZTAssessReport` | Generate local HTML, JSON, and CSV report artifacts from a run |
| `Get-ZTAssessModuleCatalog` | List available assessment modules and their metadata |
| `Get-ZTAssessRequiredPermission` | List the Graph scopes required for a given set of modules |

---

## Usage Examples

### Connect with a subset of modules

```powershell
# Identity and Conditional Access only
Connect-ZTAssessment -Modules Identity, ConditionalAccess
```

### Review required Graph permissions before connecting

```powershell
# See which scopes each module needs before requesting consent
Get-ZTAssessRequiredPermission -Modules PrivilegedAccess, Devices
```

### List available assessment modules

```powershell
# View all modules, their domain mappings, and check counts
Get-ZTAssessModuleCatalog
```

### Create an engagement

```powershell
# Creates ~/Assessments/Contoso_Ltd/ENG-2026-042/ with timestamped run folder
$eng = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' `
    -Reference 'ENG-2026-042' -OutputPath ~/Assessments

$eng.EngagementPath   # ~/Assessments/Contoso_Ltd/ENG-2026-042
```

### Run assessment with specific modules

```powershell
# Run only Identity and PrivilegedAccess checks
$run = Invoke-ZTAssessment -EngagementPath $eng.EngagementPath `
    -Modules Identity, PrivilegedAccess

$run.RunPath   # path to the timestamped run folder
```

### Score the run

```powershell
# Overall maturity score and per-domain breakdown
Get-ZTAssessScore -RunPath $run.RunPath

# Example output:
# Overall : 62 / 100  (Maturity: Developing)
# Domain                  Score  Pass  Fail  Partial  NotAssessed
# IdentitySecurity          71    8     2     2         0
# ConditionalAccess         54    7     6     0         0
# PrivilegedAccess          60    6     4     0         0
# ...
```

### Filter and inspect findings

```powershell
# All failed checks
Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail

# Critical findings only
Get-ZTAssessFinding -RunPath $run.RunPath -Severity Critical

# Failed and partial findings as a table
Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail, Partial |
    Format-Table CheckId, Severity, Title, Recommendation -Wrap

# Findings for a specific domain
Get-ZTAssessFinding -RunPath $run.RunPath -Domain ConditionalAccess |
    Sort-Object Severity | Format-List
```

### Export reports

```powershell
# Standard export — writes to <RunPath>/Reports/
Export-ZTAssessReport -RunPath $run.RunPath

# Client-safe copy with user identifiers suppressed
Export-ZTAssessReport -RunPath $run.RunPath -RedactUserIdentifiers
```

Reports written under `<RunPath>/Reports/`:

| File | Description |
|---|---|
| `ExecutiveReport.html` | One-page executive summary with risk scores and key findings |
| `TechnicalReport.html` | Full per-check technical report including NotAssessed findings |
| `RiskRegister.json` | Fail/Partial findings with SLA deadlines (machine-readable) |
| `RiskRegister.csv` | Same risk register in CSV format for spreadsheet import |
| `RemediationRoadmap.json` | Prioritised remediation plan ordered by severity and SLA |

`Export-ZTAssessReport` is fully offline — it reads persisted run artifacts and makes no Graph calls.

### Disconnect

```powershell
Disconnect-ZTAssessment
```

---

## Assessment Domains and Checks

The assessment library is data-driven. Each check is a declarative `.psd1` file under `source/Checks/<Domain>/`. The table below shows the public module name, the internal check domain, and the number of checks.

| Public Module | Internal Domain | Checks |
|---|---|---|
| Identity | IdentitySecurity | 12 |
| ConditionalAccess | ConditionalAccess | 13 |
| PrivilegedAccess | PrivilegedAccess | 10 |
| Devices | DeviceTrust | 4 |
| Devices | EndpointManagement | 21 |
| Devices | ByodGovernance | 4 |
| Devices | CorporateDeviceGovernance | 3 |
| IdentityGovernance | IdentityGovernance | 6 |
| Applications | ApplicationSecurity | 7 |
| HybridIdentity | HybridIdentity | 6 |
| Monitoring | MonitoringDetection | 6 |
| **Total** | | **92** |

`source/Settings/settings.psd1` defines thresholds, scoring weights, retry behaviour, and remediation SLA days (Critical: 7, High: 30, Medium: 90, Low: 180).

`source/Settings/permissions.psd1` defines the read-only Graph scopes required per module.

---

## Output Artifacts

`Invoke-ZTAssessment` writes under `<EngagementPath>/<RunTimestamp>/`:

```text
<RunTimestamp>/
  Raw/                     # Redacted JSON snapshots from Graph (one per collector)
  Findings.json            # All ZTAssessFinding objects
  Score.json               # Aggregated maturity and risk scores
  RunManifest.json         # Run metadata: modules, timing, tenant info
  Reports/                 # Populated by Export-ZTAssessReport
    ExecutiveReport.html
    TechnicalReport.html
    RiskRegister.json
    RiskRegister.csv
    RemediationRoadmap.json
```

Raw snapshots are written first; assessors then run purely over disk — no additional Graph calls. This enables offline re-analysis and fixture-based testing.

---

## Module Structure

```text
Get-EntraZTAssess/
├── source/
│   ├── Get-EntraZTAssess.psd1          # Module manifest — explicit FunctionsToExport
│   ├── Get-EntraZTAssess.psm1          # Dev loader: dot-sources Classes/, Private/, Public/
│   │
│   ├── Classes/
│   │   ├── 01.ZTAssessFinding.ps1      # Finding DTO
│   │   ├── 02.ZTAssessPlatformProfile.ps1
│   │   └── 03.ZTAssessRunManifest.ps1
│   │
│   ├── Public/                         # Exported cmdlets — one file per function
│   │   ├── Connect-ZTAssessment.ps1
│   │   ├── Disconnect-ZTAssessment.ps1
│   │   ├── Export-ZTAssessReport.ps1
│   │   ├── Get-ZTAssessFinding.ps1
│   │   ├── Get-ZTAssessModuleCatalog.ps1
│   │   ├── Get-ZTAssessRequiredPermission.ps1
│   │   ├── Get-ZTAssessScore.ps1
│   │   ├── Invoke-ZTAssessment.ps1
│   │   └── New-ZTAssessEngagement.ps1
│   │
│   ├── Private/
│   │   ├── Collectors/                 # Invoke-ZTAssess*Collection.ps1 — fetch & persist snapshots
│   │   │   ├── Invoke-ZTAssessApplicationCollection.ps1
│   │   │   ├── Invoke-ZTAssessCollectionSet.ps1
│   │   │   ├── Invoke-ZTAssessConditionalAccessCollection.ps1
│   │   │   ├── Invoke-ZTAssessCoreCollection.ps1
│   │   │   ├── Invoke-ZTAssessDeviceCollection.ps1
│   │   │   ├── Invoke-ZTAssessGovernanceCollection.ps1
│   │   │   ├── Invoke-ZTAssessHybridCollection.ps1
│   │   │   ├── Invoke-ZTAssessIdentityCollection.ps1
│   │   │   ├── Invoke-ZTAssessMonitoringCollection.ps1
│   │   │   └── Invoke-ZTAssessPrivilegedAccessCollection.ps1
│   │   ├── Assessors/                  # Test-ZTAssess*.ps1 — pure functions over snapshots
│   │   │   ├── Test-ZTAssessApplicationSecurity.ps1
│   │   │   ├── Test-ZTAssessByodGovernance.ps1
│   │   │   ├── Test-ZTAssessConditionalAccess.ps1
│   │   │   ├── Test-ZTAssessCorporateGovernance.ps1
│   │   │   ├── Test-ZTAssessDeviceTrust.ps1
│   │   │   ├── Test-ZTAssessEndpointManagement.ps1
│   │   │   ├── Test-ZTAssessHybridIdentity.ps1
│   │   │   ├── Test-ZTAssessIdentityGovernance.ps1
│   │   │   ├── Test-ZTAssessIdentitySecurity.ps1
│   │   │   ├── Test-ZTAssessMonitoring.ps1
│   │   │   └── Test-ZTAssessPrivilegedAccess.ps1
│   │   ├── Graph helpers
│   │   │   ├── Invoke-ZTAssessGraphRequest.ps1   # Central Graph wrapper (GET only)
│   │   │   ├── Invoke-MgGraphRequestWrapper.ps1
│   │   │   ├── Connect-MgGraphWrapper.ps1
│   │   │   ├── Disconnect-MgGraphWrapper.ps1
│   │   │   └── Get-MgContextWrapper.ps1
│   │   ├── Scoring
│   │   │   └── Measure-ZTAssessScore.ps1
│   │   ├── Reporting
│   │   │   ├── ConvertTo-ZTAssessExecutiveHtml.ps1
│   │   │   ├── ConvertTo-ZTAssessTechnicalHtml.ps1
│   │   │   ├── ConvertTo-ZTAssessHtmlDocument.ps1
│   │   │   ├── Get-ZTAssessRiskRegister.ps1
│   │   │   └── Get-ZTAssessRemediationRoadmap.ps1
│   │   └── Helpers
│   │       ├── Get-ZTAssessCheckDefinition.ps1
│   │       ├── Get-ZTAssessConfiguration.ps1
│   │       ├── Get-ZTAssessDeviceClass.ps1
│   │       ├── Get-ZTAssessHttpStatusCode.ps1
│   │       ├── Get-ZTAssessPlatformProfile.ps1
│   │       ├── Get-ZTAssessReportContext.ps1
│   │       ├── Get-ZTAssessRetryDelay.ps1
│   │       ├── Get-ZTAssessSnapshot.ps1
│   │       ├── New-ZTAssessFinding.ps1
│   │       ├── New-ZTAssessRunManifest.ps1
│   │       ├── Protect-ZTAssessData.ps1
│   │       ├── Protect-ZTAssessReportUserIdentifier.ps1
│   │       ├── Save-ZTAssessRunManifest.ps1
│   │       ├── Save-ZTAssessSnapshot.ps1
│   │       ├── Write-ToLog.ps1
│   │       ├── Get-LogFilePath.ps1
│   │       ├── Set-LogFilePath.ps1
│   │       ├── Invoke-LogRotation.ps1
│   │       └── Start-SleepWrapper.ps1
│   │
│   ├── Checks/                         # Declarative check library — one .psd1 per check
│   │   ├── ApplicationSecurity/        #  7 checks
│   │   ├── ByodGovernance/             #  4 checks
│   │   ├── ConditionalAccess/          # 13 checks
│   │   ├── CorporateDeviceGovernance/  #  3 checks
│   │   ├── DeviceTrust/               #  4 checks
│   │   ├── EndpointManagement/         # 21 checks
│   │   ├── HybridIdentity/             #  6 checks
│   │   ├── IdentityGovernance/         #  6 checks
│   │   ├── IdentitySecurity/           # 12 checks
│   │   ├── MonitoringDetection/        #  6 checks
│   │   └── PrivilegedAccess/           # 10 checks
│   │
│   ├── Settings/
│   │   ├── settings.psd1              # Thresholds, weights, SLA days, retry config
│   │   └── permissions.psd1           # Module → read-only Graph scope map
│   │
│   └── en-US/                         # External help (MAML)
│
├── tests/
│   ├── Fixtures/
│   │   └── FixtureHelper.ps1          # New-ZTAssessTestRun and all-Pass baseline fixture
│   ├── Unit/
│   │   ├── Public/                    # One test file per public function
│   │   ├── Private/                   # Collector, assessor, scoring, helper tests
│   │   └── Classes/                   # ZTAssessFinding, RunManifest, PlatformProfile tests
│   └── QA/
│       ├── module.tests.ps1           # Exported function and manifest checks
│       └── ReadOnly.tests.ps1         # Static guard: no write verbs, no write scopes, no Invoke-Expression
│
├── docs/
│   ├── ConsultantRunbook.md           # Delivery workflow and QA checklist
│   └── PermissionsGuidance.md         # Graph scope review and least-privilege guidance
│
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Push/PR: build, lint, test (Linux + Windows + macOS)
│       └── release.yml                # Tag-driven: PSGallery + GitHub Releases
│
├── azure-pipelines.yml                # Azure Pipelines: Build → Test → Code Coverage → Deploy
├── build.ps1                          # Sampler build entry point
├── build.yaml                         # CopyPaths, CodeCoverageThreshold: 85
└── RequiredModules.psd1               # NuGet version ranges (ModuleFast enabled)
```

> **Architecture note:** Collectors only fetch and persist redacted JSON snapshots to `<Run>/Raw/`. Assessors are pure functions over those snapshots — no network access. Scoring consumes findings only. This layering enables full offline re-analysis and fixture-based unit testing without a live tenant.

---

## Build and Test

```powershell
# First build — resolves and installs all RequiredModules
./build.ps1 -ResolveDependency -tasks build

# If dependency bootstrap fails, restore explicitly first
./build.ps1 -ResolveDependency -Tasks noop

# Subsequent development builds
./build.ps1 -tasks build

# Run the full test suite (includes 85% coverage gate)
./build.ps1 -tasks test

# Run tests directly (use project-scoped Pester to avoid output/ discovery)
Invoke-Pester -Path tests

# Lint (fix all warnings before committing)
Invoke-ScriptAnalyzer -Path source/ -Recurse

# Package for distribution
./build.ps1 -tasks pack
```

`build.yaml` sets `CodeCoverageThreshold: 85` and copies `source/Checks`, `source/Settings`, and `source/en-US` into the built module under `output/`.

### Adding a new check

1. Create `source/Checks/<Domain>/<CheckId>.psd1` with the declarative check definition.
2. Add evaluation logic to the corresponding `Test-ZTAssess<Domain>.ps1` assessor.
3. Add fixture coverage in `tests/Fixtures/FixtureHelper.ps1` and a unit test under `tests/Unit/Private/`.
4. Run `Invoke-Pester -Path tests` and `Invoke-ScriptAnalyzer -Path source/ -Recurse` — fix all issues before committing.

---

## Graph and Read-Only Guardrails

This module is intentionally read-only. All Graph traffic flows through the central wrappers:

```text
Invoke-ZTAssessGraphRequest  →  Invoke-MgGraphRequestWrapper
```

These wrappers enforce GET-only via `ValidateSet`, handle paging (`@odata.nextLink`), implement retry/backoff for 429 and 5xx responses, and route logging through `Write-ToLog`.

`tests/QA/ReadOnly.tests.ps1` statically verifies:

- No direct calls to `Invoke-MgGraphRequest` (must use the wrappers)
- No HTTP write verbs (POST, PUT, PATCH, DELETE)
- No write scopes in `permissions.psd1`
- No `Invoke-Expression` anywhere in source

Do not bypass these wrappers. Do not add write operations, telemetry, or external dependencies without explicit documentation and matching test coverage.

---

## Testing Notes

Pester v5+ patterns are used throughout (`BeforeDiscovery`, `BeforeAll`, `Describe`, `It`). Tests import `source/Get-EntraZTAssess.psd1` directly, so `Invoke-Pester -Path tests` works without a prior build.

Key conventions:

- Unit tests mirror the source structure under `tests/Unit/Public`, `tests/Unit/Private`, `tests/Unit/Classes`.
- Use `New-ZTAssessTestRun` from `tests/Fixtures/FixtureHelper.ps1` to set up a well-configured all-Pass baseline run folder.
- Use `TestDrive:` for all filesystem writes in tests.
- Mock `Write-ToLog` unless the logger itself is under test.
- Mock Graph SDK wrappers (`Connect-MgGraphWrapper`, `Get-MgContextWrapper`, etc.) — unit tests never need a live tenant or the SDK installed.
- Mock Windows-only cmdlets (`Get-Service`, `Get-EventLog`) for cross-platform compatibility.
- Private functions under test use `InModuleScope Get-EntraZTAssess { }`.

QA tests (`tests/QA/`) check exported-function help completeness, ScriptAnalyzer compliance, changelog entry presence, and read-only security rules.

---

## CI and Release

| Pipeline | Trigger | Jobs |
|---|---|---|
| `.github/workflows/ci.yml` | Push to `main`, all PRs | Dependency restore → pack → PSGallery-ruleset lint → Pester (Linux, Windows, macOS) |
| `.github/workflows/release.yml` | Tag `v*` | Publish to PSGallery + GitHub Releases |
| `azure-pipelines.yml` | `main` branch | Build → Test (multi-platform) → Code Coverage → Deploy |

CI lint pins PSScriptAnalyzer to the workflow-specified version before invoking the PSGallery ruleset.

Release tasks should only be run intentionally:

```powershell
./build.ps1 -tasks publish_psgallery
./build.ps1 -tasks publish_github
```

---

## Further Reference

- [`docs/ConsultantRunbook.md`](docs/ConsultantRunbook.md) — full delivery workflow, pre-engagement checklist, and QA steps
- [`docs/PermissionsGuidance.md`](docs/PermissionsGuidance.md) — Graph scope review and least-privilege guidance for client consent
- `source/Settings/settings.psd1` — remediation SLA days, scoring weights, and thresholds
- `source/Settings/permissions.psd1` — complete module → scope mapping
