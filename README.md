# Get-EntraZTAssess

Get-EntraZTAssess is a PowerShell 7+ Sampler module for read-only Microsoft Entra ID and Intune Zero Trust assessment. It connects to Microsoft Graph, collects tenant configuration snapshots, evaluates them against a declarative check library, scores maturity and risk, and writes local evidence artifacts for consultant reporting.

Treat this repository as a security assessment toolkit, not a generic Sampler template. Some older prose may still look template-derived; executable sources, `CLAUDE.md`, and `AGENTS.md` are the preferred sources of truth.

## What It Assesses

The assessment library is data-driven:

- `source/Checks/**/*.psd1` defines checks by assessment area, including identity security, conditional access, privileged access, device trust, endpoint management, BYOD governance, corporate device governance, identity governance, application security, hybrid identity, and monitoring/detection.
- `source/Settings/settings.psd1` defines thresholds, weights, retry behavior, and redaction settings.
- `source/Settings/permissions.psd1` defines module metadata and read-only Microsoft Graph scopes.
- The `Core` collection is always included; other areas are selected from check and permission metadata.
- Public `Applications` maps to internal `ApplicationSecurity`, and public `Monitoring` maps to internal `MonitoringDetection` in check, settings, and scoring data.

## Public Commands

The module manifest explicitly exports these functions:

- `Connect-ZTAssessment`
- `Disconnect-ZTAssessment`
- `Get-ZTAssessFinding`
- `Get-ZTAssessModuleCatalog`
- `Get-ZTAssessRequiredPermission`
- `Get-ZTAssessScore`
- `Invoke-ZTAssessment`
- `New-ZTAssessEngagement`

Typical consultant flow:

```powershell
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring
$engagement = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-042' -OutputPath ~/Assessments
$run = Invoke-ZTAssessment -EngagementPath $engagement.EngagementPath
Get-ZTAssessScore -RunPath $run.RunPath
Get-ZTAssessFinding -RunPath $run.RunPath -Severity High
Disconnect-ZTAssessment
```

`New-ZTAssessEngagement` creates the local engagement folder scaffold. `Invoke-ZTAssessment` orchestrates collection, assessment, scoring, and local artifact writes under that engagement path.

## Build And Test

```powershell
# First build / dependency restore
./build.ps1 -ResolveDependency -tasks build

# If dependency bootstrap fails, restore explicitly
./build.ps1 -ResolveDependency -Tasks noop

# Normal development commands
./build.ps1 -tasks build
./build.ps1 -tasks test
Invoke-Pester -Path tests
Invoke-ScriptAnalyzer -Path source/ -Recurse
./build.ps1 -tasks pack
```

Dependency restore installs required modules into `output/RequiredModules` and uses ModuleFast/NuGet version-range resolution. The build uses Sampler and ModuleBuilder; build output under `output/` is generated and should not be hand-edited.

`build.yaml` sets `CodeCoverageThreshold: 85` and copies `source/Checks`, `source/Settings`, and `source/en-US` into the built module.

## Source Layout

```text
source/
  Classes/                 DTOs and support classes
  Public/                  exported commands, one public function per file
  Private/                 collectors, assessors, scoring, Graph wrappers, logging
  Checks/                  declarative assessment definitions
  Settings/                thresholds, weights, permissions, scope metadata
  en-US/                   external help
  Get-EntraZTAssess.psm1   dev-time module loader
  Get-EntraZTAssess.psd1   module manifest and explicit export list

tests/
  Fixtures/                shared Pester fixtures and helpers
  Unit/                    public/private/class unit tests
  QA/                      read-only, help, ScriptAnalyzer, changelog, export checks
```

The dev-time module entrypoint is `source/Get-EntraZTAssess.psm1`. Sampler/ModuleBuilder compiles the release module into `output/`.

## Graph And Read-Only Guardrails

This project is intentionally read-only against Microsoft Graph. Do not add Graph write operations, write scopes, hidden telemetry, or production side effects without explicit approval and matching documentation.

Route Graph collection through the central wrappers:

- `Invoke-ZTAssessGraphRequest`
- `Invoke-MgGraphRequestWrapper`

Those paths preserve paging, retry/backoff behavior, logging, and read-only enforcement. `tests/QA/ReadOnly.tests.ps1` checks for direct `Invoke-MgGraphRequest`, write HTTP verbs, `Invoke-Expression`, hardcoded secrets, and Graph write scopes.

Use `Write-ToLog` for module logging. It handles mutex-protected file logging, rotation, redaction, and stream mapping.

## Testing Notes

Pester tests use v5 patterns and normally import `source/Get-EntraZTAssess.psd1`, so `Invoke-Pester -Path tests` works without a prior build. Prefer the project-scoped path once dependencies have been restored so generated tests under `output/RequiredModules` are not discovered. Unit tests mirror source under `tests/Unit/Public`, `tests/Unit/Private`, and `tests/Unit/Classes`.

Use helpers from `tests/Fixtures/FixtureHelper.ps1`, especially `New-ZTAssessTestRun`, and use `TestDrive` for filesystem writes. Mock `Write-ToLog` in unit tests unless the logger itself is under test. Private tests use `InModuleScope` and wrapper helpers where needed for mockability.

QA tests check exported-function help, ScriptAnalyzer, changelog quality, exported-function unit test coverage, and read-only security rules. `./build.ps1 -tasks test` includes the configured 85% coverage gate.

## CI And Release

- `.github/workflows/ci.yml` runs pack with dependency restore, test, and `Invoke-ScriptAnalyzer -Path source/ -Recurse -Settings PSGallery`.
- `.github/workflows/release.yml` is tag-driven (`v*`) and publishes to PSGallery plus GitHub Releases.
- `azure-pipelines.yml` runs pack/test across Linux, Windows PowerShell 7, and macOS.

Release tasks exist but should only be run intentionally:

```powershell
./build.ps1 -tasks publish_psgallery
./build.ps1 -tasks publish_github
```
