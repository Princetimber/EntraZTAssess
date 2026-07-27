# Design — Provisioning as functions + a read-only front door

**Date:** 2026-07-27
**Status:** Approved (design); pending spec review
**Driver:** API consistency — the `New-ZTAssess*` verb-nouns currently exist as loose
`scripts/*.ps1` files rather than proper commands alongside the module's other
`New-ZTAssess*` / `Get-ZTAssess*` cmdlets.

## Goal

Make the two provisioning commands feel like first-class PowerShell commands
(real advanced functions with working `Get-Help` and tab-completion, and
unit-testable), and give the read-only core module a single discoverable,
sanctioned entry point into provisioning — **without weakening the module's
read-only guarantee**.

## Non-negotiable constraint (the invariant)

`EntraZTAssess` sells a statically-enforced promise: *the module you
`Install-Module` cannot write to Microsoft Graph.* This is documented in seven
files and enforced by `tests/QA/ReadOnly.tests.ps1`, which scans `source/` for
write methods and non-GET Graph traffic.

`New-ZTAssessAppRegistration` performs Graph **writes** (`New-MgApplication`,
`New-MgServicePrincipal`, `New-MgServicePrincipalAppRoleAssignment`) and needs
the `Microsoft.Graph.Applications` SDK. Therefore its function **must not** live
under `source/` and **must not** be bundled into the core module's shipped
package (this rules out a Sampler `NestedModule`, which the core manifest would
carry into the install footprint). `New-ZTAssessCertificate` makes no Graph
calls, but travels with its sibling to keep the provisioning workflow coherent.

**Design rule:** provisioning code lives *outside* `source/`, in a repo-local
module that is not part of the built/published `EntraZTAssess` package.

## Design

Two independent, well-bounded units.

### 1. Repo-local provisioning module — `scripts/EntraZTAssess.Provisioning/`

A standalone PowerShell module that ships **only** in the repository (as
`scripts/` does today) — never installed by `Install-Module EntraZTAssess`, never
in `build.yaml` `CopyPaths`, never scanned by the read-only QA gate over
`source/`.

Contents:

- `EntraZTAssess.Provisioning.psd1` — manifest. `FunctionsToExport` =
  `New-ZTAssessCertificate`, `New-ZTAssessAppRegistration`. `RequiredModules`
  declares the Graph SDK (`Microsoft.Graph.Authentication`,
  `Microsoft.Graph.Applications`) so the dependency loads **only** when an admin
  imports this module — the core module's `RequiredModules = @()` stays empty.
  `PowerShellVersion = '7.0'`; `CompatiblePSEditions = @('Core')`.
- `EntraZTAssess.Provisioning.psm1` — dot-sources the two function files.
- `Public/New-ZTAssessCertificate.ps1` — the existing cert script body, wrapped
  as `function New-ZTAssessCertificate { <#CBH#> [CmdletBinding(SupportsShouldProcess)] param(...) ... }`.
  Logic is unchanged (pure .NET crypto, local file writes, no network).
- `Public/New-ZTAssessAppRegistration.ps1` — the existing app-registration
  script body wrapped as a function. Logic unchanged **except** path resolution:
  it currently reads `permissions.psd1` via
  `Join-Path $PSScriptRoot '../source/Settings/permissions.psd1'`. From the new
  location (`scripts/EntraZTAssess.Provisioning/Public/`) `$PSScriptRoot` is the
  `Public/` folder, so the path becomes
  `Join-Path $PSScriptRoot '../../../source/Settings/permissions.psd1'`
  (Public → provisioning-module → scripts → repo root → `source/…`). This is the
  one behavioural edit required by the move; it is covered by a unit test.

Usage (admin, from a repo clone):

```powershell
Import-Module ./scripts/EntraZTAssess.Provisioning
New-ZTAssessCertificate
New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' -CertificatePath ~/.ztassess/EntraZTAssess.cer
```

Why a `.psm1` module and not function-defining `.ps1` files the admin
dot-sources: a `.ps1` that only *defines* a function stops self-executing —
`./New-ZTAssessCertificate.ps1` would define and exit, doing nothing. An
importable module avoids that foot-gun and gives one clean `Import-Module`.

### 2. Front-door cmdlet — `Get-ZTAssessProvisioningStep` (core module)

A new **read-only** public function in `source/Public/`, modelled on
`Get-ZTAssessRequiredPermission` (no network, `[CmdletBinding()]`, CBH, emits
typed `PSCustomObject`s). It is the discoverable, Get-Help-able citizen that
answers "how do I provision the app?" from inside the installed module.

- `[CmdletBinding()]`, `[OutputType([pscustomobject])]`. **No** `SupportsShouldProcess`
  (read-only verb). Makes **zero** Graph calls.
- Optional `-Modules` parameter: when supplied, the emitted
  `New-ZTAssessAppRegistration` example is tailored to those modules, and the
  step set can surface the required read-only scopes (reuse
  `Get-ZTAssessRequiredPermission`).
- Emits an ordered sequence of `PSCustomObject`s
  (`PSTypeName = 'ZTAssess.ProvisioningStep'`) with `Step`, `Title`, `Command`,
  `Description`, covering: (1) `Import-Module ./scripts/EntraZTAssess.Provisioning`,
  (2) `New-ZTAssessCertificate`, (3) `New-ZTAssessAppRegistration …`,
  (4) admin-consent approval, (5) `Connect-ZTAssessment …`.
- **Post-install honesty:** guidance is repo-relative ("from a clone of the
  EntraZTAssess repository…"), because `scripts/` is not present after
  `Install-Module`. The `.DESCRIPTION`/`.NOTES` state explicitly that
  provisioning performs Graph writes and therefore lives in repo tooling, not
  the read-only module.

## Files changed

Add:
- `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1`
- `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psm1`
- `scripts/EntraZTAssess.Provisioning/Public/New-ZTAssessCertificate.ps1`
- `scripts/EntraZTAssess.Provisioning/Public/New-ZTAssessAppRegistration.ps1`
- `source/Public/Get-ZTAssessProvisioningStep.ps1`
- `tests/Unit/Public/Get-ZTAssessProvisioningStep.tests.ps1`
- `tests/Unit/Provisioning/New-ZTAssessCertificate.tests.ps1`
- `tests/Unit/Provisioning/New-ZTAssessAppRegistration.tests.ps1`

Remove:
- `scripts/New-ZTAssessCertificate.ps1`
- `scripts/New-ZTAssessAppRegistration.ps1`
(their bodies move into the provisioning module)

Edit:
- `source/EntraZTAssess.psd1` — add `Get-ZTAssessProvisioningStep` to
  `FunctionsToExport`. Core `RequiredModules` stays `@()`.
- `tests/QA/ReadOnly.tests.ps1` — **tighten** to also assert no `New-Mg*` /
  `Update-Mg*` / `*AppRoleAssignment` write SDK cmdlets appear under `source/`,
  closing the gap where the app-reg function could pass CI if accidentally moved
  in. (Robustness improvement; the invariant, not the current test coverage, is
  the real constraint.)
- Docs (per the mandatory doc-sync rule): `README.md`, `AGENTS.md`, `CLAUDE.md`,
  `CHANGELOG.md` (Unreleased entry), `docs/PermissionsGuidance.md`,
  `docs/Authentication.md`, `.github/copilot-instructions.md`, `scripts/README.md`
  — update the provisioning invocation from `./scripts/New-ZTAssess*.ps1` to the
  `Import-Module ./scripts/EntraZTAssess.Provisioning` + function-call form, and
  mention `Get-ZTAssessProvisioningStep` as the front door.

## Testing

- `Get-ZTAssessProvisioningStep`: unit test asserting it emits the ordered steps,
  makes no Graph calls, and honours `-Modules`. Subject to the full QA battery
  (CBH quality, matching test file, analyzer-clean) because it is an exported
  core function.
- Provisioning functions: unit tests mocking the Graph SDK cmdlets
  (`Connect-MgGraph`, `Get-MgServicePrincipal`, `New-MgApplication`,
  `New-MgServicePrincipal`, `New-MgServicePrincipalAppRoleAssignment`,
  `Update-MgApplication`) so they run cross-platform with no live tenant; and a
  test for the corrected `permissions.psd1` path resolution. These live outside
  `$sourcePath`, so they are added deliberately rather than auto-required.
- Keep the provisioning module analyzer-clean (retain the existing
  `PSAvoidUsingWriteHost` suppressions on the interactive functions).
- Full suite (`Invoke-Pester -Path tests`) + `Invoke-ScriptAnalyzer` on both
  `source/` and `scripts/` must pass. `tests/QA/ReadOnly.tests.ps1` stays green.

## Out of scope

- Publishing `EntraZTAssess.Provisioning` to PSGallery (that is the heavier
  "full C" path; explicitly deferred).
- Any change to what the assessment itself can do; no new runtime scopes.
- Turning `New-ZTAssessAppRegistration` into a core-module function (breaks the
  invariant — rejected).

## Risks & mitigations

- **Invariant regression** if provisioning code ever lands under `source/` or in
  a bundled nested module → mitigated by the tightened ReadOnly test and by
  keeping the provisioning module repo-local and out of `CopyPaths`.
- **Path breakage** for `permissions.psd1` after the move → covered by an
  explicit unit test.
- **Consistency caveat honoured:** this makes the commands real, importable
  functions; it does not make them installable via `Install-Module EntraZTAssess`
  (by design — that would ship write code).

## Acceptance criteria

1. `Import-Module ./scripts/EntraZTAssess.Provisioning; Get-Command -Module EntraZTAssess.Provisioning`
   lists `New-ZTAssessCertificate` and `New-ZTAssessAppRegistration`, and
   `Get-Help New-ZTAssessAppRegistration -Full` renders.
2. The core module still declares `RequiredModules = @()` and ships no write code;
   `Get-ZTAssessProvisioningStep` is exported and read-only.
3. `Invoke-Pester -Path tests` and ScriptAnalyzer over `source/` and `scripts/`
   pass; `ReadOnly.tests.ps1` (tightened) passes.
4. All eight docs describe the new function-based provisioning flow.
