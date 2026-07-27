# Provisioning-as-Functions + Read-Only Front Door — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the two `scripts/New-ZTAssess*.ps1` provisioning scripts into real advanced functions in a repo-local `EntraZTAssess.Provisioning` module, and add a read-only `Get-ZTAssessProvisioningStep` front-door cmdlet to the core module — without weakening the read-only guarantee.

**Architecture:** Provisioning functions (one pure-crypto, one Graph-write) live in a standalone module under `scripts/`, imported deliberately by an admin and never shipped by `Install-Module Get-EntraZTAssess`. The core read-only module gains a single no-network cmdlet that emits the ordered provisioning commands as discoverable, Get-Help-able guidance.

**Tech Stack:** PowerShell 7+, Sampler/ModuleBuilder, Pester v5, PSScriptAnalyzer, Microsoft.Graph SDK (Applications/Authentication) — SDK required only at provisioning call time, never at import.

## Global Constraints

Every task's requirements implicitly include these:

- `#Requires -Version 7.0` on **line 1** of every `.ps1` and `.psm1`.
- Core module name is **`Get-EntraZTAssess`**; manifest is `source/Get-EntraZTAssess.psd1`.
- Provisioning module name is **`EntraZTAssess.Provisioning`**.
- **Read-only invariant:** no Graph-write code under `source/`. Provisioning code MUST stay outside `source/`, MUST NOT be added to `build.yaml` `CopyPaths`, and MUST NOT be a Sampler `NestedModule`. Core manifest keeps `RequiredModules = @()`.
- The provisioning manifest MUST keep `RequiredModules = @()` (do **not** hard-require the Graph SDK — it would block import/tests/Get-Help). Declare the SDK via `PrivateData.PSData.ExternalModuleDependencies`, and keep the runtime `Get-Command` precondition throw inside `New-ZTAssessAppRegistration`.
- Cross-platform (macOS/Linux/Windows). Tests must run with **no** Graph SDK installed and **no** live tenant — mock/stub all `*-Mg*` cmdlets.
- Public/core functions: CBH mandatory (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`). Read-only verbs (`Get-`) never use `SupportsShouldProcess`.
- Analyzer runs with the settings file: `Invoke-ScriptAnalyzer -Path <path> -Recurse -Settings PSScriptAnalyzerSettings.psd1`.
- Full suite `Invoke-Pester -Path tests` and `tests/QA/ReadOnly.tests.ps1` must stay green.
- Work on a feature branch (not `main`); one commit per task. Conventional-commit messages.

---

## Task 0: Branch

- [ ] **Step 1: Create and switch to a feature branch**

Run:
```bash
git switch -c feat/provisioning-functions
```

---

## Task 1: Provisioning module skeleton + `New-ZTAssessCertificate` function

Creates the repo-local module and moves the certificate script into it as a function. The cert function makes no network calls, so it is fully unit-testable.

**Files:**
- Create: `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1`
- Create: `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psm1`
- Create: `scripts/EntraZTAssess.Provisioning/Public/New-ZTAssessCertificate.ps1`
- Delete: `scripts/New-ZTAssessCertificate.ps1`
- Test: `tests/Unit/Provisioning/New-ZTAssessCertificate.tests.ps1`

**Interfaces:**
- Produces: module `EntraZTAssess.Provisioning` exporting
  `New-ZTAssessCertificate` with the SAME parameters as the existing script
  (`-SubjectName`, `-ValidityMonths`, `-OutputPath`, `-PfxPassword`,
  `-InstallToWindowsStore`) returning a `pscustomobject`
  (`PSTypeName = 'ZTAssess.Certificate'`) with `Thumbprint, Subject, NotAfter, CerPath, PfxPath, Platform`.

- [ ] **Step 1: Write the failing test**

Create `tests/Unit/Provisioning/New-ZTAssessCertificate.tests.ps1`:
```powershell
#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provManifest = Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1'
    Import-Module -Name $script:provManifest -Force
}

AfterAll {
    Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'New-ZTAssessCertificate' -Tag 'Unit' {

    It 'Should create a .cer and password-protected .pfx and return a summary' {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs'

        $result = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw -ValidityMonths 12

        $result.PSObject.TypeNames | Should -Contain 'ZTAssess.Certificate'
        Test-Path -LiteralPath $result.CerPath | Should -BeTrue
        Test-Path -LiteralPath $result.PfxPath | Should -BeTrue
        $result.Thumbprint | Should -Not -BeNullOrEmpty
    }

    It 'Should produce a .pfx that can be reloaded with its password' {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs2'

        $result = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw

        $reloaded = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $result.PfxPath, $securePw)
        $reloaded.Thumbprint | Should -Be $result.Thumbprint
        $reloaded.Dispose()
    }

    It 'Should throw when given an empty PFX password' {
        $empty = [securestring]::new()
        { New-ZTAssessCertificate -OutputPath (Join-Path $TestDrive 'c3') -PfxPassword $empty } |
            Should -Throw -ExpectedMessage '*password*'
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `Invoke-Pester -Path tests/Unit/Provisioning/New-ZTAssessCertificate.tests.ps1`
Expected: FAIL — the manifest/module does not exist yet (`Import-Module` throws).

- [ ] **Step 3: Create the module manifest**

Run this once to generate a valid manifest with a fresh GUID:
```powershell
New-ModuleManifest `
    -Path scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1 `
    -RootModule 'EntraZTAssess.Provisioning.psm1' `
    -ModuleVersion '0.1.0' `
    -PowerShellVersion '7.0' `
    -CompatiblePSEditions 'Core' `
    -Author 'EntraZTAssess' `
    -Description 'Admin-run, one-time provisioning commands (certificate + Entra ID app registration) for the read-only EntraZTAssess assessment toolkit. Not installed with the assessment module; imported deliberately from the repository. Performs Graph WRITE operations and therefore lives outside the read-only module surface.' `
    -FunctionsToExport @('New-ZTAssessCertificate') `
    -CmdletsToExport @() -AliasesToExport @() -VariablesToExport @() `
    -RequiredModules @() `
    -Tags @('Entra','Provisioning','ZTAssess')
```
Then edit the generated `.psd1` so `PrivateData.PSData` declares the external
SDK dependency (this documents the requirement without forcing it at import):
```powershell
# inside PrivateData = @{ PSData = @{ ... } }
        ExternalModuleDependencies = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')
```

- [ ] **Step 4: Create the module loader `.psm1`**

Create `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psm1`:
```powershell
#Requires -Version 7.0

<#
    Repo-local provisioning module loader. Dot-sources the provisioning
    functions and exports them. This module is deliberately NOT part of the
    built/published Get-EntraZTAssess package; it performs Graph writes and is
    run once by an administrator from a clone of the repository.
#>

$publicFunctions = Get-ChildItem -Path $PSScriptRoot/Public/*.ps1 -ErrorAction SilentlyContinue
foreach ($function in $publicFunctions) {
    . $function.FullName
    Export-ModuleMember -Function $function.BaseName
}
```

- [ ] **Step 5: Move the certificate script into the module as a function**

Move `scripts/New-ZTAssessCertificate.ps1` to
`scripts/EntraZTAssess.Provisioning/Public/New-ZTAssessCertificate.ps1`,
wrapping its content as a function. Keep the body **verbatim** — only add the
function wrapper. The file becomes:
```powershell
#Requires -Version 7.0

function New-ZTAssessCertificate {
    <#
        ... the existing comment-based help block, unchanged ...
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive admin-run provisioning function; coloured console guidance is intentional and not pipeline output.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        ... the existing param() block, unchanged ...
    )

    ... the existing body (from `$ErrorActionPreference = 'Stop'` through the
        final `try { ... return $result } finally { $certificate.Dispose() }`),
        unchanged ...
}
```
Then delete the old file:
```bash
git rm scripts/New-ZTAssessCertificate.ps1
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `Invoke-Pester -Path tests/Unit/Provisioning/New-ZTAssessCertificate.tests.ps1`
Expected: PASS (3 tests).

- [ ] **Step 7: Analyzer-clean the new module**

Run: `Invoke-ScriptAnalyzer -Path scripts/EntraZTAssess.Provisioning -Recurse -Settings PSScriptAnalyzerSettings.psd1`
Expected: no warnings/errors (the `PSAvoidUsingWriteHost` suppression covers the console output).

- [ ] **Step 8: Commit**

```bash
git add scripts/EntraZTAssess.Provisioning tests/Unit/Provisioning/New-ZTAssessCertificate.tests.ps1
git commit -m "feat: add EntraZTAssess.Provisioning module with New-ZTAssessCertificate function"
```

---

## Task 2: `New-ZTAssessAppRegistration` function (with corrected catalogue path)

Moves the app-registration script into the provisioning module as a function, fixes the one relative path that changes with the move, and tests it with mocked Graph SDK cmdlets.

**Files:**
- Create: `scripts/EntraZTAssess.Provisioning/Public/New-ZTAssessAppRegistration.ps1`
- Delete: `scripts/New-ZTAssessAppRegistration.ps1`
- Modify: `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1` (add to `FunctionsToExport`)
- Test: `tests/Unit/Provisioning/New-ZTAssessAppRegistration.tests.ps1`

**Interfaces:**
- Consumes: the `EntraZTAssess.Provisioning` module from Task 1.
- Produces: exported `New-ZTAssessAppRegistration` with the SAME parameters as
  the existing script (`-TenantId`, `-Modules`, `-CertificatePath`,
  `-DisplayName`, `-Environment`, `-GrantAdminConsent`, `-ConfigOutputPath`)
  returning a `pscustomobject` (`PSTypeName = 'ZTAssess.AppRegistration'`) with
  `ClientId, TenantId, CertificateThumbprint, ConfigPath, ConsentUrl`.
- Reads the permission catalogue from
  `Join-Path $PSScriptRoot '../../../source/Settings/permissions.psd1'`.

- [ ] **Step 1: Write the failing test**

Create `tests/Unit/Provisioning/New-ZTAssessAppRegistration.tests.ps1`. The
`BeforeAll` defines global stubs for the Graph SDK cmdlets (so the function's
`Get-Command` precondition passes and the commands are mockable cross-platform),
then each test mocks them in the module scope:
```powershell
#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provManifest = Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1'

    # Global stubs so the function's Get-Command precondition finds the SDK
    # cmdlets and Pester can Mock them without the real Microsoft.Graph SDK.
    function global:Connect-MgGraph { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function global:Get-MgServicePrincipal { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function global:New-MgApplication { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function global:Update-MgApplication { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function global:New-MgServicePrincipal { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function global:New-MgServicePrincipalAppRoleAssignment { param([Parameter(ValueFromRemainingArguments)]$Rest) }

    Import-Module -Name $script:provManifest -Force

    # A self-signed .cer on disk for the -CertificatePath argument.
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=ZTAssessProvTest', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $cert = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))
    $script:cerPath = Join-Path $TestDrive 'ZTAssess.cer'
    [System.IO.File]::WriteAllBytes($script:cerPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $cert.Dispose()

    # A fake Graph service principal whose AppRoles cover every catalogue scope.
    $catalogue = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '../../../source/Settings/permissions.psd1')
    $allScopes = $catalogue.Modules.Values.Scopes | Sort-Object -Unique
    $script:fakeAppRoles = foreach ($s in $allScopes) {
        [pscustomobject]@{ Value = $s; Id = [guid]::NewGuid().ToString(); AllowedMemberTypes = @('Application') }
    }
    $script:fakeSp = [pscustomobject]@{ Id = [guid]::NewGuid().ToString(); AppRoles = $script:fakeAppRoles }
}

AfterAll {
    Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\Connect-MgGraph, Function:\Get-MgServicePrincipal, Function:\New-MgApplication, `
        Function:\Update-MgApplication, Function:\New-MgServicePrincipal, `
        Function:\New-MgServicePrincipalAppRoleAssignment -ErrorAction SilentlyContinue
}

Describe 'New-ZTAssessAppRegistration' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:provModuleName Connect-MgGraph { }
        Mock -ModuleName $script:provModuleName Get-MgServicePrincipal { $script:fakeSp }
        Mock -ModuleName $script:provModuleName New-MgApplication {
            [pscustomobject]@{ DisplayName = 'EntraZTAssess-Assessment'; AppId = '11111111-1111-1111-1111-111111111111' }
        }
        Mock -ModuleName $script:provModuleName New-MgServicePrincipal {
            [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222' }
        }
        Mock -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment { }
    }

    It 'Should resolve the catalogue path and create the application' {
        $configPath = Join-Path $TestDrive 'auth.json'
        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -ConfigOutputPath $configPath

        $result.PSObject.TypeNames | Should -Contain 'ZTAssess.AppRegistration'
        $result.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 1
    }

    It 'Should write a non-secret config with no password field' {
        $configPath = Join-Path $TestDrive 'auth2.json'
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -ConfigOutputPath $configPath

        $json = Get-Content -Raw -Path $configPath | ConvertFrom-Json
        $json.TenantId | Should -Be 'contoso.onmicrosoft.com'
        $json.PSObject.Properties.Name | Should -Not -Contain 'CertificatePassword'
        $json.PSObject.Properties.Name | Should -Not -Contain 'Password'
    }

    It 'Should throw on an unknown module name' {
        { New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'NoSuchModule' } |
            Should -Throw -ExpectedMessage '*Unknown module*'
    }

    It 'Should throw when the certificate file is missing' {
        { New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath (Join-Path $TestDrive 'missing.cer') -Modules 'Identity' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `Invoke-Pester -Path tests/Unit/Provisioning/New-ZTAssessAppRegistration.tests.ps1`
Expected: FAIL — `New-ZTAssessAppRegistration` is not exported yet.

- [ ] **Step 3: Move the script into the module as a function, fixing the catalogue path**

Move `scripts/New-ZTAssessAppRegistration.ps1` to
`scripts/EntraZTAssess.Provisioning/Public/New-ZTAssessAppRegistration.ps1`,
wrapping its content as a function exactly as in Task 1 Step 5 (keep CBH,
`SuppressMessageAttribute`, `[CmdletBinding(SupportsShouldProcess)]`,
`[OutputType([pscustomobject])]`, and `param()`). Keep the body verbatim
**except** the one catalogue-path line, which must change because `$PSScriptRoot`
is now the `Public/` folder:
```powershell
# BEFORE (old script location):
$permissionsPath = Join-Path -Path $PSScriptRoot -ChildPath '../source/Settings/permissions.psd1'

# AFTER (Public/ -> module -> scripts -> repo root -> source/):
$permissionsPath = Join-Path -Path $PSScriptRoot -ChildPath '../../../source/Settings/permissions.psd1'
```
Then delete the old file:
```bash
git rm scripts/New-ZTAssessAppRegistration.ps1
```

- [ ] **Step 4: Export the new function from the manifest**

Edit `scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1` so
`FunctionsToExport` lists both functions:
```powershell
FunctionsToExport = @('New-ZTAssessAppRegistration', 'New-ZTAssessCertificate')
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `Invoke-Pester -Path tests/Unit/Provisioning/New-ZTAssessAppRegistration.tests.ps1`
Expected: PASS (4 tests).

- [ ] **Step 6: Analyzer-clean**

Run: `Invoke-ScriptAnalyzer -Path scripts/EntraZTAssess.Provisioning -Recurse -Settings PSScriptAnalyzerSettings.psd1`
Expected: no warnings/errors.

- [ ] **Step 7: Commit**

```bash
git add scripts/EntraZTAssess.Provisioning tests/Unit/Provisioning/New-ZTAssessAppRegistration.tests.ps1
git commit -m "feat: add New-ZTAssessAppRegistration function to provisioning module"
```

---

## Task 3: `Get-ZTAssessProvisioningStep` front-door cmdlet (core module)

Adds the read-only, no-network cmdlet to the core module and exports it.

**Files:**
- Create: `source/Public/Get-ZTAssessProvisioningStep.ps1`
- Modify: `source/Get-EntraZTAssess.psd1` (add to `FunctionsToExport`, between `Get-ZTAssessModuleCatalog` and `Get-ZTAssessRequiredPermission`)
- Test: `tests/Unit/Public/Get-ZTAssessProvisioningStep.tests.ps1`

**Interfaces:**
- Consumes: `Get-ZTAssessModuleCatalog -Name <string[]>` (existing core function; throws on unknown names) for `-Modules` validation.
- Produces: exported `Get-ZTAssessProvisioningStep [-Modules <string[]>]` emitting an ordered set of `pscustomobject` (`PSTypeName = 'ZTAssess.ProvisioningStep'`) each with `Step` (int), `Title` (string), `Command` (string), `Description` (string). Makes no Graph calls.

- [ ] **Step 1: Write the failing test**

Create `tests/Unit/Public/Get-ZTAssessProvisioningStep.tests.ps1`:
```powershell
#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'
    if (Get-Module -ListAvailable -Name $script:dscModuleName -ErrorAction SilentlyContinue) {
        Import-Module -Name $script:dscModuleName -Force
    }
    else {
        Import-Module -Name (Join-Path $PSScriptRoot '../../../source/Get-EntraZTAssess.psd1') -Force
    }
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessProvisioningStep' -Tag 'Unit' {

    It 'Should emit an ordered set of provisioning steps' {
        $steps = Get-ZTAssessProvisioningStep
        $steps.Count | Should -BeGreaterOrEqual 5
        $steps[0].PSObject.TypeNames | Should -Contain 'ZTAssess.ProvisioningStep'
        ($steps | ForEach-Object Step) | Should -Be (1..$steps.Count)
        ($steps.Command -join "`n") | Should -Match 'Import-Module .*EntraZTAssess\.Provisioning'
        ($steps.Command -join "`n") | Should -Match 'New-ZTAssessCertificate'
        ($steps.Command -join "`n") | Should -Match 'New-ZTAssessAppRegistration'
    }

    It 'Should tailor the app-registration and connect commands to -Modules' {
        $steps = Get-ZTAssessProvisioningStep -Modules Identity, Devices
        ($steps.Command -join "`n") | Should -Match '-Modules Identity, Devices'
    }

    It 'Should throw on an unknown module name' {
        { Get-ZTAssessProvisioningStep -Modules 'NoSuchModule' } | Should -Throw
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `Invoke-Pester -Path tests/Unit/Public/Get-ZTAssessProvisioningStep.tests.ps1`
Expected: FAIL — command not found.

- [ ] **Step 3: Implement the cmdlet**

Create `source/Public/Get-ZTAssessProvisioningStep.ps1`:
```powershell
#Requires -Version 7.0

function Get-ZTAssessProvisioningStep {
    <#
    .SYNOPSIS
    Lists the ordered steps to provision the EntraZTAssess app registration.

    .DESCRIPTION
    Emits the sequence of commands an administrator runs once to stand up the
    certificate and Entra ID app registration used for certificate-based,
    app-only assessment. Provisioning performs Microsoft Graph WRITE operations
    and therefore lives in the repository's scripts/EntraZTAssess.Provisioning
    module, NOT in this read-only assessment module; the guidance below is
    repo-relative because that module is not installed by Install-Module.

    This function makes no network calls and requires no connection.

    .PARAMETER Modules
    Optional assessment modules to scope the app registration to. When supplied,
    the emitted app-registration and connection commands are tailored to them.
    Use Get-ZTAssessModuleCatalog to list valid names; unknown names throw.

    .EXAMPLE
    Get-ZTAssessProvisioningStep

    Lists the default provisioning steps.

    .EXAMPLE
    Get-ZTAssessProvisioningStep -Modules Identity, Devices | Format-List

    Lists provisioning steps scoped to the Identity and Devices modules.

    .OUTPUTS
    PSCustomObject
    One object per step with Step, Title, Command, and Description.

    .NOTES
    Provisioning is an admin-run, one-time step performed from a clone of the
    EntraZTAssess repository. It is intentionally not part of the installed,
    read-only assessment module.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules
    )

    # Validate module names against the catalogue (reads local settings, no network).
    if ($Modules) {
        $null = Get-ZTAssessModuleCatalog -Name $Modules -ErrorAction Stop
    }

    $moduleSuffix = if ($Modules) { ' -Modules {0}' -f ($Modules -join ', ') } else { '' }

    $steps = @(
        @{ Title = 'Create the certificate'
           Command = 'New-ZTAssessCertificate'
           Description = 'Generates ~/.ztassess/EntraZTAssess.cer (public) and EntraZTAssess.pfx (private key). Run once; keep the .pfx and its password safe.' }
        @{ Title = 'Register the application'
           Command = ('New-ZTAssessAppRegistration -TenantId <YourTenantId> -CertificatePath ~/.ztassess/EntraZTAssess.cer{0}' -f $moduleSuffix)
           Description = 'Creates the Entra ID app with least-privilege read-only Graph permissions, uploads the certificate, and writes ~/.ztassess/auth.json. Requires the Microsoft.Graph SDK and an account that can create app registrations.' }
        @{ Title = 'Approve admin consent'
           Command = 'Get-ZTAssessRequiredPermission{0} | Format-Table' -f $moduleSuffix
           Description = 'A Global Administrator approves the read-only permissions via the consent URL printed by the previous step. Share the required-permission list with the security team first.' }
        @{ Title = 'Connect and assess'
           Command = ('Connect-ZTAssessment{0}' -f $moduleSuffix)
           Description = 'Once consent is granted, connect with certificate-based app-only auth using the values recorded in ~/.ztassess/auth.json.' }
    )

    # Prepend the import step; provisioning commands live in the repo module.
    $orderedSteps = @(
        @{ Title = 'Import the provisioning module'
           Command = 'Import-Module ./scripts/EntraZTAssess.Provisioning'
           Description = 'From a clone of the EntraZTAssess repository. These commands perform Graph writes and are not installed with the read-only assessment module.' }
    ) + $steps

    $stepNumber = 0
    foreach ($step in $orderedSteps) {
        $stepNumber++
        [pscustomobject]@{
            PSTypeName  = 'ZTAssess.ProvisioningStep'
            Step        = $stepNumber
            Title       = $step.Title
            Command     = $step.Command
            Description = $step.Description
        }
    }
}
```

- [ ] **Step 4: Export the function from the core manifest**

Edit `source/Get-EntraZTAssess.psd1`, adding the entry in alphabetical position:
```powershell
FunctionsToExport = @(
    'Connect-ZTAssessment'
    'Disconnect-ZTAssessment'
    'Export-ZTAssessReport'
    'Get-ZTAssessFinding'
    'Get-ZTAssessModuleCatalog'
    'Get-ZTAssessProvisioningStep'
    'Get-ZTAssessRequiredPermission'
    'Get-ZTAssessScore'
    'Invoke-ZTAssessment'
    'New-ZTAssessEngagement'
)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `Invoke-Pester -Path tests/Unit/Public/Get-ZTAssessProvisioningStep.tests.ps1`
Expected: PASS (3 tests).

- [ ] **Step 6: Run the QA gate for the new exported function**

Run: `Invoke-Pester -Path tests/QA`
Expected: PASS — the help-quality and per-function test-existence checks accept
`Get-ZTAssessProvisioningStep` (it has full CBH and a matching test file), and
`ReadOnly.tests.ps1` stays green (the cmdlet makes no Graph calls).

- [ ] **Step 7: Analyzer-clean**

Run: `Invoke-ScriptAnalyzer -Path source/Public/Get-ZTAssessProvisioningStep.ps1 -Settings PSScriptAnalyzerSettings.psd1`
Expected: no warnings/errors.

- [ ] **Step 8: Commit**

```bash
git add source/Public/Get-ZTAssessProvisioningStep.ps1 source/Get-EntraZTAssess.psd1 tests/Unit/Public/Get-ZTAssessProvisioningStep.tests.ps1
git commit -m "feat: add read-only Get-ZTAssessProvisioningStep front-door cmdlet"
```

---

## Task 4: Tighten the read-only QA gate

Closes the gap where a Graph-write SDK cmdlet (`New-Mg*`, `Update-Mg*`, `*AppRoleAssignment`) could be added under `source/` and still pass CI.

**Files:**
- Modify: `tests/QA/ReadOnly.tests.ps1` (add one `It` block in the `Read-only enforcement` Describe)

**Interfaces:**
- Consumes: `$script:sourceFiles` (already defined in the file's `BeforeAll` — all `*.ps1`/`*.psm1` under `source/`).

- [ ] **Step 1: Add the failing-guard test**

In `tests/QA/ReadOnly.tests.ps1`, inside `Describe 'Read-only enforcement'`, add:
```powershell
    It 'Should not use Graph write SDK cmdlets anywhere under source/' {
        $writeCmdletPattern = '\b(New|Update|Remove|Set)-Mg[A-Za-z]+\b|AppRoleAssignment\b'

        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match $writeCmdletPattern) {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'Graph write operations must live in scripts/EntraZTAssess.Provisioning, never under source/'
    }
```

- [ ] **Step 2: Run the read-only QA suite**

Run: `Invoke-Pester -Path tests/QA/ReadOnly.tests.ps1`
Expected: PASS — no `source/` file uses write SDK cmdlets (the provisioning
functions live under `scripts/`, which this suite does not scan).

- [ ] **Step 3: Commit**

```bash
git add tests/QA/ReadOnly.tests.ps1
git commit -m "test: forbid Graph write SDK cmdlets under source/"
```

---

## Task 5: Documentation sync

Updates every doc that references the provisioning scripts to the new
import-and-call flow, and mentions the front-door cmdlet. Required by the repo's
mandatory doc-maintenance rule.

**Files (Modify):**
- `scripts/README.md` — the Step 1/Step 2 invocations become
  `Import-Module ./scripts/EntraZTAssess.Provisioning` followed by
  `New-ZTAssessCertificate` / `New-ZTAssessAppRegistration ...`. Update the
  "Why these live outside the module" section to describe a repo-local module
  (not loose scripts) and note it is still not shipped by `Install-Module`.
- `README.md` — update any `scripts/New-ZTAssess*.ps1` usage to the new flow and
  add `Get-ZTAssessProvisioningStep` to the exported-command list.
- `docs/Authentication.md` — update the provisioning walkthrough to the module
  import + function calls; reference `Get-ZTAssessProvisioningStep`.
- `docs/PermissionsGuidance.md` — update any script-path references.
- `CLAUDE.md` — in the read-only architecture rule, change "the only Graph write
  operations ... live in the top-level `scripts/` provisioning folder" to name
  the `scripts/EntraZTAssess.Provisioning` module and functions; add
  `Get-ZTAssessProvisioningStep` to the exported-function list; note the new
  provisioning-module test location.
- `AGENTS.md` — mirror the CLAUDE.md changes (boundaries, provisioning location).
- `.github/copilot-instructions.md` — mirror the summary changes.
- `CHANGELOG.md` — add entries under `## [Unreleased]`.

- [ ] **Step 1: Update `scripts/README.md`**

Replace the Step 1 and Step 2 fenced commands with:
```powershell
Import-Module ./scripts/EntraZTAssess.Provisioning

# Step 1 - create the certificate (any OS)
New-ZTAssessCertificate

# Step 2 - register the application (admin)
New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' -CertificatePath ~/.ztassess/EntraZTAssess.cer
```
And update the prose that calls them "scripts" to "functions in the repo-local
`EntraZTAssess.Provisioning` module", preserving the distribution note that the
module is not shipped by `Install-Module`.

- [ ] **Step 2: Update the remaining docs**

Apply the equivalent script-path → import-and-call change in `README.md`,
`docs/Authentication.md`, and `docs/PermissionsGuidance.md`; add
`Get-ZTAssessProvisioningStep` to the exported-command listing in `README.md`
and `CLAUDE.md`; mirror the boundary wording in `AGENTS.md`,
`.github/copilot-instructions.md`, and the read-only rule in `CLAUDE.md`.

- [ ] **Step 3: Add the changelog entry**

Under `## [Unreleased]` in `CHANGELOG.md`:
```markdown
### Added
- `Get-ZTAssessProvisioningStep` — a read-only cmdlet in the core module that
  lists the ordered provisioning commands (no Graph calls).
- Repo-local `EntraZTAssess.Provisioning` module exposing `New-ZTAssessCertificate`
  and `New-ZTAssessAppRegistration` as advanced functions.

### Changed
- Provisioning is now performed by importing the repo-local
  `EntraZTAssess.Provisioning` module and calling its functions, instead of
  invoking `scripts/New-ZTAssess*.ps1` directly. The module is still not shipped
  by `Install-Module`; the read-only guarantee is unchanged.

### Removed
- `scripts/New-ZTAssessCertificate.ps1` and `scripts/New-ZTAssessAppRegistration.ps1`
  (their logic moved into the `EntraZTAssess.Provisioning` module).
```

- [ ] **Step 4: Verify the changelog parses**

Run: `Invoke-Pester -Path tests/QA/module.tests.ps1 -TagFilter Changelog` (or the full `tests/QA`).
Expected: PASS — the changelog `[Unreleased]` section is present and valid.

- [ ] **Step 5: Commit**

```bash
git add README.md AGENTS.md CLAUDE.md CHANGELOG.md docs/Authentication.md docs/PermissionsGuidance.md .github/copilot-instructions.md scripts/README.md
git commit -m "docs: describe function-based provisioning and Get-ZTAssessProvisioningStep"
```

---

## Task 6: Full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run the entire test suite**

Run: `Invoke-Pester -Path tests`
Expected: PASS — all unit + QA tests green, including `ReadOnly.tests.ps1` and
the two new provisioning test files.

- [ ] **Step 2: Run ScriptAnalyzer over both trees**

Run:
```powershell
Invoke-ScriptAnalyzer -Path source/ -Recurse -Settings PSScriptAnalyzerSettings.psd1
Invoke-ScriptAnalyzer -Path scripts/ -Recurse -Settings PSScriptAnalyzerSettings.psd1
```
Expected: no warnings/errors from either.

- [ ] **Step 3: Confirm the read-only build packaging is unchanged**

Verify `build.yaml` `CopyPaths` still lists only `en-US`, `Settings`, `Checks`
(the provisioning module must NOT appear), and `source/Get-EntraZTAssess.psd1`
keeps `RequiredModules = @()`.

- [ ] **Step 4: Confirm provisioning discovery works end to end**

Run:
```powershell
Import-Module ./scripts/EntraZTAssess.Provisioning -Force
Get-Command -Module EntraZTAssess.Provisioning
Get-Help New-ZTAssessAppRegistration -Full | Out-Null
```
Expected: both `New-ZTAssessCertificate` and `New-ZTAssessAppRegistration` are
listed, and Get-Help renders full help.

---

## Execution outcome (2026-07-27)

Implemented and **staged, not committed** (per user direction) on branch
`feat/provisioning-functions`. Verified:

- Unit suite: 460 Pester tests pass (Pester 5.7.1); the 3 new test files pass,
  including the added write-path coverage (`-GrantAdminConsent`), default-module
  resolution, and `New-MgApplication` payload assertion from code review.
- ScriptAnalyzer clean on all new code files (bare **and** `-Settings PSGallery`
  on the new core cmdlet).
- Read-only invariant confirmed four ways (CopyPaths, psm1 loader, core
  `RequiredModules = @()`, tightened ReadOnly gate). `New-ZTAssessProvisioningStep`
  is 100% covered.
- Code review (independent): no Critical; HIGH test-gap fixed, MEDIUM regex
  broadened, one LOW (cert dispose) fixed, one LOW (`Update-MgApplication` dead
  precondition) deferred as faithful-to-original.

**Known-red, pre-existing (NOT caused by this change):** `build.ps1 -tasks test`
coverage gate fails at 79.32% vs the 85% threshold. Per-file analysis attributes
the shortfall to long-standing 0%-covered network collectors
(`Invoke-ZTAssess*Collection.ps1`), the assessors (76–84%), and the uncommitted
CBA `Connect-MgGraphWrapper.ps1` (0%). This refactor's own new source file is
100% covered and does not lower the aggregate. Raising coverage on the
collectors/CBA wrapper (or adjusting the threshold/exclusions) belongs to the CBA
feature, not this refactor.

## Self-Review (completed by plan author)

- **Spec coverage:** provisioning module (Tasks 1–2), corrected catalogue path (Task 2 Step 3), front-door cmdlet (Task 3), tightened ReadOnly gate (Task 4), doc-sync across eight files + changelog (Task 5), full verification incl. `RequiredModules = @()` and `CopyPaths` unchanged (Task 6). All spec sections mapped.
- **Placeholder scan:** the moved function bodies are an explicit verbatim carry-over of existing, version-controlled files (not a TODO); every test and the new cmdlet are given in full. `<YourTenantId>` inside an emitted example string is intended literal guidance text, not an unfilled plan placeholder.
- **Type consistency:** `PSTypeName` values (`ZTAssess.Certificate`, `ZTAssess.AppRegistration`, `ZTAssess.ProvisioningStep`), the module name `EntraZTAssess.Provisioning`, the core module name `Get-EntraZTAssess`, and the catalogue path `../../../source/Settings/permissions.psd1` are used consistently across tasks.
