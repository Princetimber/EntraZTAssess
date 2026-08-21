#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provModuleRoot = Resolve-Path (Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning')
    $script:sourceCataloguePath = Resolve-Path (Join-Path $PSScriptRoot '../../../source/Settings/permissions.psd1')
    $script:bundledCataloguePath = Join-Path $script:provModuleRoot 'Settings/permissions.psd1'
}

Describe 'EntraZTAssess.Provisioning permission catalogue bundling' -Tag 'Unit' {

    It 'Ships its own copy of the permission catalogue under Settings/' {
        Test-Path -LiteralPath $script:bundledCataloguePath | Should -BeTrue
    }

    It 'Keeps the bundled catalogue in sync with source/Settings/permissions.psd1' {
        # Compare parsed data, not raw text, so the bundled copy's extra header
        # comment (documenting why it's here) doesn't fail the diff.
        $sourceCatalogue = Import-PowerShellDataFile -Path $script:sourceCataloguePath
        $bundledCatalogue = Import-PowerShellDataFile -Path $script:bundledCataloguePath

        (ConvertTo-Json -InputObject $bundledCatalogue -Depth 10) |
            Should -Be (ConvertTo-Json -InputObject $sourceCatalogue -Depth 10)
    }

    It 'Declares the bundled catalogue in the module manifest FileList' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:provModuleRoot 'EntraZTAssess.Provisioning.psd1')
        $manifest.FileList | Should -Contain 'Settings/permissions.psd1'
    }

    It 'Resolves the permission catalogue when the module is copied without a sibling source/ folder (simulated PSGallery install)' {
        # Regression test for the bug where New-ZTAssessAppRegistration resolved
        # the catalogue via '../../../source/Settings/permissions.psd1' -
        # correct only in a git checkout, and always missing for a module
        # installed from PSGallery (no sibling `source/` folder exists there).
        $installRoot = Join-Path $TestDrive 'simulated-install'
        Copy-Item -LiteralPath $script:provModuleRoot -Destination $installRoot -Recurse -Force

        # Prove the isolation: no `source` directory anywhere above the copy.
        Join-Path (Split-Path $installRoot -Parent) 'source' | Test-Path | Should -BeFalse

        $installedManifest = Join-Path $installRoot 'EntraZTAssess.Provisioning.psd1'

        function global:Connect-MgGraph { [CmdletBinding()] param($TenantId, $Scopes, $Environment, [switch]$NoWelcome, [switch]$UseDeviceCode) }
        function global:Get-MgApplication { [CmdletBinding()] param($Filter) }
        function global:Get-MgServicePrincipal { [CmdletBinding()] param($Filter) }
        function global:New-MgApplication { [CmdletBinding()] param($DisplayName, $SignInAudience, $RequiredResourceAccess, $KeyCredentials) }
        function global:New-MgServicePrincipal { [CmdletBinding()] param($AppId) }
        function global:New-MgServicePrincipalAppRoleAssignment { [CmdletBinding()] param($ServicePrincipalId, $PrincipalId, $ResourceId, $AppRoleId) }

        try {
            Import-Module -Name $installedManifest -Force

            Mock -ModuleName $script:provModuleName Connect-MgGraph { }
            Mock -ModuleName $script:provModuleName Get-MgApplication { $null }
            Mock -ModuleName $script:provModuleName Get-MgServicePrincipal {
                $cat = Import-PowerShellDataFile -Path $script:sourceCataloguePath
                $scopes = $cat.Modules.Values.Scopes | Sort-Object -Unique
                $roles = foreach ($s in $scopes) {
                    [pscustomobject]@{ Value = $s; Id = [guid]::NewGuid().ToString(); AllowedMemberTypes = @('Application') }
                }
                [pscustomobject]@{ Id = [guid]::NewGuid().ToString(); AppRoles = $roles }
            }
            Mock -ModuleName $script:provModuleName New-MgApplication {
                [pscustomobject]@{ DisplayName = 'EntraZTAssess-Assessment'; AppId = '11111111-1111-1111-1111-111111111111' }
            }
            Mock -ModuleName $script:provModuleName New-MgServicePrincipal {
                [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222' }
            }
            Mock -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment { }

            $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=ZTAssessProvTest', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $cert = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))
            $cerPath = Join-Path $TestDrive 'ZTAssessSimInstall.cer'
            [System.IO.File]::WriteAllBytes($cerPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            $cert.Dispose()

            $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
                -CertificatePath $cerPath -Modules 'Identity' `
                -ConfigOutputPath (Join-Path $TestDrive 'auth-simulated-install.json') -Confirm:$false

            $result.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'

            # Regression test for the same bug in
            # Get-ZTAssessExchangeOnlineRoleGuidance, which resolved the
            # catalogue via '../../../source/Settings/permissions.psd1'
            # instead of the bundled '../Settings/permissions.psd1'.
            $guidance = Get-ZTAssessExchangeOnlineRoleGuidance -Modules 'SecurityCompliance'
            $guidance | Should -Not -BeNullOrEmpty
        }
        finally {
            Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
            Remove-Item Function:\Connect-MgGraph, Function:\Get-MgApplication, Function:\Get-MgServicePrincipal, `
                Function:\New-MgApplication, `
                Function:\New-MgServicePrincipal, `
                Function:\New-MgServicePrincipalAppRoleAssignment -ErrorAction SilentlyContinue
        }
    }
}
