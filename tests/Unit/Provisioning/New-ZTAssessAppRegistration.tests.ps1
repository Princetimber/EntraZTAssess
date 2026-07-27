#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provManifest = Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1'

    # Absolute path to the permission catalogue, shared with the module-scoped
    # mock bodies via an environment variable (module-scope mocks cannot see
    # $script: variables from this test file).
    $env:ZTPROV_TEST_PERMISSIONS = (Resolve-Path (Join-Path $PSScriptRoot '../../../source/Settings/permissions.psd1')).Path

    # Advanced-function stubs for the Microsoft.Graph SDK cmdlets. They declare
    # exactly the named parameters the function passes, so both the stub and the
    # Pester-generated mock bind those arguments cleanly. [CmdletBinding()] also
    # gives them -ErrorAction. This lets the function's Get-Command precondition
    # pass and the tests run with no real SDK installed.
    function global:Connect-MgGraph { [CmdletBinding()] param($TenantId, $Scopes, $Environment, [switch]$NoWelcome) }
    function global:Get-MgServicePrincipal { [CmdletBinding()] param($Filter) }
    function global:New-MgApplication { [CmdletBinding()] param($DisplayName, $SignInAudience, $RequiredResourceAccess, $KeyCredentials) }
    function global:New-MgServicePrincipal { [CmdletBinding()] param($AppId) }
    function global:New-MgServicePrincipalAppRoleAssignment { [CmdletBinding()] param($ServicePrincipalId, $PrincipalId, $ResourceId, $AppRoleId) }

    Import-Module -Name $script:provManifest -Force

    # A self-signed public .cer on disk for the -CertificatePath argument.
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=ZTAssessProvTest', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $cert = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))
    $script:cerPath = Join-Path $TestDrive 'ZTAssess.cer'
    [System.IO.File]::WriteAllBytes($script:cerPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $cert.Dispose()
}

AfterAll {
    Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\Connect-MgGraph, Function:\Get-MgServicePrincipal, Function:\New-MgApplication, `
        Function:\New-MgServicePrincipal, `
        Function:\New-MgServicePrincipalAppRoleAssignment -ErrorAction SilentlyContinue
    Remove-Item Env:\ZTPROV_TEST_PERMISSIONS -ErrorAction SilentlyContinue
}

Describe 'New-ZTAssessAppRegistration' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:provModuleName Connect-MgGraph { }
        Mock -ModuleName $script:provModuleName Get-MgServicePrincipal {
            # Build a fake Graph SP whose AppRoles cover every catalogue scope.
            $cat = Import-PowerShellDataFile -Path $env:ZTPROV_TEST_PERMISSIONS
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

    It 'Should create one app-role assignment per resolved scope when -GrantAdminConsent is supplied' {
        # Expected = unique union of the always-included Core scopes and the
        # requested Identity scopes; the fake service principal exposes an
        # Application app role for every catalogue scope, so all resolve.
        $cat = Import-PowerShellDataFile -Path $env:ZTPROV_TEST_PERMISSIONS
        $expected = @($cat.Modules['Core'].Scopes + $cat.Modules['Identity'].Scopes | Sort-Object -Unique).Count

        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-consent.json') -GrantAdminConsent

        Should -Invoke -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment -Times $expected -Exactly
    }

    It 'Should not create app-role assignments without -GrantAdminConsent' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-noconsent.json')

        Should -Invoke -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment -Times 0 -Exactly
    }

    It 'Should resolve the default module set when -Modules is omitted' {
        $configPath = Join-Path $TestDrive 'auth-default.json'
        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -ConfigOutputPath $configPath

        $result.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 1
    }

    It 'Should pass only read-only application (Role) resource access to New-MgApplication' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-payload.json')

        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 1 -ParameterFilter {
            $RequiredResourceAccess.Count -eq 1 -and
            $RequiredResourceAccess[0].ResourceAppId -eq '00000003-0000-0000-c000-000000000000' -and
            $RequiredResourceAccess[0].ResourceAccess.Count -ge 1 -and
            -not ($RequiredResourceAccess[0].ResourceAccess | Where-Object { $_.Type -ne 'Role' })
        }
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
