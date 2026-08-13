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
    function global:Get-MgApplication { [CmdletBinding()] param($Filter) }
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
    Remove-Item Function:\Connect-MgGraph, Function:\Get-MgApplication, Function:\Get-MgServicePrincipal, `
        Function:\New-MgApplication, `
        Function:\New-MgServicePrincipal, `
        Function:\New-MgServicePrincipalAppRoleAssignment -ErrorAction SilentlyContinue
    Remove-Item Env:\ZTPROV_TEST_PERMISSIONS -ErrorAction SilentlyContinue
}

Describe 'New-ZTAssessAppRegistration' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:provModuleName Connect-MgGraph { }
        Mock -ModuleName $script:provModuleName Get-MgApplication { $null }
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
            -CertificatePath $script:cerPath -Modules 'Identity' -ConfigOutputPath $configPath -Confirm:$false

        $result.PSObject.TypeNames | Should -Contain 'ZTAssess.AppRegistration'
        $result.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 1
    }

    It 'Should write a non-secret config with no password field' {
        $configPath = Join-Path $TestDrive 'auth2.json'
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -ConfigOutputPath $configPath -Confirm:$false

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
            -ConfigOutputPath (Join-Path $TestDrive 'auth-consent.json') -GrantAdminConsent -Confirm:$false

        Should -Invoke -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment -Times $expected -Exactly
    }

    It 'Should not create app-role assignments without -GrantAdminConsent' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-noconsent.json') -Confirm:$false

        Should -Invoke -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment -Times 0 -Exactly
    }

    It 'Should resolve the default module set when -Modules is omitted' {
        $configPath = Join-Path $TestDrive 'auth-default.json'
        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -ConfigOutputPath $configPath -Confirm:$false

        $result.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 1
    }

    It 'Should pass only read-only application (Role) resource access to New-MgApplication' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-payload.json') -Confirm:$false

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

    It 'Should only request Application.ReadWrite.All when -GrantAdminConsent is not supplied' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-scopes-default.json') -Confirm:$false

        Should -Invoke -ModuleName $script:provModuleName Connect-MgGraph -Times 1 -ParameterFilter {
            @($Scopes) -contains 'Application.ReadWrite.All' -and
            @($Scopes) -notcontains 'AppRoleAssignment.ReadWrite.All' -and
            @($Scopes) -notcontains 'Directory.Read.All'
        }
    }

    It 'Should additionally request AppRoleAssignment.ReadWrite.All when -GrantAdminConsent is supplied' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -GrantAdminConsent `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-scopes-consent.json') -Confirm:$false

        Should -Invoke -ModuleName $script:provModuleName Connect-MgGraph -Times 1 -ParameterFilter {
            @($Scopes) -contains 'Application.ReadWrite.All' -and
            @($Scopes) -contains 'AppRoleAssignment.ReadWrite.All'
        }
    }

    It 'Should throw naming the existing AppId when an application with the same DisplayName already exists' {
        Mock -ModuleName $script:provModuleName Get-MgApplication {
            [pscustomobject]@{ AppId = '99999999-9999-9999-9999-999999999999'; DisplayName = 'EntraZTAssess-Assessment' }
        }

        { New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-dup.json') -Confirm:$false } |
            Should -Throw -ExpectedMessage '*99999999-9999-9999-9999-999999999999*'

        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 0
    }

    It 'Should create a new application when -Force is supplied despite an existing DisplayName match' {
        Mock -ModuleName $script:provModuleName Get-MgApplication {
            [pscustomobject]@{ AppId = '99999999-9999-9999-9999-999999999999'; DisplayName = 'EntraZTAssess-Assessment' }
        }

        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -Force `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-force.json') -Confirm:$false

        $result.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 1
    }

    It 'Should not connect to Microsoft Graph under -WhatIf' {
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-whatif.json') -WhatIf

        Should -Invoke -ModuleName $script:provModuleName Connect-MgGraph -Times 0
        Should -Invoke -ModuleName $script:provModuleName New-MgApplication -Times 0
    }

    It 'Should record a failed grant in FailedGrants without throwing' {
        Mock -ModuleName $script:provModuleName New-MgServicePrincipalAppRoleAssignment { throw 'Insufficient privileges' }

        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -GrantAdminConsent `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-failedgrants.json') -Confirm:$false

        $result.FailedGrants.Count | Should -BeGreaterThan 0
        $result.FailedGrants[0].Error | Should -BeLike '*Insufficient privileges*'
    }

    It 'Should throw when TenantId is not a GUID or a domain name' {
        { New-ZTAssessAppRegistration -TenantId 'not a tenant' `
            -CertificatePath $script:cerPath -Modules 'Identity' } |
            Should -Throw
    }

    It 'Should warn and skip scopes with no matching Application app role' {
        Mock -ModuleName $script:provModuleName Get-MgServicePrincipal {
            # Only the Core module's first scope resolves; every other requested
            # scope is left unmatched and should be warned about, not fail the run.
            $cat = Import-PowerShellDataFile -Path $env:ZTPROV_TEST_PERMISSIONS
            $matchedScope = $cat.Modules['Core'].Scopes | Select-Object -First 1
            $roles = @([pscustomobject]@{ Value = $matchedScope; Id = [guid]::NewGuid().ToString(); AllowedMemberTypes = @('Application') })
            [pscustomobject]@{ Id = [guid]::NewGuid().ToString(); AppRoles = $roles }
        }

        $warnings = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-unmatched.json') -Confirm:$false `
            -WarningVariable warnOutput -WarningAction SilentlyContinue

        $warnOutput | Should -Not -BeNullOrEmpty
        ($warnOutput -join ' ') | Should -BeLike '*No matching Application app role*'
    }

    It 'Should throw when no scopes resolve to an Application app role' {
        Mock -ModuleName $script:provModuleName Get-MgServicePrincipal {
            [pscustomobject]@{ Id = [guid]::NewGuid().ToString(); AppRoles = @() }
        }

        { New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-nomatch.json') -Confirm:$false -WarningAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*No application app roles could be resolved*'
    }

    It 'Should prefer a sibling .pfx over the .cer for the recorded ConfigCertificatePath' {
        $outDir = Join-Path $TestDrive 'pfx-sibling'
        $null = New-Item -Path $outDir -ItemType Directory -Force
        $cerPath = Join-Path $outDir 'sibling.cer'
        $pfxPath = Join-Path $outDir 'sibling.pfx'
        Copy-Item -LiteralPath $script:cerPath -Destination $cerPath
        Set-Content -LiteralPath $pfxPath -Value 'placeholder-pfx-bytes'

        $configPath = Join-Path $TestDrive 'auth-pfx-sibling.json'
        New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $cerPath -Modules 'Identity' -ConfigOutputPath $configPath -Confirm:$false

        $json = Get-Content -Raw -Path $configPath | ConvertFrom-Json
        $json.CertificatePath | Should -Be $pfxPath
    }

    It 'Should emit a USGov admin-consent host when -Environment USGov is supplied' {
        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -Environment 'USGov' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-usgov.json') -Confirm:$false

        $result.ConsentUrl | Should -BeLike 'https://login.microsoftonline.us/*'
    }

    It 'Should emit a China admin-consent host when -Environment China is supplied' {
        $result = New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' `
            -CertificatePath $script:cerPath -Modules 'Identity' -Environment 'China' `
            -ConfigOutputPath (Join-Path $TestDrive 'auth-china.json') -Confirm:$false

        $result.ConsentUrl | Should -BeLike 'https://login.partner.microsoftonline.cn/*'
    }
}
