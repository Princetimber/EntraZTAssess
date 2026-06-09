#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    <#
        Prefer an installed or built module; fall back to the source manifest
        so bare Invoke-Pester works without a prior build or PSModulePath
        registration.
    #>
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

Describe 'Connect-ZTAssessment' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Get-MgContextWrapper -MockWith {
            [pscustomobject]@{
                TenantId = '11111111-1111-1111-1111-111111111111'
                Account  = 'consultant@contoso.com'
                Scopes   = @(
                    'Organization.Read.All'
                    'Directory.Read.All'
                    'UserAuthenticationMethod.Read.All'
                    'Reports.Read.All'
                    'Policy.Read.All'
                    'AuditLog.Read.All'
                )
            }
        }
    }

    Context 'When connecting with delegated authentication' {
        It 'Should request only the least-privilege scopes for the selected modules' {
            $null = Connect-ZTAssessment -Modules Identity -WarningAction SilentlyContinue

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $Scopes -contains 'UserAuthenticationMethod.Read.All' -and
                $Scopes -notcontains 'DeviceManagementManagedDevices.Read.All'
            }
        }

        It 'Should return a connection summary with the expected auth mode' {
            $result = Connect-ZTAssessment -Modules Identity -WarningAction SilentlyContinue

            $result.AuthMode | Should -Be 'Delegated'
            $result.TenantId | Should -Be '11111111-1111-1111-1111-111111111111'
            $result.Account | Should -Be 'consultant@contoso.com'
            $result.Modules | Should -Contain 'Identity'
        }

        It 'Should report no missing scopes when everything was granted' {
            $result = Connect-ZTAssessment -Modules Identity

            $result.MissingScopes | Should -BeNullOrEmpty
        }

        It 'Should warn and list missing scopes when the tenant grants fewer scopes' {
            Mock -ModuleName $script:dscModuleName -CommandName Get-MgContextWrapper -MockWith {
                [pscustomobject]@{
                    TenantId = '11111111-1111-1111-1111-111111111111'
                    Account  = 'consultant@contoso.com'
                    Scopes   = @('Organization.Read.All', 'Directory.Read.All')
                }
            }

            $result = Connect-ZTAssessment -Modules Identity -WarningVariable connectionWarnings -WarningAction SilentlyContinue

            $result.MissingScopes | Should -Contain 'UserAuthenticationMethod.Read.All'
            $connectionWarnings | Should -Not -BeNullOrEmpty
        }

        It 'Should use the device code flow when requested' {
            $null = Connect-ZTAssessment -Modules Identity -UseDeviceCode -WarningAction SilentlyContinue

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $UseDeviceCode -eq $true
            }
        }

        It 'Should report DeviceCode as the auth mode when using device code flow' {
            $result = Connect-ZTAssessment -Modules Identity -UseDeviceCode

            $result.AuthMode | Should -Be 'DeviceCode'
        }
    }

    Context 'When connecting with app-only certificate authentication' {
        It 'Should pass client ID and certificate thumbprint without scopes' {
            $null = Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $ClientId -eq '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -and
                $CertificateThumbprint -eq 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0' -and
                -not $Scopes
            }
        }

        It 'Should report AppOnly as the auth mode' {
            $result = Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'

            $result.AuthMode | Should -Be 'AppOnly'
        }

        It 'Should reject an invalid client ID format' {
            {
                Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' `
                    -ClientId 'not-a-guid' `
                    -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'
            } | Should -Throw
        }

        It 'Should reject an invalid certificate thumbprint format' {
            {
                Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' `
                    -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                    -CertificateThumbprint 'short'
            } | Should -Throw
        }
    }

    Context 'When the connection fails' {
        It 'Should surface a terminating connection error' {
            Mock -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -MockWith {
                throw 'Authentication cancelled.'
            }

            { Connect-ZTAssessment -Modules Identity -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*Failed to connect to Microsoft Graph*'
        }

        It 'Should fail when no Graph context exists after connecting' {
            Mock -ModuleName $script:dscModuleName -CommandName Get-MgContextWrapper -MockWith { $null }

            { Connect-ZTAssessment -Modules Identity -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*no Microsoft Graph context*'
        }
    }

    Context 'When invalid modules are selected' {
        It 'Should throw before attempting any connection' {
            { Connect-ZTAssessment -Modules 'NoSuchModule' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*Unknown module name*'

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 0 -Exactly
        }
    }
}
