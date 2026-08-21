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

    # A real, in-memory self-signed certificate for mocking Get-ZTAssessCertificate.
    # Connect-MgGraphWrapper types its -Certificate parameter as X509Certificate2, and
    # Pester enforces that type on the mocked command, so a pscustomobject will not
    # coerce. Generated with pure .NET so the test stays offline and cross-platform.
    $script:testRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=ZTAssessTest',
        $script:testRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $script:testCertificate = $certificateRequest.CreateSelfSigned(
        [System.DateTimeOffset]::Now.AddDays(-1),
        [System.DateTimeOffset]::Now.AddDays(1))
}

AfterAll {
    if ($script:testCertificate) { $script:testCertificate.Dispose() }
    if ($script:testRsa) { $script:testRsa.Dispose() }
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Connect-ZTAssessment' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -MockWith { }
        # Default to no resolved CBA config so the auto path falls back to
        # interactive delegated sign-in deterministically, regardless of any
        # ZTASSESS_* environment variables or ~/.ztassess/auth.json on the host.
        Mock -ModuleName $script:dscModuleName -CommandName Resolve-ZTAssessAuthConfig -MockWith { $null }
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

    Context 'When auto mode resolves a certificate-based configuration' {
        BeforeEach {
            Mock -ModuleName $script:dscModuleName -CommandName Resolve-ZTAssessAuthConfig -MockWith {
                [pscustomobject]@{
                    TenantId              = '22222222-2222-2222-2222-222222222222'
                    ClientId              = '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3'
                    CertificateThumbprint = 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'
                    CertificatePath       = $null
                    Environment           = 'Global'
                    Source                = 'Environment'
                }
            }
        }

        It 'Should connect app-only using the resolved client ID and thumbprint' {
            $result = Connect-ZTAssessment -Modules Identity

            $result.AuthMode | Should -Be 'AppOnly'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $ClientId -eq '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -and
                $CertificateThumbprint -eq 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0' -and
                -not $Scopes
            }
        }

        It 'Should not warn about missing scopes for app-only authentication' {
            Mock -ModuleName $script:dscModuleName -CommandName Get-MgContextWrapper -MockWith {
                [pscustomobject]@{
                    TenantId = '22222222-2222-2222-2222-222222222222'
                    Account  = 'app-only'
                    Scopes   = @()
                }
            }

            $result = Connect-ZTAssessment -Modules Identity -WarningVariable connectionWarnings -WarningAction SilentlyContinue

            $result.AuthMode | Should -Be 'AppOnly'
            $connectionWarnings | Should -BeNullOrEmpty
        }
    }

    Context 'When auto mode resolves a PFX certificate path' {
        It 'Should load the certificate and connect app-only' {
            Mock -ModuleName $script:dscModuleName -CommandName Resolve-ZTAssessAuthConfig -MockWith {
                [pscustomobject]@{
                    TenantId              = '22222222-2222-2222-2222-222222222222'
                    ClientId              = '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3'
                    CertificateThumbprint = $null
                    CertificatePath       = '/tmp/ztassess.pfx'
                    Environment           = $null
                    Source                = 'File'
                }
            }
            Mock -ModuleName $script:dscModuleName -CommandName Get-ZTAssessCertificate -MockWith {
                $script:testCertificate
            }

            $result = Connect-ZTAssessment -Modules Identity

            $result.AuthMode | Should -Be 'AppOnly'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Get-ZTAssessCertificate -Times 1 -Exactly
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $ClientId -eq '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -and
                $null -ne $Certificate
            }
        }
    }

    Context 'When auto mode finds no configuration' {
        It 'Should fall back to interactive delegated sign-in' {
            $result = Connect-ZTAssessment -Modules Identity -WarningAction SilentlyContinue

            $result.AuthMode | Should -Be 'Delegated'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $Scopes -contains 'UserAuthenticationMethod.Read.All'
            }
        }

        It 'Should throw when interactive fallback is disabled' {
            { Connect-ZTAssessment -Modules Identity -NoInteractiveFallback -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*interactive fallback was disabled*'

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 0 -Exactly
        }
    }

    Context 'When explicit app-only certificate authentication is used' {
        It 'Should load the PFX and pass the certificate object to the connection' {
            Mock -ModuleName $script:dscModuleName -CommandName Get-ZTAssessCertificate -MockWith {
                $script:testCertificate
            }

            $result = Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificatePath (Join-Path $TestDrive 'client.pfx')

            $result.AuthMode | Should -Be 'AppOnly'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Get-ZTAssessCertificate -Times 1 -Exactly
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -Times 1 -Exactly -ParameterFilter {
                $null -ne $Certificate -and
                -not $CertificateThumbprint -and
                -not $Scopes
            }
        }
    }

    Context 'When a selected module requires Exchange Online / IPPS' {
        BeforeEach {
            Mock -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -MockWith { }
            Mock -ModuleName $script:dscModuleName -CommandName Get-MgContextWrapper -MockWith {
                [pscustomobject]@{
                    TenantId = '11111111-1111-1111-1111-111111111111'
                    Account  = 'app-only'
                    Scopes   = @()
                }
            }
        }

        It 'Should connect both surfaces in app-only mode using the same certificate' {
            $result = Connect-ZTAssessment -Modules ThreatProtection -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0' `
                -Organization 'contoso.onmicrosoft.com'

            $result.ExchangeOnlineConnected | Should -BeTrue
            $result.ExchangeOnlineWarning | Should -BeNullOrEmpty
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -Times 2 -Exactly -ParameterFilter {
                $Organization -eq 'contoso.onmicrosoft.com' -and $AppId -eq '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -and
                $CertificateThumbprint -eq 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'
            }
        }

        It 'Should skip Exchange Online / IPPS and warn for delegated sign-in' {
            $result = Connect-ZTAssessment -Modules ThreatProtection -WarningAction SilentlyContinue

            $result.ExchangeOnlineConnected | Should -BeFalse
            $result.ExchangeOnlineWarning | Should -Match 'app-only authentication'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -Times 0 -Exactly
        }

        It 'Should warn and leave ExchangeOnlineConnected false when no organization can be resolved' {
            Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessGraphRequest -MockWith {
                throw 'Graph unavailable.'
            }

            $result = Connect-ZTAssessment -Modules ThreatProtection -TenantId '11111111-1111-1111-1111-111111111111' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0' `
                -WarningAction SilentlyContinue

            $result.ExchangeOnlineConnected | Should -BeFalse
            $result.ExchangeOnlineWarning | Should -Match 'Could not resolve an Exchange Online organization'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -Times 0 -Exactly
        }

        It 'Should warn but not fail the overall connection when Exchange Online / IPPS fails to connect' {
            Mock -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -MockWith {
                throw 'Certificate not trusted by Exchange Online.'
            }

            $result = Connect-ZTAssessment -Modules ThreatProtection -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0' `
                -Organization 'contoso.onmicrosoft.com' `
                -WarningAction SilentlyContinue

            $result.AuthMode | Should -Be 'AppOnly'
            $result.ExchangeOnlineConnected | Should -BeFalse
            $result.ExchangeOnlineWarning | Should -Match 'Failed to connect to Exchange Online'
        }

        It 'Should not attempt Exchange Online / IPPS for modules that do not require it' {
            $null = Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' `
                -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' `
                -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -Times 0 -Exactly
        }

        It 'Should connect both surfaces via the device-code access-token bridge when Graph used -UseDeviceCode' {
            Mock -ModuleName $script:dscModuleName -CommandName Get-ZTAssessExchangeOnlineDeviceCodeToken -MockWith { 'device-code-token' }

            $result = Connect-ZTAssessment -Modules ThreatProtection -UseDeviceCode -Organization 'contoso.onmicrosoft.com'

            $result.AuthMode | Should -Be 'DeviceCode'
            $result.ExchangeOnlineConnected | Should -BeTrue
            $result.ExchangeOnlineWarning | Should -BeNullOrEmpty
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Get-ZTAssessExchangeOnlineDeviceCodeToken -Times 1 -Exactly
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -Times 2 -Exactly -ParameterFilter {
                $Organization -eq 'contoso.onmicrosoft.com' -and $AccessToken -eq 'device-code-token'
            }
        }

        It 'Should warn but not fail the overall connection when the device-code token request fails' {
            Mock -ModuleName $script:dscModuleName -CommandName Get-ZTAssessExchangeOnlineDeviceCodeToken -MockWith {
                throw 'Exchange Online device-code sign-in expired before the user completed authentication.'
            }

            $result = Connect-ZTAssessment -Modules ThreatProtection -UseDeviceCode -Organization 'contoso.onmicrosoft.com' -WarningAction SilentlyContinue

            $result.AuthMode | Should -Be 'DeviceCode'
            $result.ExchangeOnlineConnected | Should -BeFalse
            $result.ExchangeOnlineWarning | Should -Match 'device code'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnlineWrapper -Times 0 -Exactly
        }
    }

    Context 'When a resolved certificate configuration fails to connect' {
        It 'Should surface a terminating error rather than falling back silently' {
            Mock -ModuleName $script:dscModuleName -CommandName Resolve-ZTAssessAuthConfig -MockWith {
                [pscustomobject]@{
                    TenantId              = '22222222-2222-2222-2222-222222222222'
                    ClientId              = '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3'
                    CertificateThumbprint = 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'
                    CertificatePath       = $null
                    Environment           = 'Global'
                    Source                = 'Environment'
                }
            }
            Mock -ModuleName $script:dscModuleName -CommandName Connect-MgGraphWrapper -MockWith {
                throw 'Certificate not trusted.'
            }

            { Connect-ZTAssessment -Modules Identity -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*resolved certificate-based configuration*'
        }
    }
}
