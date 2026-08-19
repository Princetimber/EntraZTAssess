#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    # Global stubs so the wrapper's Get-Command precondition passes and
    # Pester can mock Connect-ExchangeOnline/Connect-IPPSSession without the
    # real ExchangeOnlineManagement module installed.
    function global:Connect-ExchangeOnline {
        [CmdletBinding()]
        param($Organization, $AppId, $Certificate, $CertificateThumbprint, $CommandName, [switch]$ShowBanner)
    }
    function global:Connect-IPPSSession {
        [CmdletBinding()]
        param($Organization, $AppId, $Certificate, $CertificateThumbprint, $CommandName, [switch]$ShowBanner)
    }

    if (Get-Module -ListAvailable -Name $script:dscModuleName -ErrorAction SilentlyContinue) {
        Import-Module -Name $script:dscModuleName -Force
    }
    else {
        Import-Module -Name (Join-Path $PSScriptRoot '../../../source/Get-EntraZTAssess.psd1') -Force
    }
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
    Remove-Item Function:\Connect-ExchangeOnline -ErrorAction SilentlyContinue
    Remove-Item Function:\Connect-IPPSSession -ErrorAction SilentlyContinue
}

Describe 'Connect-ExchangeOnlineWrapper' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Connect-ExchangeOnline -MockWith { }
        Mock -ModuleName $script:dscModuleName -CommandName Connect-IPPSSession -MockWith { }
    }

    It 'Should connect to Exchange Online with a certificate thumbprint' {
        InModuleScope -ModuleName $script:dscModuleName {
            Connect-ExchangeOnlineWrapper -Surface ExchangeOnline -Organization 'contoso.onmicrosoft.com' `
                -AppId 'app-1' -CertificateThumbprint 'ABC123'

            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $Organization -eq 'contoso.onmicrosoft.com' -and $AppId -eq 'app-1' -and
                $CertificateThumbprint -eq 'ABC123' -and $ShowBanner -eq $false
            }
            Should -Invoke Connect-IPPSSession -Times 0 -Exactly
        }
    }

    It 'Should connect to IPPS with a certificate object' {
        InModuleScope -ModuleName $script:dscModuleName {
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=ExoWrapperTest', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $cert = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))

            Connect-ExchangeOnlineWrapper -Surface IPPS -Organization 'contoso.onmicrosoft.com' `
                -AppId 'app-1' -Certificate $cert

            Should -Invoke Connect-IPPSSession -Times 1 -Exactly -ParameterFilter {
                $null -ne $Certificate -and $AppId -eq 'app-1'
            }
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
            $cert.Dispose()
        }
    }

    It 'Should restrict the imported session to the read-only allow-list' {
        InModuleScope -ModuleName $script:dscModuleName {
            Connect-ExchangeOnlineWrapper -Surface ExchangeOnline -Organization 'contoso.onmicrosoft.com' `
                -AppId 'app-1' -CertificateThumbprint 'ABC123'

            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                ($CommandName -contains 'Get-SafeLinksPolicy') -and
                ($CommandName -notcontains 'Set-SafeLinksPolicy')
            }
        }
    }

    It 'Should throw when neither a certificate nor a thumbprint is supplied' {
        InModuleScope -ModuleName $script:dscModuleName {
            { Connect-ExchangeOnlineWrapper -Surface ExchangeOnline -Organization 'contoso.onmicrosoft.com' -AppId 'app-1' } |
                Should -Throw -ExpectedMessage '*Either -Certificate or -CertificateThumbprint*'
        }
    }
}
