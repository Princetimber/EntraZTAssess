#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    # Global stub so the wrapper's Get-Command precondition passes and Pester can
    # mock Connect-MgGraph without the real Microsoft.Graph.Authentication SDK.
    # It declares the parameters the wrapper splats so both the stub and the
    # generated mock bind them cleanly.
    function global:Connect-MgGraph {
        [CmdletBinding()]
        param($Environment, [switch]$NoWelcome, $TenantId, $ClientId, $Certificate,
            $CertificateThumbprint, $Scopes, [switch]$UseDeviceCode)
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
    Remove-Item Function:\Connect-MgGraph -ErrorAction SilentlyContinue
}

Describe 'Connect-MgGraphWrapper' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Connect-MgGraph -MockWith { }
    }

    It 'Should use the certificate object path (ClientId + Certificate) without scopes' {
        InModuleScope -ModuleName $script:dscModuleName {
            $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WrapperTest', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $cert = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))

            Connect-MgGraphWrapper -TenantId 'contoso' -ClientId 'app-1' -Certificate $cert -Environment 'Global'

            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
                $ClientId -eq 'app-1' -and $null -ne $Certificate -and $TenantId -eq 'contoso' -and
                $null -eq $Scopes -and $NoWelcome
            }
            $cert.Dispose()
        }
    }

    It 'Should use the Windows certificate-store path (ClientId + CertificateThumbprint) without scopes' {
        InModuleScope -ModuleName $script:dscModuleName {
            Connect-MgGraphWrapper -TenantId 'contoso' -ClientId 'app-1' -CertificateThumbprint 'ABC123'

            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
                $ClientId -eq 'app-1' -and $CertificateThumbprint -eq 'ABC123' -and $null -eq $Scopes
            }
        }
    }

    It 'Should use the delegated path (scopes + device code) when no certificate is supplied' {
        InModuleScope -ModuleName $script:dscModuleName {
            Connect-MgGraphWrapper -Scopes 'Directory.Read.All', 'Policy.Read.All' -UseDeviceCode

            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
                ($Scopes -contains 'Directory.Read.All') -and $UseDeviceCode -and
                $null -eq $CertificateThumbprint -and $null -eq $Certificate
            }
        }
    }
}
