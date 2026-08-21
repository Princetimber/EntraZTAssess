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

    It 'Should render (not discard) the output of Connect-MgGraph when using device code' {
        # Regression test: Connect-MgGraph's device-code prompt is silenced
        # on affected Microsoft.Graph.Authentication SDK versions whenever
        # its return value is DISCARDED before rendering - `$null = ...`
        # and `| Out-Null` both do this and were confirmed NOT to work -
        # https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/2798.
        # `| Out-Host` renders immediately at this call site and produces
        # no output of its own, so it neither discards the prompt nor lets
        # anything leak into this function's own return value. This
        # asserts the wrapper's source text uses that exact pattern in the
        # device-code branch, since a functional Pester mock can't observe
        # real console rendering.
        $wrapperSource = Get-Content -Raw -Path (Join-Path $PSScriptRoot '../../../source/Private/Connect-MgGraphWrapper.ps1')
        $wrapperSource | Should -Match '(?m)^\s{8}Connect-MgGraph @connectParameters \| Out-Host\s*$'
        $wrapperSource | Should -Not -Match '(?m)^\s{8}\$null = Connect-MgGraph @connectParameters \| Out-Null\s*$'
    }

    It 'Should still connect successfully when the device-code call is piped to Out-Host' {
        InModuleScope -ModuleName $script:dscModuleName {
            { Connect-MgGraphWrapper -Scopes 'Directory.Read.All' -UseDeviceCode } | Should -Not -Throw
        }
    }

    It 'Should not leak whatever Connect-MgGraph returns into its own output for the device-code path' {
        # Mocks a non-empty return (simulating an SDK version that emits an
        # auth-context-like object) to prove Out-Host actually consumes it,
        # rather than trivially passing because the mock returned nothing.
        Mock -ModuleName $script:dscModuleName -CommandName Connect-MgGraph -MockWith {
            [pscustomobject]@{ TenantId = 'contoso' }
        }

        InModuleScope -ModuleName $script:dscModuleName {
            $result = Connect-MgGraphWrapper -Scopes 'Directory.Read.All' -UseDeviceCode
            $result | Should -BeNullOrEmpty
        }
    }
}
