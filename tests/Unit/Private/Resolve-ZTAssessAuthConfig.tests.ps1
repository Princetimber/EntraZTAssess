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

    $script:authEnvNames = @(
        'ZTASSESS_TENANTID'
        'ZTASSESS_CLIENTID'
        'ZTASSESS_CERT_THUMBPRINT'
        'ZTASSESS_CERT_PATH'
        'ZTASSESS_ENVIRONMENT'
        'ZTASSESS_ORGANIZATION'
    )

    # Preserve any pre-existing values so the developer's environment is intact.
    $script:originalAuthEnv = @{}
    foreach ($name in $script:authEnvNames) {
        $script:originalAuthEnv[$name] = [System.Environment]::GetEnvironmentVariable($name)
    }
}

AfterAll {
    foreach ($name in $script:authEnvNames) {
        [System.Environment]::SetEnvironmentVariable($name, $script:originalAuthEnv[$name])
    }

    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Resolve-ZTAssessAuthConfig' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }

        # Start every test from a clean environment.
        foreach ($name in $script:authEnvNames) {
            Set-Item -Path "Env:$name" -Value '' -ErrorAction SilentlyContinue
            Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
        }
    }

    Context 'When no environment variables and no config file are present' {
        It 'Should return null' {
            $missingPath = Join-Path $TestDrive 'no-such-auth.json'

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $missingPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result | Should -BeNullOrEmpty
        }
    }

    Context 'When a complete config file is present' {
        It 'Should resolve TenantId, ClientId, and the certificate reference' {
            $configPath = Join-Path $TestDrive 'auth.json'
            @{
                TenantId              = 'file-tenant'
                ClientId              = 'file-client'
                CertificateThumbprint = 'FILETHUMBPRINT'
                Environment           = 'USGov'
            } | ConvertTo-Json | Set-Content -Path $configPath

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $configPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result | Should -Not -BeNullOrEmpty
            $result.TenantId | Should -Be 'file-tenant'
            $result.ClientId | Should -Be 'file-client'
            $result.CertificateThumbprint | Should -Be 'FILETHUMBPRINT'
            $result.Environment | Should -Be 'USGov'
            $result.Source | Should -Match 'File'
        }
    }

    Context 'When environment variables and a config file are both present' {
        It 'Should let environment variables override file values' {
            $configPath = Join-Path $TestDrive 'auth.json'
            @{
                TenantId              = 'file-tenant'
                ClientId              = 'file-client'
                CertificateThumbprint = 'FILETHUMBPRINT'
            } | ConvertTo-Json | Set-Content -Path $configPath

            $env:ZTASSESS_TENANTID = 'env-tenant'
            $env:ZTASSESS_CLIENTID = 'env-client'

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $configPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result.TenantId | Should -Be 'env-tenant'
            $result.ClientId | Should -Be 'env-client'
            $result.CertificateThumbprint | Should -Be 'FILETHUMBPRINT'
            $result.Source | Should -Match 'Environment'
        }
    }

    Context 'When configuration comes only from environment variables' {
        It 'Should resolve using the certificate path from the environment' {
            $env:ZTASSESS_TENANTID = 'env-tenant'
            $env:ZTASSESS_CLIENTID = 'env-client'
            $env:ZTASSESS_CERT_PATH = '/tmp/env.pfx'

            $missingPath = Join-Path $TestDrive 'no-such-auth.json'

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $missingPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result | Should -Not -BeNullOrEmpty
            $result.CertificatePath | Should -Be '/tmp/env.pfx'
            $result.Source | Should -Be 'Environment'
        }
    }

    Context 'When the resolved configuration is incomplete' {
        It 'Should return null when no certificate reference is present' {
            $env:ZTASSESS_TENANTID = 'env-tenant'
            $env:ZTASSESS_CLIENTID = 'env-client'

            $missingPath = Join-Path $TestDrive 'no-such-auth.json'

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $missingPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result | Should -BeNullOrEmpty
        }
    }

    Context 'When Organization is supplied' {
        It 'Should let the environment variable override the file value' {
            $configPath = Join-Path $TestDrive 'auth.json'
            @{
                TenantId              = 'file-tenant'
                ClientId              = 'file-client'
                CertificateThumbprint = 'FILETHUMBPRINT'
                Organization          = 'file.onmicrosoft.com'
            } | ConvertTo-Json | Set-Content -Path $configPath

            $env:ZTASSESS_ORGANIZATION = 'env.onmicrosoft.com'

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $configPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result.Organization | Should -Be 'env.onmicrosoft.com'
        }

        It 'Should resolve Organization from the file when no environment variable is set' {
            $configPath = Join-Path $TestDrive 'auth.json'
            @{
                TenantId              = 'file-tenant'
                ClientId              = 'file-client'
                CertificateThumbprint = 'FILETHUMBPRINT'
                Organization          = 'file.onmicrosoft.com'
            } | ConvertTo-Json | Set-Content -Path $configPath

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $configPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result.Organization | Should -Be 'file.onmicrosoft.com'
        }
    }

    Context 'When the config file is malformed' {
        It 'Should warn and not throw, falling back to environment values' {
            $configPath = Join-Path $TestDrive 'bad-auth.json'
            Set-Content -Path $configPath -Value '{ this is not valid json '

            $env:ZTASSESS_TENANTID = 'env-tenant'
            $env:ZTASSESS_CLIENTID = 'env-client'
            $env:ZTASSESS_CERT_THUMBPRINT = 'ENVTHUMBPRINT'

            $result = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ Path = $configPath } {
                param($Path)
                Resolve-ZTAssessAuthConfig -ConfigPath $Path
            }

            $result | Should -Not -BeNullOrEmpty
            $result.TenantId | Should -Be 'env-tenant'
            $result.CertificateThumbprint | Should -Be 'ENVTHUMBPRINT'
            Should -Invoke -ModuleName $script:dscModuleName -CommandName Write-ToLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'WARN'
            }
        }
    }
}
