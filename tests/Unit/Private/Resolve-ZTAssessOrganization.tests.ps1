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

Describe 'Resolve-ZTAssessOrganization' -Tag 'Unit' {

    BeforeEach {
        Remove-Item Env:\ZTASSESS_ORGANIZATION -ErrorAction SilentlyContinue
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
    }

    AfterEach {
        Remove-Item Env:\ZTASSESS_ORGANIZATION -ErrorAction SilentlyContinue
    }

    It 'Should prefer the explicit -Organization parameter' {
        InModuleScope -ModuleName $script:dscModuleName {
            $result = Resolve-ZTAssessOrganization -Organization 'explicit.onmicrosoft.com' -TenantId 'contoso.onmicrosoft.com'

            $result | Should -Be 'explicit.onmicrosoft.com'
        }
    }

    It 'Should fall back to the ZTASSESS_ORGANIZATION environment variable' {
        $env:ZTASSESS_ORGANIZATION = 'env.onmicrosoft.com'

        InModuleScope -ModuleName $script:dscModuleName {
            $result = Resolve-ZTAssessOrganization -TenantId '11111111-1111-1111-1111-111111111111'

            $result | Should -Be 'env.onmicrosoft.com'
        }
    }

    It 'Should fall back to the resolved auth config Organization value' {
        InModuleScope -ModuleName $script:dscModuleName {
            $authConfig = [pscustomobject]@{ Organization = 'authconfig.onmicrosoft.com' }
            $result = Resolve-ZTAssessOrganization -AuthConfig $authConfig -TenantId '11111111-1111-1111-1111-111111111111'

            $result | Should -Be 'authconfig.onmicrosoft.com'
        }
    }

    It 'Should use a domain-looking TenantId as-is' {
        InModuleScope -ModuleName $script:dscModuleName {
            $result = Resolve-ZTAssessOrganization -TenantId 'contoso.onmicrosoft.com'

            $result | Should -Be 'contoso.onmicrosoft.com'
        }
    }

    It 'Should not treat a GUID TenantId as a domain' {
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessGraphRequest -MockWith {
            [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @([pscustomobject]@{ name = 'derived.onmicrosoft.com'; isInitial = $true }) }) }
        }

        InModuleScope -ModuleName $script:dscModuleName {
            $result = Resolve-ZTAssessOrganization -TenantId '11111111-1111-1111-1111-111111111111'

            $result | Should -Be 'derived.onmicrosoft.com'
        }
    }

    It 'Should derive the organization from the Graph tenant''s initial verified domain when nothing else resolves' {
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessGraphRequest -MockWith {
            [pscustomobject]@{
                value = @([pscustomobject]@{
                        verifiedDomains = @(
                            [pscustomobject]@{ name = 'other.onmicrosoft.com'; isInitial = $false }
                            [pscustomobject]@{ name = 'derived.onmicrosoft.com'; isInitial = $true }
                        )
                    })
            }
        }

        InModuleScope -ModuleName $script:dscModuleName {
            $result = Resolve-ZTAssessOrganization

            $result | Should -Be 'derived.onmicrosoft.com'
        }
    }

    It 'Should return null when nothing can be resolved' {
        Mock -ModuleName $script:dscModuleName -CommandName Invoke-ZTAssessGraphRequest -MockWith {
            throw 'Graph unavailable.'
        }

        InModuleScope -ModuleName $script:dscModuleName {
            $result = Resolve-ZTAssessOrganization

            $result | Should -BeNullOrEmpty
        }
    }
}
