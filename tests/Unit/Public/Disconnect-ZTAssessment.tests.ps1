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

Describe 'Disconnect-ZTAssessment' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:dscModuleName -CommandName Write-ToLog -MockWith { }
    }

    Context 'When a session exists' {
        It 'Should call the disconnect wrapper exactly once' {
            Mock -ModuleName $script:dscModuleName -CommandName Disconnect-MgGraphWrapper -MockWith { }

            Disconnect-ZTAssessment

            Should -Invoke -ModuleName $script:dscModuleName -CommandName Disconnect-MgGraphWrapper -Times 1 -Exactly
        }

        It 'Should clear the cached connection summary' {
            Mock -ModuleName $script:dscModuleName -CommandName Disconnect-MgGraphWrapper -MockWith { }

            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessConnection = [pscustomobject]@{ TenantId = 'cached' }
            }

            Disconnect-ZTAssessment

            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessConnection | Should -BeNullOrEmpty
            }
        }
    }

    Context 'When no session exists or disconnection fails' {
        It 'Should warn rather than throw' {
            Mock -ModuleName $script:dscModuleName -CommandName Disconnect-MgGraphWrapper -MockWith {
                throw 'No application to sign out from.'
            }

            { Disconnect-ZTAssessment -WarningVariable disconnectWarnings -WarningAction SilentlyContinue } |
                Should -Not -Throw
        }

        It 'Should still clear the cached connection summary on failure' {
            Mock -ModuleName $script:dscModuleName -CommandName Disconnect-MgGraphWrapper -MockWith {
                throw 'No application to sign out from.'
            }

            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessConnection = [pscustomobject]@{ TenantId = 'cached' }
            }

            Disconnect-ZTAssessment -WarningAction SilentlyContinue

            InModuleScope -ModuleName $script:dscModuleName {
                $script:ZTAssessConnection | Should -BeNullOrEmpty
            }
        }
    }
}
