#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    function global:Get-SafeLinksPolicy {
        [CmdletBinding()]
        param([string]$Identity)
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
    Remove-Item Function:\Get-SafeLinksPolicy -ErrorAction SilentlyContinue
}

Describe 'Invoke-ZTAssessExoRequestWrapper' -Tag 'Unit' {

    It 'Should dispatch an allow-listed cmdlet and return its output' {
        Mock -ModuleName $script:dscModuleName -CommandName Get-SafeLinksPolicy -MockWith {
            [pscustomobject]@{ Name = 'Default' }
        }

        InModuleScope -ModuleName $script:dscModuleName {
            $result = Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-SafeLinksPolicy'

            $result.Name | Should -Be 'Default'
            Should -Invoke Get-SafeLinksPolicy -Times 1 -Exactly
        }
    }

    It 'Should pass through -Parameters to the dispatched cmdlet' {
        Mock -ModuleName $script:dscModuleName -CommandName Get-SafeLinksPolicy -MockWith { }

        InModuleScope -ModuleName $script:dscModuleName {
            Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-SafeLinksPolicy' -Parameters @{ Identity = 'Default' }

            Should -Invoke Get-SafeLinksPolicy -Times 1 -Exactly -ParameterFilter { $Identity -eq 'Default' }
        }
    }

    It 'Should reject a cmdlet name that is not on the allow-list' {
        InModuleScope -ModuleName $script:dscModuleName {
            { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Set-SafeLinksPolicy' } | Should -Throw
        }
    }

    It 'Should throw an actionable error when the allow-listed cmdlet is not available' {
        InModuleScope -ModuleName $script:dscModuleName {
            { Invoke-ZTAssessExoRequestWrapper -CmdletName 'Get-DlpCompliancePolicy' } |
                Should -Throw -ExpectedMessage '*is not available*'
        }
    }
}
