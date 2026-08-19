#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    function global:Disconnect-ExchangeOnline {
        [CmdletBinding()]
        param([switch]$Confirm)
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
    Remove-Item Function:\Disconnect-ExchangeOnline -ErrorAction SilentlyContinue
}

Describe 'Disconnect-ExchangeOnlineWrapper' -Tag 'Unit' {

    It 'Should call Disconnect-ExchangeOnline without prompting for confirmation' {
        Mock -ModuleName $script:dscModuleName -CommandName Disconnect-ExchangeOnline -MockWith { }

        InModuleScope -ModuleName $script:dscModuleName {
            Disconnect-ExchangeOnlineWrapper

            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly
        }
    }

    It 'Should throw an actionable error when ExchangeOnlineManagement is not available' {
        Mock -ModuleName $script:dscModuleName -CommandName Get-Command -MockWith { $null } -ParameterFilter {
            $Name -eq 'Disconnect-ExchangeOnline'
        }

        InModuleScope -ModuleName $script:dscModuleName {
            { Disconnect-ExchangeOnlineWrapper } | Should -Throw -ExpectedMessage '*ExchangeOnlineManagement module is required*'
        }
    }
}
