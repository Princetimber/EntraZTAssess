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

Describe 'Get-ZTAssessExoAllowedCmdletName' -Tag 'Unit' {

    It 'Should return only Get-* cmdlet names' {
        InModuleScope -ModuleName $script:dscModuleName {
            $names = Get-ZTAssessExoAllowedCmdletName

            $names | Should -Not -BeNullOrEmpty
            foreach ($name in $names) {
                $name | Should -Match '^Get-'
            }
        }
    }

    It 'Should not contain duplicate entries' {
        InModuleScope -ModuleName $script:dscModuleName {
            $names = Get-ZTAssessExoAllowedCmdletName

            ($names | Select-Object -Unique).Count | Should -Be $names.Count
        }
    }
}
