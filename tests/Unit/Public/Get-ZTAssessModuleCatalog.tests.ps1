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

Describe 'Get-ZTAssessModuleCatalog' -Tag 'Unit' {

    Context 'When called without parameters' {
        It 'Should return every module in the catalogue' {
            $result = Get-ZTAssessModuleCatalog

            $result.Count | Should -BeGreaterOrEqual 10
            $result.Name | Should -Contain 'Core'
            $result.Name | Should -Contain 'Identity'
            $result.Name | Should -Contain 'Devices'
            $result.Name | Should -Contain 'Sentinel'
        }

        It 'Should mark Core as always included' {
            $core = Get-ZTAssessModuleCatalog | Where-Object Name -eq 'Core'

            $core.AlwaysIncluded | Should -BeTrue
            $core.Optional | Should -BeFalse
        }

        It 'Should mark Sentinel as optional' {
            $sentinel = Get-ZTAssessModuleCatalog | Where-Object Name -eq 'Sentinel'

            $sentinel.Optional | Should -BeTrue
        }

        It 'Should return only read-only Graph scopes' {
            $allScopes = (Get-ZTAssessModuleCatalog).Scopes | Where-Object { $_ }

            foreach ($scope in $allScopes) {
                $scope | Should -Match '\.Read\.' -Because "scope '$scope' must be read-only"
            }
        }

        It 'Should include a description for every module' {
            foreach ($entry in (Get-ZTAssessModuleCatalog)) {
                $entry.Description | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'When filtering by name' {
        It 'Should return only the requested modules' {
            $result = Get-ZTAssessModuleCatalog -Name Identity, Devices

            $result.Count | Should -Be 2
            $result.Name | Should -Contain 'Identity'
            $result.Name | Should -Contain 'Devices'
        }

        It 'Should throw for unknown module names' {
            { Get-ZTAssessModuleCatalog -Name 'NoSuchModule' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*Unknown module name*'
        }
    }
}
