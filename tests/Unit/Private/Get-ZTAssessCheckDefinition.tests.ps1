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

Describe 'Get-ZTAssessCheckDefinition' -Tag 'Unit' {

    Context 'When loading the shipped check library' {
        It 'Should load all 92 check definitions' {
            $checks = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessCheckDefinition -Force
            }

            $checks.Count | Should -Be 92
        }

        It 'Should expose the expected domains with the expected counts' {
            InModuleScope -ModuleName $script:dscModuleName {
                (Get-ZTAssessCheckDefinition -Domain 'IdentitySecurity').Count | Should -Be 12
                (Get-ZTAssessCheckDefinition -Domain 'ConditionalAccess').Count | Should -Be 13
                (Get-ZTAssessCheckDefinition -Domain 'PrivilegedAccess').Count | Should -Be 10
                (Get-ZTAssessCheckDefinition -Domain 'DeviceTrust').Count | Should -Be 4
                (Get-ZTAssessCheckDefinition -Domain 'EndpointManagement').Count | Should -Be 21
                (Get-ZTAssessCheckDefinition -Domain 'ByodGovernance').Count | Should -Be 4
                (Get-ZTAssessCheckDefinition -Domain 'CorporateDeviceGovernance').Count | Should -Be 3
            (Get-ZTAssessCheckDefinition -Domain 'IdentityGovernance').Count | Should -Be 6
            (Get-ZTAssessCheckDefinition -Domain 'ApplicationSecurity').Count | Should -Be 7
            (Get-ZTAssessCheckDefinition -Domain 'HybridIdentity').Count | Should -Be 6
            (Get-ZTAssessCheckDefinition -Domain 'MonitoringDetection').Count | Should -Be 6
            }
        }

        It 'Should return a single check by ID with the required metadata' {
            $check = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessCheckDefinition -CheckId 'CA-001'
            }

            $check.Domain | Should -Be 'ConditionalAccess'
            $check.DefaultSeverity | Should -Be 'Critical'
            $check.MaturityWeight | Should -Be 5
            $check.ZeroTrustPillars | Should -Contain 'VerifyExplicitly'
            $check.Remediation | Should -Not -BeNullOrEmpty
            $check.References | Should -Not -BeNullOrEmpty
        }

        It 'Should throw for an unknown check ID' {
            InModuleScope -ModuleName $script:dscModuleName {
                { Get-ZTAssessCheckDefinition -CheckId 'XX-999' } | Should -Throw -ExpectedMessage '*Unknown check ID*'
            }
        }

        It 'Should give every check a valid severity and weight' {
            InModuleScope -ModuleName $script:dscModuleName {
                foreach ($check in (Get-ZTAssessCheckDefinition).Values) {
                    $check.DefaultSeverity | Should -BeIn @('Critical', 'High', 'Medium', 'Low')
                    [double]$check.MaturityWeight | Should -BeGreaterOrEqual 1
                    [double]$check.MaturityWeight | Should -BeLessOrEqual 5
                }
            }
        }
    }
}
