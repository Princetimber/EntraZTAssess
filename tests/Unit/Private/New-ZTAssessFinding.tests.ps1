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

Describe 'New-ZTAssessFinding' -Tag 'Unit' {

    Context 'When creating findings from check definitions' {
        It 'Should merge the check metadata into the finding' {
            InModuleScope -ModuleName $script:dscModuleName {
                $finding = New-ZTAssessFinding -CheckId 'PA-001' -Status Fail -Evidence '7 Global Administrators.'

                $finding.Domain | Should -Be 'PrivilegedAccess'
                $finding.Title | Should -Not -BeNullOrEmpty
                $finding.Rationale | Should -Not -BeNullOrEmpty
                $finding.Remediation | Should -Not -BeNullOrEmpty
                $finding.ZeroTrustPillars | Should -Contain 'LeastPrivilege'
                $finding.References | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should apply the default severity on Fail' {
            InModuleScope -ModuleName $script:dscModuleName {
                (New-ZTAssessFinding -CheckId 'CA-001' -Status Fail).Severity | Should -Be 'Critical'
            }
        }

        It 'Should use severity None on Pass' {
            InModuleScope -ModuleName $script:dscModuleName {
                (New-ZTAssessFinding -CheckId 'CA-001' -Status Pass).Severity | Should -Be 'None'
            }
        }

        It 'Should honour a severity override (conditional escalation)' {
            InModuleScope -ModuleName $script:dscModuleName {
                (New-ZTAssessFinding -CheckId 'ID-003' -Status Fail -SeverityOverride Critical).Severity | Should -Be 'Critical'
            }
        }

        It 'Should require a reason for NotAssessed findings' {
            InModuleScope -ModuleName $script:dscModuleName {
                { New-ZTAssessFinding -CheckId 'CA-004' -Status NotAssessed } | Should -Throw -ExpectedMessage '*NotAssessedReason*'

                $finding = New-ZTAssessFinding -CheckId 'CA-004' -Status NotAssessed -NotAssessedReason 'Licence missing.'
                $finding.Status | Should -Be 'NotAssessed'
            }
        }

        It 'Should throw for an unknown check ID' {
            InModuleScope -ModuleName $script:dscModuleName {
                { New-ZTAssessFinding -CheckId 'XX-001' -Status Pass } | Should -Throw -ExpectedMessage '*Unknown check ID*'
            }
        }
    }
}
