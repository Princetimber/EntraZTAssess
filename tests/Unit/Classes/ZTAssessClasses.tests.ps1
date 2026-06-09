#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    Import-Module -Name $script:dscModuleName
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'ZTAssessFinding' -Tag 'Unit' {

    Context 'When constructing a finding' {
        It 'Should default the maturity weight to 3' {
            InModuleScope -ModuleName $script:dscModuleName {
                ([ZTAssessFinding]::new()).MaturityWeight | Should -Be 3
            }
        }

        It 'Should validate a well-formed finding without problems' {
            InModuleScope -ModuleName $script:dscModuleName {
                $finding = [ZTAssessFinding]::new()
                $finding.CheckId = 'ID-001'
                $finding.Domain = 'IdentitySecurity'
                $finding.Title = 'MFA registration coverage'
                $finding.Status = 'Pass'
                $finding.Severity = 'None'
                $finding.ZeroTrustPillars = @('VerifyExplicitly')

                $finding.Validate() | Should -BeNullOrEmpty
            }
        }

        It 'Should report problems for an invalid status and severity' {
            InModuleScope -ModuleName $script:dscModuleName {
                $finding = [ZTAssessFinding]::new()
                $finding.CheckId = 'ID-001'
                $finding.Domain = 'IdentitySecurity'
                $finding.Status = 'Maybe'
                $finding.Severity = 'Catastrophic'

                $problems = $finding.Validate()

                $problems | Should -Not -BeNullOrEmpty
                ($problems -join ' ') | Should -Match 'Status'
                ($problems -join ' ') | Should -Match 'Severity'
            }
        }

        It 'Should require a reason when the status is NotAssessed' {
            InModuleScope -ModuleName $script:dscModuleName {
                $finding = [ZTAssessFinding]::new()
                $finding.CheckId = 'CA-001'
                $finding.Domain = 'ConditionalAccess'
                $finding.Status = 'NotAssessed'
                $finding.Severity = 'None'

                ($finding.Validate() -join ' ') | Should -Match 'NotAssessedReason'
            }
        }

        It 'Should reject an unknown Zero Trust pillar' {
            InModuleScope -ModuleName $script:dscModuleName {
                $finding = [ZTAssessFinding]::new()
                $finding.CheckId = 'PA-001'
                $finding.Domain = 'PrivilegedAccess'
                $finding.Status = 'Fail'
                $finding.Severity = 'High'
                $finding.ZeroTrustPillars = @('TrustEveryone')

                ($finding.Validate() -join ' ') | Should -Match 'ZeroTrustPillar'
            }
        }
    }
}

Describe 'ZTAssessPlatformProfile' -Tag 'Unit' {

    Context 'When constructing a platform profile' {
        It 'Should default coverage values to -1 (NotAssessed) and risk to NotAssessed' {
            InModuleScope -ModuleName $script:dscModuleName {
                $profile = [ZTAssessPlatformProfile]::new()

                $profile.CompliancePolicyCoveragePercent | Should -Be -1
                $profile.AppProtectionCoveragePercent | Should -Be -1
                $profile.RiskRating | Should -Be 'NotAssessed'
            }
        }

        It 'Should validate a well-formed profile without problems' {
            InModuleScope -ModuleName $script:dscModuleName {
                $profile = [ZTAssessPlatformProfile]::new()
                $profile.Platform = 'Windows'
                $profile.RiskRating = 'Medium'
                $profile.CompliancePolicyCoveragePercent = 87.5
                $profile.OwnershipSplit = @{ Corporate = 120; BYOD = 30 }

                $profile.Validate() | Should -BeNullOrEmpty
            }
        }

        It 'Should reject an unknown platform and out-of-range coverage' {
            InModuleScope -ModuleName $script:dscModuleName {
                $profile = [ZTAssessPlatformProfile]::new()
                $profile.Platform = 'BlackBerry'
                $profile.CompliancePolicyCoveragePercent = 250

                $problems = $profile.Validate()

                ($problems -join ' ') | Should -Match 'Platform'
                ($problems -join ' ') | Should -Match 'CompliancePolicyCoveragePercent'
            }
        }

        It 'Should reject unknown ownership classes' {
            InModuleScope -ModuleName $script:dscModuleName {
                $profile = [ZTAssessPlatformProfile]::new()
                $profile.Platform = 'Android'
                $profile.OwnershipSplit = @{ Borrowed = 3 }

                ($profile.Validate() -join ' ') | Should -Match 'OwnershipSplit'
            }
        }
    }
}

Describe 'ZTAssessRunManifest class' -Tag 'Unit' {

    Context 'When constructing a run manifest directly' {
        It 'Should initialise collections and a UTC start time' {
            InModuleScope -ModuleName $script:dscModuleName {
                $manifest = [ZTAssessRunManifest]::new()

                $manifest.Warnings | Should -BeNullOrEmpty
                $manifest.CollectorTimings.Count | Should -Be 0
                $manifest.AuthMode | Should -Be 'Unknown'
                $manifest.StartTime | Should -BeGreaterThan ([datetime]::UtcNow.AddMinutes(-1))
            }
        }

        It 'Should fail validation without a tool version' {
            InModuleScope -ModuleName $script:dscModuleName {
                ([ZTAssessRunManifest]::new()).Validate() | Should -Not -BeNullOrEmpty
            }
        }
    }
}
