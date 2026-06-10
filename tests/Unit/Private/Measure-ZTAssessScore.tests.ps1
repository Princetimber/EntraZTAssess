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

Describe 'Measure-ZTAssessScore' -Tag 'Unit' {

    Context 'When scoring a simple known-answer set' {
        It 'Should compute the weighted domain score exactly' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                # weight 5 Pass (5.0) + weight 3 Fail (0.0) + weight 2 Partial (1.0)
                # => 100 * 6.0 / 10 = 60.0
                $findings = @(
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @('VerifyExplicitly') }
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Fail'; Severity = 'High'; MaturityWeight = 3.0; ZeroTrustPillars = @('VerifyExplicitly') }
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Partial'; Severity = 'Medium'; MaturityWeight = 2.0; ZeroTrustPillars = @('AssumeBreach') }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            $domain = $result.Domains | Where-Object Domain -eq 'IdentitySecurity'
            $domain.ScorePercent | Should -Be 60.0
            $domain.Level | Should -Be 'Managed'
        }

        It 'Should exclude NotAssessed findings from the denominator' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                # Assessed: weight 5 Pass => 100%; one NotAssessed weight 2 excluded
                # (2/7 = 28.6% NotAssessed weight, below the 40% threshold).
                $findings = @(
                    [pscustomobject]@{ Domain = 'ConditionalAccess'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'ConditionalAccess'; Status = 'NotAssessed'; Severity = 'None'; MaturityWeight = 2.0; ZeroTrustPillars = @() }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            $domain = $result.Domains | Where-Object Domain -eq 'ConditionalAccess'
            $domain.ScorePercent | Should -Be 100.0
            $domain.Level | Should -Be 'Optimised'
            $domain.NotAssessedCount | Should -Be 1
        }

        It 'Should exclude Informational findings from scoring entirely' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $findings = @(
                    [pscustomobject]@{ Domain = 'ConditionalAccess'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'ConditionalAccess'; Status = 'Informational'; Severity = 'None'; MaturityWeight = 1.0; ZeroTrustPillars = @() }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            ($result.Domains | Where-Object Domain -eq 'ConditionalAccess').ScorePercent | Should -Be 100.0
        }
    }

    Context 'When most of a domain could not be assessed' {
        It 'Should label the domain InsufficientData rather than scoring it' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                # NotAssessed weight 8 of 10 total (80%) exceeds the 40% threshold.
                $findings = @(
                    [pscustomobject]@{ Domain = 'HybridIdentity'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 2.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'HybridIdentity'; Status = 'NotAssessed'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'HybridIdentity'; Status = 'NotAssessed'; Severity = 'None'; MaturityWeight = 3.0; ZeroTrustPillars = @() }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            $domain = $result.Domains | Where-Object Domain -eq 'HybridIdentity'
            $domain.ScorePercent | Should -BeNullOrEmpty
            $domain.Level | Should -Be 'InsufficientData'
        }
    }

    Context 'When computing the risk posture' {
        It 'Should cap the posture at At Risk when any Critical finding exists' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $findings = @(
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Fail'; Severity = 'Critical'; MaturityWeight = 1.0; ZeroTrustPillars = @() }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            $result.RiskPosture | Should -Be 'At Risk'
            $result.RiskCounts.Critical | Should -Be 1
        }

        It 'Should report Managed Risk when only Medium/Low issues exist' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $findings = @(
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Fail'; Severity = 'Medium'; MaturityWeight = 3.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Partial'; Severity = 'Low'; MaturityWeight = 2.0; ZeroTrustPillars = @() }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            $result.RiskPosture | Should -Be 'Managed Risk'
        }
    }

    Context 'When computing pillar scores' {
        It 'Should score each pillar from its tagged findings only' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                $findings = @(
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 4.0; ZeroTrustPillars = @('VerifyExplicitly') }
                    [pscustomobject]@{ Domain = 'PrivilegedAccess'; Status = 'Fail'; Severity = 'High'; MaturityWeight = 4.0; ZeroTrustPillars = @('LeastPrivilege') }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            ($result.Pillars | Where-Object Pillar -eq 'VerifyExplicitly').ScorePercent | Should -Be 100.0
            ($result.Pillars | Where-Object Pillar -eq 'LeastPrivilege').ScorePercent | Should -Be 0.0
            ($result.Pillars | Where-Object Pillar -eq 'AssumeBreach').Level | Should -Be 'InsufficientData'
        }
    }

    Context 'When computing the overall score' {
        It 'Should weight domains using the configured domain weights' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                # IdentitySecurity (weight 1.5) at 100, IdentityGovernance (0.75) at 0
                # => (100*1.5 + 0*0.75) / 2.25 = 66.7
                $findings = @(
                    [pscustomobject]@{ Domain = 'IdentitySecurity'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                    [pscustomobject]@{ Domain = 'IdentityGovernance'; Status = 'Fail'; Severity = 'Medium'; MaturityWeight = 5.0; ZeroTrustPillars = @() }
                )
                Measure-ZTAssessScore -Findings $findings
            }

            $result.OverallScorePercent | Should -Be 66.7
            $result.OverallLevel | Should -Be 'Managed'
        }
    }
}
