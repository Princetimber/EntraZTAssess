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

Describe 'ZTAssess report HTML helpers' -Tag 'Unit' {
    It 'Should HTML-encode customer, finding, evidence, and reason text' {
        InModuleScope -ModuleName $script:dscModuleName {
            $context = [pscustomobject]@{
                GeneratedUtc = [datetime]'2026-06-10T12:00:00Z'
                Engagement = @{ CustomerName = 'Contoso <script>'; Reference = 'ENG&001'; Classification = 'Secret <Client>' }
                Manifest = [pscustomobject]@{ TenantId = 'tenant&1' }
                Scores = [pscustomobject]@{
                    OverallScorePercent = 25; OverallLevel = 'Initial'; RiskPosture = 'At Risk'; RiskCounts = [pscustomobject]@{ Critical = 1; High = 0 }
                    Domains = @([pscustomobject]@{ Domain = 'ConditionalAccess'; ScorePercent = 25; Level = 'Initial' })
                    Pillars = @([pscustomobject]@{ Pillar = 'VerifyExplicitly'; ScorePercent = 25; Level = 'Initial' })
                }
                Findings = @(
                    [pscustomobject]@{ CheckId = 'CA-001'; Domain = 'ConditionalAccess'; Title = 'Block <legacy>'; Status = 'Fail'; Severity = 'Critical'; Evidence = '<b>not blocked</b>'; Rationale = 'Risk & impact'; Remediation = 'Enable > block'; RemediationEffort = 'Low'; ZeroTrustPillars = @(); References = @('https://example.test/?a=1&b=2') }
                    [pscustomobject]@{ CheckId = 'CA-002'; Domain = 'ConditionalAccess'; Title = 'Logs'; Status = 'NotAssessed'; Severity = 'None'; NotAssessedReason = 'Missing <licence>'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                )
            }

            $technical = ConvertTo-ZTAssessTechnicalHtml -Context $context

            $technical | Should -Match 'Contoso &lt;script&gt;'
            $technical | Should -Match 'Block &lt;legacy&gt;'
            $technical | Should -Match '&lt;b&gt;not blocked&lt;/b&gt;'
            $technical | Should -Match 'Missing &lt;licence&gt;'
            $technical | Should -Not -Match '<b>not blocked</b>'
        }
    }

    It 'Should treat NotAssessed as an appendix item but not an executive top risk' {
        InModuleScope -ModuleName $script:dscModuleName {
            $context = [pscustomobject]@{
                GeneratedUtc = [datetime]'2026-06-10T12:00:00Z'
                Engagement = @{ CustomerName = 'Contoso'; Reference = 'ENG'; Classification = 'Confidential' }
                Manifest = [pscustomobject]@{ TenantId = 'tenant' }
                Scores = [pscustomobject]@{
                    OverallScorePercent = 100; OverallLevel = 'Optimised'; RiskPosture = 'Low Risk'; RiskCounts = [pscustomobject]@{ Critical = 0; High = 0 }
                    Domains = @(); Pillars = @()
                }
                Findings = @([pscustomobject]@{ CheckId = 'NA-001'; Domain = 'MonitoringDetection'; Title = 'Unavailable logs'; Status = 'NotAssessed'; Severity = 'None'; NotAssessedReason = 'Missing permission'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() })
            }

            $technical = ConvertTo-ZTAssessTechnicalHtml -Context $context
            $executive = ConvertTo-ZTAssessExecutiveHtml -Context $context

            $technical | Should -Match 'Appendix: items not assessed'
            $executive | Should -Match '0 finding\(s\) require remediation'
            $executive | Should -Not -Match 'Unavailable logs'
        }
    }
}
