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

Describe 'Get-ZTAssessRiskRegister' -Tag 'Unit' {
    It 'Should map remediation SLA days from settings by severity' {
        InModuleScope -ModuleName $script:dscModuleName {
            $context = [pscustomobject]@{
                Findings = @(
                    [pscustomobject]@{ CheckId = 'C'; Domain = 'D'; Title = 'Critical'; Status = 'Fail'; Severity = 'Critical'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'H'; Domain = 'D'; Title = 'High'; Status = 'Fail'; Severity = 'High'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'M'; Domain = 'D'; Title = 'Medium'; Status = 'Partial'; Severity = 'Medium'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'L'; Domain = 'D'; Title = 'Low'; Status = 'Partial'; Severity = 'Low'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                )
            }

            $rows = Get-ZTAssessRiskRegister -Context $context

            ($rows | Where-Object CheckId -eq 'C').SlaDays | Should -Be 7
            ($rows | Where-Object CheckId -eq 'H').SlaDays | Should -Be 30
            ($rows | Where-Object CheckId -eq 'M').SlaDays | Should -Be 90
            ($rows | Where-Object CheckId -eq 'L').SlaDays | Should -Be 180
        }
    }

    It 'Should exclude Pass and NotAssessed findings from risk rows' {
        InModuleScope -ModuleName $script:dscModuleName {
            $context = [pscustomobject]@{
                Findings = @(
                    [pscustomobject]@{ CheckId = 'FAIL'; Domain = 'D'; Title = 'Fail'; Status = 'Fail'; Severity = 'High'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'PASS'; Domain = 'D'; Title = 'Pass'; Status = 'Pass'; Severity = 'None'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'NA'; Domain = 'D'; Title = 'Not assessed'; Status = 'NotAssessed'; Severity = 'None'; Evidence = ''; Rationale = ''; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                )
            }

            @(Get-ZTAssessRiskRegister -Context $context).CheckId | Should -Be @('FAIL')
        }
    }
}
