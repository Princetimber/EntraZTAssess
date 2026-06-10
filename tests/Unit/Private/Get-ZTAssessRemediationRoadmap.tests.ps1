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

Describe 'Get-ZTAssessRemediationRoadmap' -Tag 'Unit' {
    It 'Should sequence only remediable findings into deterministic waves' {
        InModuleScope -ModuleName $script:dscModuleName {
            $context = [pscustomobject]@{
                Findings = @(
                    [pscustomobject]@{ CheckId = 'MED'; Domain = 'D'; Title = 'Medium'; Status = 'Partial'; Severity = 'Medium'; Remediation = 'Fix medium'; RemediationEffort = 'Medium'; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'CRIT'; Domain = 'D'; Title = 'Critical'; Status = 'Fail'; Severity = 'Critical'; Remediation = 'Fix critical'; RemediationEffort = 'High'; ZeroTrustPillars = @(); References = @() }
                    [pscustomobject]@{ CheckId = 'NA'; Domain = 'D'; Title = 'NA'; Status = 'NotAssessed'; Severity = 'None'; Remediation = ''; RemediationEffort = ''; ZeroTrustPillars = @(); References = @() }
                )
            }

            $roadmap = Get-ZTAssessRemediationRoadmap -Context $context

            @($roadmap).CheckId | Should -Be @('CRIT', 'MED')
            $roadmap[0].Wave | Should -Be 'Wave 1'
            $roadmap[1].Wave | Should -Be 'Wave 2'
        }
    }
}
