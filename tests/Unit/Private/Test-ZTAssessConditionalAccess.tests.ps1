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

    . (Join-Path $PSScriptRoot '../../Fixtures/FixtureHelper.ps1')
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Test-ZTAssessConditionalAccess' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessConditionalAccess -RunPath $runPath
            }
        }

        It 'Should emit a finding for every Conditional Access check' {
            $script:findings.Count | Should -Be 13
        }

        It 'Should pass check <_>' -ForEach @('CA-001', 'CA-002', 'CA-003', 'CA-004', 'CA-005', 'CA-006', 'CA-007', 'CA-008', 'CA-009', 'CA-010', 'CA-011', 'CA-012', 'CA-013') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When no Conditional Access policies exist' {
        BeforeAll {
            $script:emptyRunPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'empty-ca') -Overrides @{ conditionalAccessPolicies = @() }
            $script:emptyFindings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:emptyRunPath } {
                param($runPath)
                Test-ZTAssessConditionalAccess -RunPath $runPath
            }
        }

        It 'Should fail CA-001 as Critical' {
            $finding = $script:emptyFindings | Where-Object CheckId -eq 'CA-001'
            $finding.Status | Should -Be 'Fail'
            $finding.Severity | Should -Be 'Critical'
        }

        It 'Should fail the structural policy checks' {
            foreach ($checkId in @('CA-002', 'CA-003', 'CA-005', 'CA-011', 'CA-012', 'CA-013')) {
                ($script:emptyFindings | Where-Object CheckId -eq $checkId).Status | Should -Be 'Fail' -Because $checkId
            }
        }
    }

    Context 'When the policy snapshot is missing entirely' {
        It 'Should mark every check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-ca-snap') -ExcludeSnapshots @('conditionalAccessPolicies')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessConditionalAccess -RunPath $runPath
            }

            $findings.Count | Should -Be 13
            ($findings | Where-Object Status -ne 'NotAssessed').Count | Should -Be 0
        }
    }

    Context 'When the all-users MFA policy is only report-only' {
        It 'Should rate CA-001 as Partial with High severity' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'report-only')
            $policies = Get-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Raw | ConvertFrom-Json -Depth 20
            # ca-1, ca-5, and ca-6 all qualify as all-users MFA policies; every
            # one must drop to report-only for CA-001 to become Partial.
            foreach ($policyId in @('ca-1', 'ca-5', 'ca-6')) {
                ($policies | Where-Object id -eq $policyId).state = 'enabledForReportingButNotEnforced'
            }
            $policies | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessConditionalAccess -RunPath $runPath
            }

            $ca001 = $findings | Where-Object CheckId -eq 'CA-001'
            $ca001.Status | Should -Be 'Partial'
            $ca001.Severity | Should -Be 'High'
        }
    }

    Context 'When Entra ID P2 is not licensed' {
        It 'Should mark CA-004 NotAssessed for licence reasons' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-p2') -Overrides @{
                subscribedSkus = @(@{ skuPartNumber = 'O365_BUSINESS'; servicePlans = @(@{ servicePlanName = 'EXCHANGE_S_STANDARD' }) })
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessConditionalAccess -RunPath $runPath
            }

            $ca004 = $findings | Where-Object CheckId -eq 'CA-004'
            $ca004.Status | Should -Be 'NotAssessed'
            $ca004.NotAssessedReason | Should -Match 'P2'
        }
    }

    Context 'When group exclusions exist' {
        It 'Should fail CA-008 with High severity' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'group-excl')
            $policies = Get-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Raw | ConvertFrom-Json -Depth 20
            ($policies | Where-Object id -eq 'ca-1').conditions.users.excludeGroups = @('g-vip')
            $policies | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessConditionalAccess -RunPath $runPath
            }

            $ca008 = $findings | Where-Object CheckId -eq 'CA-008'
            $ca008.Status | Should -Be 'Fail'
            $ca008.Severity | Should -Be 'High'
        }
    }
}
