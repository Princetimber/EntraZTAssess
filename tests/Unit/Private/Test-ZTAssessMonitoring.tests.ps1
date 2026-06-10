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

Describe 'Test-ZTAssessMonitoring' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessMonitoring -RunPath $runPath
            }
        }

        It 'Should emit a finding for every monitoring check' {
            $script:findings.Count | Should -Be 6
        }

        It 'Should pass check <_>' -ForEach @('MD-001', 'MD-002', 'MD-004') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should rate MD-003 Partial (export verification is manual)' {
            ($script:findings | Where-Object CheckId -eq 'MD-003').Status | Should -Be 'Partial'
        }

        It 'Should mark MD-005 NotAssessed without the optional Sentinel module' {
            ($script:findings | Where-Object CheckId -eq 'MD-005').Status | Should -Be 'NotAssessed'
        }

        It 'Should report MD-006 as Informational telemetry' {
            ($script:findings | Where-Object CheckId -eq 'MD-006').Status | Should -Be 'Informational'
        }
    }

    Context 'When risky users sit unremediated' {
        It 'Should fail MD-002 with High severity when high-risk users are overdue' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'risky-open') -Overrides @{
                riskyUsers = @(
                    @{ id = 'ru-1'; userPrincipalName = 'victim@contoso.com'; riskLevel = 'high'; riskState = 'atRisk'; riskLastUpdatedDateTime = [datetime]::UtcNow.AddDays(-20).ToString('yyyy-MM-ddTHH:mm:ssZ') }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessMonitoring -RunPath $runPath
            }

            $md002 = $findings | Where-Object CheckId -eq 'MD-002'
            $md002.Status | Should -Be 'Fail'
            $md002.Severity | Should -Be 'High'
        }
    }

    Context 'When no risk policies are enforced despite P2' {
        It 'Should fail MD-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-risk-ca')
            $policies = Get-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Raw | ConvertFrom-Json -Depth 20
            $kept = @($policies | Where-Object { @($_.conditions.signInRiskLevels).Count -eq 0 -and @($_.conditions.userRiskLevels).Count -eq 0 })
            ConvertTo-Json -InputObject $kept -Depth 20 | Set-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessMonitoring -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'MD-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When a hybrid tenant has no Defender for Identity sensors' {
        It 'Should fail MD-004' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-mdi') -Overrides @{
                mdiSensors = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessMonitoring -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'MD-004').Status | Should -Be 'Fail'
        }

        It 'Should mark MD-004 NotAssessed on cloud-only tenants' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'cloud-only-md') -Overrides @{
                organization = @(@{ id = 'tenant-1'; displayName = 'Contoso Ltd'; onPremisesSyncEnabled = $false })
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessMonitoring -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'MD-004').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When Identity Protection data is unavailable (no P2)' {
        It 'Should mark MD-002 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-ip') -ExcludeSnapshots @('riskyUsers')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessMonitoring -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'MD-002').Status | Should -Be 'NotAssessed'
        }
    }
}
