#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

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

Describe 'Test-ZTAssessSecurityCompliance' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }
        }

        It 'Should emit a finding for every SecurityCompliance check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('SC-001', 'SC-002', 'SC-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should report SC-004 as Informational telemetry' {
            ($script:findings | Where-Object CheckId -eq 'SC-004').Status | Should -Be 'Informational'
        }
    }

    Context 'When the Exchange Online / IPPS connection was unavailable' {
        It 'Should mark every substantive check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-exo') -ExcludeSnapshots @(
                'retentionCompliancePolicies', 'retentionComplianceRules', 'complianceTags'
            )

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'SC-002').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'SC-003').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When no retention policies cover core workloads' {
        It 'Should mark SC-001 Partial when a policy exists but coverage is narrow' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'narrow-policy') -Overrides @{
                retentionCompliancePolicies = @(
                    @{ Name = 'Exchange-Only'; Enabled = $true; ExchangeLocation = @('All'); SharePointLocation = @(); OneDriveLocation = @() }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-001').Status | Should -Be 'Partial'
        }

        It 'Should fail SC-001 when no enabled policies exist' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-policy') -Overrides @{
                retentionCompliancePolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When retention rules expire too soon' {
        It 'Should fail SC-002' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'short-retention') -Overrides @{
                retentionComplianceRules = @(
                    @{ Name = 'Short-Rule'; Policy = 'Contoso-7Year'; RetentionDuration = 30; RetentionComplianceAction = 'Keep' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-002').Status | Should -Be 'Fail'
        }

        It 'Should pass SC-002 for an Unlimited retention duration' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'unlimited-retention') -Overrides @{
                retentionComplianceRules = @(
                    @{ Name = 'Unlimited-Rule'; Policy = 'Contoso-7Year'; RetentionDuration = 'Unlimited'; RetentionComplianceAction = 'Keep' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-002').Status | Should -Be 'Pass'
        }
    }

    Context 'When no compliance tags are record labels' {
        It 'Should mark SC-003 Partial' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-record-labels') -Overrides @{
                complianceTags = @(
                    @{ Name = 'Confidential'; RetentionAction = 'Keep'; RetentionDuration = 365; IsRecordLabel = $false; Regulatory = $false }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-003').Status | Should -Be 'Partial'
        }

        It 'Should fail SC-003 when no compliance tags exist' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-tags') -Overrides @{
                complianceTags = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessSecurityCompliance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'SC-003').Status | Should -Be 'Fail'
        }
    }
}
