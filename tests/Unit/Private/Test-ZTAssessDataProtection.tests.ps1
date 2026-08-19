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

Describe 'Test-ZTAssessDataProtection' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }
        }

        It 'Should emit a finding for every DataProtection check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('DP-001', 'DP-002', 'DP-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should report DP-004 as Informational telemetry' {
            ($script:findings | Where-Object CheckId -eq 'DP-004').Status | Should -Be 'Informational'
        }
    }

    Context 'When the Exchange Online / IPPS connection was unavailable' {
        It 'Should mark every substantive check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-exo') -ExcludeSnapshots @(
                'dlpCompliancePolicies', 'dlpComplianceRules', 'sensitivityLabels', 'labelPolicies'
            )

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DP-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'DP-002').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'DP-003').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When DLP policies are only in test mode' {
        It 'Should mark DP-001 Partial' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'test-mode-dlp') -Overrides @{
                dlpCompliancePolicies = @(
                    @{ Name = 'Test-Policy'; Mode = 'TestWithNotifications'; ExchangeLocation = @('All'); SharePointLocation = @('All'); OneDriveLocation = @() }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DP-001').Status | Should -Be 'Partial'
        }

        It 'Should fail DP-001 when no DLP policies exist' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-dlp-policy') -Overrides @{
                dlpCompliancePolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DP-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When no DLP rule blocks access' {
        It 'Should fail DP-002' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'notify-only-dlp') -Overrides @{
                dlpComplianceRules = @(
                    @{ Name = 'Notify-Only-Rule'; Policy = 'Block-CreditCard-External'; BlockAccess = $false; NotifyUser = @('Owner') }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DP-002').Status | Should -Be 'Fail'
        }
    }

    Context 'When sensitivity labels are not published' {
        It 'Should mark DP-003 Partial' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'unpublished-labels') -Overrides @{
                labelPolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DP-003').Status | Should -Be 'Partial'
        }

        It 'Should fail DP-003 when no sensitivity labels exist' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-labels') -Overrides @{
                sensitivityLabels = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDataProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DP-003').Status | Should -Be 'Fail'
        }
    }
}
