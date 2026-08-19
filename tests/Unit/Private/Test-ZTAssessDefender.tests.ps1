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

Describe 'Test-ZTAssessDefender' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }
        }

        It 'Should emit a finding for every Defender check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('DF-001', 'DF-002', 'DF-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should report DF-004 as Informational telemetry' {
            ($script:findings | Where-Object CheckId -eq 'DF-004').Status | Should -Be 'Informational'
        }
    }

    Context 'When the Secure Score is below the maturity floor' {
        It 'Should fail DF-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'low-score') -Overrides @{
                secureScoreLatest = @{ id = 'score-2'; currentScore = 30; maxScore = 100; controlScores = @() }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When Secure Score data is unavailable' {
        It 'Should mark DF-001 and DF-002 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-score') -ExcludeSnapshots @('secureScoreLatest')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'DF-002').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When no devices are onboarded to Defender for Endpoint' {
        It 'Should fail DF-002 with a zero-contribution control' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-onboarding') -Overrides @{
                secureScoreLatest = @{
                    id            = 'score-3'
                    currentScore  = 80
                    maxScore      = 100
                    controlScores = @(
                        @{ controlName = 'OnboardMachinesToMDATP'; score = 0; description = 'Onboard machines to Microsoft Defender for Endpoint' }
                    )
                }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-002').Status | Should -Be 'Fail'
        }
    }

    Context 'When partial onboarding coverage is achieved' {
        It 'Should mark DF-002 Partial' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'partial-onboarding') -Overrides @{
                secureScoreLatest = @{
                    id            = 'score-4'
                    currentScore  = 85
                    maxScore      = 100
                    controlScores = @(
                        @{ controlName = 'OnboardMachinesToMDATP'; score = 5; description = 'Onboard machines to Microsoft Defender for Endpoint' }
                    )
                }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-002').Status | Should -Be 'Partial'
        }
    }

    Context 'When the onboarding control cannot be found in the catalogue' {
        It 'Should mark DF-002 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'unknown-control') -Overrides @{
                secureScoreLatest = @{
                    id            = 'score-5'
                    currentScore  = 80
                    maxScore      = 100
                    controlScores = @(
                        @{ controlName = 'SomeUnrelatedControl'; score = 10; description = 'Unrelated' }
                    )
                }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-002').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When high-severity alerts are open and overdue' {
        It 'Should fail DF-003 for alerts overdue beyond the SLA' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'overdue-alerts') -Overrides @{
                unifiedAlerts = @(
                    @{ id = 'alert-2'; title = 'Ransomware behaviour detected'; severity = 'high'; status = 'new'; classification = $null; createdDateTime = [datetime]::UtcNow.AddDays(-20).ToString('yyyy-MM-ddTHH:mm:ssZ'); serviceSource = 'microsoftDefenderForEndpoint'; category = 'Ransomware' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-003').Status | Should -Be 'Fail'
        }

        It 'Should pass DF-003 when open alerts are still within the SLA window' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'fresh-alerts') -Overrides @{
                unifiedAlerts = @(
                    @{ id = 'alert-3'; title = 'New alert'; severity = 'high'; status = 'new'; classification = $null; createdDateTime = [datetime]::UtcNow.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ'); serviceSource = 'microsoftDefenderForEndpoint'; category = 'InitialAccess' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-003').Status | Should -Be 'Pass'
        }
    }

    Context 'When unified alert data is unavailable' {
        It 'Should mark DF-003 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-alerts') -ExcludeSnapshots @('unifiedAlerts')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDefender -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DF-003').Status | Should -Be 'NotAssessed'
        }
    }
}
