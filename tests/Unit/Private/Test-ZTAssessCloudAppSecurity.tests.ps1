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

Describe 'Test-ZTAssessCloudAppSecurity' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessCloudAppSecurity -RunPath $runPath
            }
        }

        It 'Should emit a finding for every CloudAppSecurity check' {
            $script:findings.Count | Should -Be 3
        }

        It 'Should pass check <_>' -ForEach @('CAS-001', 'CAS-002') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should report CAS-003 as Informational telemetry' {
            ($script:findings | Where-Object CheckId -eq 'CAS-003').Status | Should -Be 'Informational'
        }
    }

    Context 'When secure score data is unavailable' {
        It 'Should mark CAS-001 and CAS-002 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-score') -ExcludeSnapshots @('secureScoreLatest', 'secureScoreControlProfiles')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCloudAppSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CAS-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'CAS-002').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When Defender for Cloud Apps is not provisioned' {
        It 'Should fail CAS-001 with a zero-contribution control' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-mcas') -Overrides @{
                secureScoreLatest = @{
                    id            = 'score-2'
                    currentScore  = 80
                    maxScore      = 100
                    controlScores = @(
                        @{ controlName = 'MCASSetup'; score = 0; description = 'Set up Microsoft Defender for Cloud Apps' }
                    )
                }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCloudAppSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CAS-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When the setup control cannot be found in the catalogue' {
        It 'Should mark CAS-001 and CAS-002 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'unknown-control') -Overrides @{
                secureScoreLatest = @{
                    id            = 'score-3'
                    currentScore  = 80
                    maxScore      = 100
                    controlScores = @(
                        @{ controlName = 'SomeUnrelatedControl'; score = 10; description = 'Unrelated' }
                    )
                }
                secureScoreControlProfiles = @(
                    @{ id = 'ctrl-x'; controlName = 'SomeUnrelatedControl'; title = 'Unrelated'; category = 'Identity'; service = 'Microsoft Entra ID'; rank = 9; tier = 'Core'; maxScore = 10 }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCloudAppSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CAS-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'CAS-002').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When a relevant control is marked Ignored' {
        It 'Should mark CAS-002 Partial' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'ignored-control') -Overrides @{
                secureScoreControlProfiles = @(
                    @{ id = 'ctrl-3'; controlName = 'MCASSetup'; title = 'Set up Microsoft Defender for Cloud Apps'; category = 'Apps'; service = 'Microsoft Defender for Cloud Apps'; rank = 3; tier = 'Core'; maxScore = 5
                        controlStateUpdates = @(
                            @{ state = 'Ignored'; updatedBy = 'admin@contoso.com'; updatedDateTime = [datetime]::UtcNow.AddDays(-10).ToString('yyyy-MM-ddTHH:mm:ssZ') }
                        )
                    }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCloudAppSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CAS-002').Status | Should -Be 'Partial'
        }
    }
}
