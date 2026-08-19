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

Describe 'Test-ZTAssessCollaboration' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }
        }

        It 'Should emit a finding for every Collaboration check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('CO-001', 'CO-002', 'CO-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should report CO-004 as Informational telemetry' {
            ($script:findings | Where-Object CheckId -eq 'CO-004').Status | Should -Be 'Informational'
        }
    }

    Context 'When the Exchange Online / IPPS connection was unavailable' {
        It 'Should mark every substantive check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-exo') -ExcludeSnapshots @(
                'sharingPolicies', 'transportRules'
            )

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CO-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'CO-002').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'CO-003').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When anonymous users can see calendar detail' {
        It 'Should fail CO-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'anon-detail') -Overrides @{
                sharingPolicies = @(
                    @{ Name = 'Default Sharing Policy'; Enabled = $true; Domains = @('Anonymous:CalendarSharingFreeBusyDetail') }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CO-001').Status | Should -Be 'Fail'
        }

        It 'Should pass CO-001 when no sharing policies exist' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-sharing-policy') -Overrides @{
                sharingPolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CO-001').Status | Should -Be 'Pass'
        }
    }

    Context 'When a transport rule silently redirects messages' {
        It 'Should fail CO-002' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'redirect-rule') -Overrides @{
                transportRules = @(
                    @{ Name = 'Silent-Redirect'; State = 'Enabled'; RedirectMessageTo = @('attacker@external.com'); BlindCopyTo = @() }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CO-002').Status | Should -Be 'Fail'
        }

        It 'Should ignore a disabled redirect rule' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'disabled-redirect-rule') -Overrides @{
                transportRules = @(
                    @{ Name = 'Disabled-Redirect'; State = 'Disabled'; RedirectMessageTo = @('someone@contoso.com'); BlindCopyTo = @() }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CO-002').Status | Should -Be 'Pass'
        }
    }

    Context 'When full calendar details are shared with all external domains' {
        It 'Should fail CO-003' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'wildcard-full-details') -Overrides @{
                sharingPolicies = @(
                    @{ Name = 'Default Sharing Policy'; Enabled = $true; Domains = @('*:CalendarSharingFullDetails') }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCollaboration -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CO-003').Status | Should -Be 'Fail'
        }
    }
}
