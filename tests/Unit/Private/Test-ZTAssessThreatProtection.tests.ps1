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

Describe 'Test-ZTAssessThreatProtection' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }
        }

        It 'Should emit a finding for every ThreatProtection check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('TP-001', 'TP-002', 'TP-003', 'TP-004') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When the Exchange Online / IPPS connection was unavailable' {
        It 'Should mark every check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-exo') -ExcludeSnapshots @(
                'safeLinksPolicies', 'safeAttachmentPolicies', 'antiPhishPolicies', 'malwareFilterPolicies'
            )

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            foreach ($finding in $findings) {
                $finding.Status | Should -Be 'NotAssessed'
            }
        }
    }

    Context 'When Safe Links allows click-through' {
        It 'Should fail TP-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'clickthrough') -Overrides @{
                safeLinksPolicies = @(
                    @{ Name = 'Default'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $false; EnableSafeLinksForOffice = $false; ScanUrls = $true; AllowClickThrough = $true; TrackClicks = $true }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-001').Status | Should -Be 'Fail'
        }

        It 'Should mark TP-001 Partial when only some policies are hardened' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'mixed-safelinks') -Overrides @{
                safeLinksPolicies = @(
                    @{ Name = 'Default'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true; ScanUrls = $true; AllowClickThrough = $false; TrackClicks = $true }
                    @{ Name = 'Executives'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $false; EnableSafeLinksForOffice = $false; ScanUrls = $true; AllowClickThrough = $true; TrackClicks = $true }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-001').Status | Should -Be 'Partial'
        }
    }

    Context 'When no Safe Links policies exist' {
        It 'Should fail TP-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-safelinks') -Overrides @{
                safeLinksPolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When Safe Attachments is monitor-only' {
        It 'Should fail TP-002' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'monitor-only') -Overrides @{
                safeAttachmentPolicies = @(
                    @{ Name = 'Default'; Enable = $true; Action = 'Allow' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-002').Status | Should -Be 'Fail'
        }
    }

    Context 'When anti-phishing mailbox intelligence is disabled' {
        It 'Should fail TP-003' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-mailbox-intel') -Overrides @{
                antiPhishPolicies = @(
                    @{ Name = 'Default'; Enabled = $true; EnableMailboxIntelligence = $false; EnableMailboxIntelligenceProtection = $false; EnableSpoofIntelligence = $true; PhishThresholdLevel = 3 }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-003').Status | Should -Be 'Fail'
        }

        It 'Should fail TP-003 when the threshold level is below the floor' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'low-threshold') -Overrides @{
                antiPhishPolicies = @(
                    @{ Name = 'Default'; Enabled = $true; EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $true; EnableSpoofIntelligence = $true; PhishThresholdLevel = 1 }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-003').Status | Should -Be 'Fail'
        }
    }

    Context 'When malware filtering does not enable the file filter' {
        It 'Should fail TP-004' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-file-filter') -Overrides @{
                malwareFilterPolicies = @(
                    @{ Name = 'Default'; EnableFileFilter = $false; Action = 'DeleteMessage' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessThreatProtection -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'TP-004').Status | Should -Be 'Fail'
        }
    }
}
