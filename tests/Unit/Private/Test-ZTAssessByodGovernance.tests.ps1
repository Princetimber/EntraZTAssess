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

Describe 'Test-ZTAssessByodGovernance' -Tag 'Unit' {

    Context 'When the estate is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessByodGovernance -RunPath $runPath
            }
        }

        It 'Should emit a finding for every BYOD governance check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('BG-001', 'BG-002', 'BG-003', 'BG-004') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When BYOD has neither app protection nor device-based Conditional Access' {
        It 'Should fail BG-001 as Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'byod-open') -Overrides @{
                appProtectionPolicies     = @()
                conditionalAccessPolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessByodGovernance -RunPath $runPath
            }

            $bg001 = $findings | Where-Object CheckId -eq 'BG-001'
            $bg001.Status | Should -Be 'Fail'
            $bg001.Severity | Should -Be 'Critical'
        }
    }

    Context 'When app protection is missing but device Conditional Access mitigates' {
        It 'Should rate BG-001 Partial with High severity' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'byod-ca-only') -Overrides @{
                appProtectionPolicies = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessByodGovernance -RunPath $runPath
            }

            $bg001 = $findings | Where-Object CheckId -eq 'BG-001'
            $bg001.Status | Should -Be 'Partial'
            $bg001.Severity | Should -Be 'High'
        }
    }

    Context 'When no enrolment restrictions exist' {
        It 'Should fail BG-003' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-restrictions') -Overrides @{
                enrollmentConfigurations = @(
                    @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration'; state = 'enabled' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessByodGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'BG-003').Status | Should -Be 'Fail'
        }
    }

    Context 'When no personal devices are enrolled' {
        It 'Should pass BG-001 and mark BG-004 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'corp-only') -Overrides @{
                managedDevices = @(
                    @{ id = 'md-1'; deviceName = 'WIN-CORP-01'; operatingSystem = 'Windows'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; complianceState = 'compliant'; isEncrypted = $true; lastSyncDateTime = [datetime]::UtcNow.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ'); managementAgent = 'mdm'; azureADDeviceId = 'aad-1'; serialNumber = 'SER-WIN-1' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessByodGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'BG-001').Status | Should -Be 'Pass'
            ($findings | Where-Object CheckId -eq 'BG-004').Status | Should -Be 'NotAssessed'
        }
    }
}
