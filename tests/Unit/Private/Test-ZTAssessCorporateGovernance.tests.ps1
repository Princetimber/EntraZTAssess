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

Describe 'Test-ZTAssessCorporateGovernance' -Tag 'Unit' {

    Context 'When the estate is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessCorporateGovernance -RunPath $runPath
            }
        }

        It 'Should emit a finding for every corporate governance check' {
            $script:findings.Count | Should -Be 3
        }

        It 'Should pass check <_>' -ForEach @('CG-001', 'CG-002', 'CG-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When corporate devices are non-compliant and unencrypted' {
        It 'Should fail CG-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'weak-corp')
            $devices = Get-Content (Join-Path $runPath 'Raw/managedDevices.json') -Raw | ConvertFrom-Json -Depth 20
            foreach ($device in ($devices | Where-Object managedDeviceOwnerType -eq 'company')) {
                $device.complianceState = 'noncompliant'
                $device.isEncrypted = $false
            }
            $devices | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/managedDevices.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCorporateGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CG-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When ownership tags are missing' {
        It 'Should flag CG-002' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'unknown-owner')
            $devices = Get-Content (Join-Path $runPath 'Raw/managedDevices.json') -Raw | ConvertFrom-Json -Depth 20
            ($devices | Where-Object id -eq 'md-6').managedDeviceOwnerType = 'unknown'
            $devices | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/managedDevices.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCorporateGovernance -RunPath $runPath
            }

            $cg002 = $findings | Where-Object CheckId -eq 'CG-002'
            $cg002.Status | Should -BeIn @('Partial', 'Fail')
            $cg002.Evidence | Should -Match 'unknown ownership'
        }
    }

    Context 'When corporate devices were provisioned manually' {
        It 'Should fail CG-003' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'manual-corp') -Overrides @{
                autopilotDevices = @()
            }
            $devices = Get-Content (Join-Path $runPath 'Raw/managedDevices.json') -Raw | ConvertFrom-Json -Depth 20
            foreach ($device in ($devices | Where-Object managedDeviceOwnerType -eq 'company')) {
                $device.deviceEnrollmentType = 'userEnrollment'
            }
            $devices | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/managedDevices.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCorporateGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'CG-003').Status | Should -Be 'Fail'
        }
    }

    Context 'When the managed device snapshot is missing' {
        It 'Should mark every check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-intune') -ExcludeSnapshots @('managedDevices')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessCorporateGovernance -RunPath $runPath
            }

            $findings.Count | Should -Be 3
            ($findings | Where-Object Status -ne 'NotAssessed').Count | Should -Be 0
        }
    }
}
