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

Describe 'Test-ZTAssessDeviceTrust' -Tag 'Unit' {

    Context 'When the estate is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessDeviceTrust -RunPath $runPath
            }
        }

        It 'Should emit a finding for every device trust check' {
            $script:findings.Count | Should -Be 4
        }

        It 'Should pass check <_>' -ForEach @('DT-001', 'DT-002', 'DT-003', 'DT-004') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When devices are marked compliant by default while device CA is in use' {
        It 'Should escalate DT-003 to Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'insecure-default') -Overrides @{
                deviceManagementSettings = @{ secureByDefault = $false }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDeviceTrust -RunPath $runPath
            }

            $dt003 = $findings | Where-Object CheckId -eq 'DT-003'
            $dt003.Status | Should -Be 'Fail'
            $dt003.Severity | Should -Be 'Critical'
        }
    }

    Context 'When a platform has devices but no compliance policy' {
        It 'Should fail DT-002 naming the platform' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-android-cp') -Overrides @{
                compliancePolicies = @(
                    @{ id = 'cp-win'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; displayName = 'Windows compliance'; osMinimumVersion = '10.0'; bitLockerEnabled = $true; passwordRequired = $true }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDeviceTrust -RunPath $runPath
            }

            $dt002 = $findings | Where-Object CheckId -eq 'DT-002'
            $dt002.Status | Should -Be 'Fail'
            $dt002.Evidence | Should -Match 'Android'
        }
    }

    Context 'When device snapshots are missing' {
        It 'Should mark DT-001 NotAssessed without erroring' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-devices') -ExcludeSnapshots @('managedDevices', 'entraDevices')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessDeviceTrust -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'DT-001').Status | Should -Be 'NotAssessed'
        }
    }
}
