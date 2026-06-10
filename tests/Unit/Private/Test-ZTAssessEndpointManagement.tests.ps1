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

Describe 'Test-ZTAssessEndpointManagement' -Tag 'Unit' {

    Context 'When the estate is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }
        }

        It 'Should emit a finding for every endpoint and platform check' {
            # EM 7 + AND 4 + IOS 4 + MAC 3 + WIN 3 = 21
            $script:findings.Count | Should -Be 21
        }

        It 'Should pass check <_>' -ForEach @('EM-001', 'EM-002', 'EM-003', 'EM-004', 'EM-005', 'EM-006', 'EM-007', 'AND-001', 'AND-002', 'AND-003', 'AND-004', 'IOS-001', 'IOS-002', 'IOS-003', 'IOS-004', 'MAC-001', 'MAC-002', 'MAC-003', 'WIN-001', 'WIN-002', 'WIN-003') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When the Apple MDM push certificate has expired' {
        It 'Should fail IOS-001 as Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'apns-expired') -Overrides @{
                applePushCertificate = @{ id = 'apns-1'; expirationDateTime = [datetime]::UtcNow.AddDays(-2).ToString('yyyy-MM-ddTHH:mm:ssZ') }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }

            $ios001 = $findings | Where-Object CheckId -eq 'IOS-001'
            $ios001.Status | Should -Be 'Fail'
            $ios001.Severity | Should -Be 'Critical'
        }
    }

    Context 'When Android devices use legacy device administrator enrolment' {
        It 'Should fail AND-002' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'android-da')
            $devices = Get-Content (Join-Path $runPath 'Raw/managedDevices.json') -Raw | ConvertFrom-Json -Depth 20
            ($devices | Where-Object id -eq 'md-7').deviceEnrollmentType = 'deviceEnrollmentManager'
            $devices | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/managedDevices.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'AND-002').Status | Should -Be 'Fail'
        }
    }

    Context 'When personal iOS devices have no app protection policy' {
        It 'Should fail IOS-004' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-ios-mam') -Overrides @{
                appProtectionPolicies = @(
                    @{ id = 'mam-and'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection'; displayName = 'Android app protection' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'IOS-004').Status | Should -Be 'Fail'
        }
    }

    Context 'When no encryption policy exists for Windows' {
        It 'Should fail WIN-003' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-bitlocker') -Overrides @{
                compliancePolicies = @(
                    @{ id = 'cp-win'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; displayName = 'Weak Windows compliance'; passwordRequired = $true }
                    @{ id = 'cp-ios'; '@odata.type' = '#microsoft.graph.iosCompliancePolicy'; displayName = 'iOS compliance'; osMinimumVersion = '17.0'; securityBlockJailbrokenDevices = $true; passwordRequired = $true; storageRequireEncryption = $true }
                    @{ id = 'cp-mac'; '@odata.type' = '#microsoft.graph.macOSCompliancePolicy'; displayName = 'macOS compliance'; osMinimumVersion = '14.0'; storageRequireEncryption = $true; firewallEnabled = $true; passwordRequired = $true }
                    @{ id = 'cp-and'; '@odata.type' = '#microsoft.graph.androidDeviceOwnerCompliancePolicy'; displayName = 'Android compliance'; osMinimumVersion = '13'; securityBlockJailbrokenDevices = $true; storageRequireEncryption = $true; passwordRequired = $true }
                )
                intents            = @()
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'WIN-003').Status | Should -Be 'Fail'
        }
    }

    Context 'When platforms have no devices' {
        It 'Should mark platform checks NotAssessed rather than failing them' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'windows-only') -Overrides @{
                managedDevices = @(
                    @{ id = 'md-1'; deviceName = 'WIN-CORP-01'; operatingSystem = 'Windows'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; complianceState = 'compliant'; isEncrypted = $true; lastSyncDateTime = [datetime]::UtcNow.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ'); managementAgent = 'mdm'; azureADDeviceId = 'aad-1'; serialNumber = 'SER-WIN-1' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }

            foreach ($checkId in @('AND-001', 'IOS-003', 'MAC-002')) {
                ($findings | Where-Object CheckId -eq $checkId).Status | Should -Be 'NotAssessed' -Because $checkId
            }
        }
    }

    Context 'When the managed device snapshot is missing entirely' {
        It 'Should mark every check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-intune') -ExcludeSnapshots @('managedDevices')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessEndpointManagement -RunPath $runPath
            }

            $findings.Count | Should -Be 21
            ($findings | Where-Object Status -ne 'NotAssessed').Count | Should -Be 0
        }
    }
}
