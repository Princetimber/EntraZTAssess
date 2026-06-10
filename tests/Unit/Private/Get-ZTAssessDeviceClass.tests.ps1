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
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessDeviceClass' -Tag 'Unit' {

    Context 'When classifying Intune managed devices' {
        It 'Should classify company-owned devices as Corporate with high confidence' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'WIN-01'; operatingSystem = 'Windows'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; azureADDeviceId = 'a1' }
                ) -EntraDevices @()
            }

            $result[0].Class | Should -Be 'Corporate'
            $result[0].Confidence | Should -Be 'High'
            $result[0].Platform | Should -Be 'Windows'
        }

        It 'Should classify personally owned devices as BYOD' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'PHONE-01'; operatingSystem = 'iOS'; managedDeviceOwnerType = 'personal'; deviceEnrollmentType = 'userEnrollment'; azureADDeviceId = 'a1' }
                ) -EntraDevices @()
            }

            $result[0].Class | Should -Be 'BYOD'
        }

        It 'Should classify dedicated-device enrolments as Kiosk' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'LOBBY-01'; operatingSystem = 'Android'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'androidEnterpriseDedicatedDevice'; azureADDeviceId = 'a1' }
                ) -EntraDevices @()
            }

            $result[0].Class | Should -Be 'Kiosk'
            $result[0].Confidence | Should -Be 'High'
        }

        It 'Should flag PAW candidates from configured name patterns with medium confidence' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'PAW-ADMIN-01'; operatingSystem = 'Windows'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; azureADDeviceId = 'a1' }
                ) -EntraDevices @()
            }

            $result[0].Class | Should -Be 'PAW'
            $result[0].Confidence | Should -Be 'Medium'
        }
    }

    Context 'When classifying Entra-only devices' {
        It 'Should classify an active registered device with no Intune record as BYOD' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @() -EntraDevices @(
                    [pscustomobject]@{ id = 'e1'; deviceId = 'a1'; displayName = 'PERSONAL-LAPTOP'; operatingSystem = 'Windows'; profileType = 'RegisteredDevice'; accountEnabled = $true; approximateLastSignInDateTime = [datetime]::UtcNow.AddDays(-3).ToString('o') }
                )
            }

            $result[0].Class | Should -Be 'BYOD'
            $result[0].Managed | Should -BeFalse
        }

        It 'Should classify a stale Entra device as Unknown with low confidence' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @() -EntraDevices @(
                    [pscustomobject]@{ id = 'e1'; deviceId = 'a1'; displayName = 'OLD-PC'; operatingSystem = 'Windows'; profileType = 'RegisteredDevice'; accountEnabled = $true; approximateLastSignInDateTime = [datetime]::UtcNow.AddDays(-400).ToString('o') }
                )
            }

            $result[0].Class | Should -Be 'Unknown'
            $result[0].Confidence | Should -Be 'Low'
        }

        It 'Should not double-count devices present in both Intune and Entra' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'WIN-01'; operatingSystem = 'Windows'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; azureADDeviceId = 'a1' }
                ) -EntraDevices @(
                    [pscustomobject]@{ id = 'e1'; deviceId = 'a1'; displayName = 'WIN-01'; operatingSystem = 'Windows'; profileType = 'RegisteredDevice'; accountEnabled = $true; approximateLastSignInDateTime = [datetime]::UtcNow.ToString('o') }
                )
            }

            @($result).Count | Should -Be 1
            $result[0].Source | Should -Be 'Intune'
        }

        It 'Should skip disabled Entra device objects' {
            $result = InModuleScope -ModuleName $script:dscModuleName {
                Get-ZTAssessDeviceClass -ManagedDevices @() -EntraDevices @(
                    [pscustomobject]@{ id = 'e1'; deviceId = 'a1'; displayName = 'DISABLED-PC'; operatingSystem = 'Windows'; profileType = 'RegisteredDevice'; accountEnabled = $false }
                )
            }

            @($result).Count | Should -Be 0
        }
    }
}
