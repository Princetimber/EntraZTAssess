#Requires -Version 7.0

# Builds a ZTAssessPlatformProfile for each platform with devices in the
# estate, combining the classification engine output with policy snapshots.
# Coverage percentages are estate-level estimates from device-reported
# state; -1 means the value could not be calculated.
function Get-ZTAssessPlatformProfile {
    [CmdletBinding()]
    [OutputType([ZTAssessPlatformProfile[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [AllowNull()]
        [object[]]$DeviceClasses
    )

    $managedDevices = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'managedDevices'
    $deviceConfigurations = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'deviceConfigurations'
    $appProtectionPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'appProtectionPolicies'
    $enrollmentConfigs = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'enrollmentConfigurations'
    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'

    $platformMatchers = @{
        Windows = @{ Compliance = 'windows'; Config = 'windows'; Mam = 'windowsManagedAppProtection|mdmWindowsInformationProtection'; Restriction = 'windows' }
        iOS     = @{ Compliance = 'ios'; Config = 'ios'; Mam = 'iosManagedAppProtection'; Restriction = 'ios' }
        macOS   = @{ Compliance = 'macOS'; Config = 'macOS'; Mam = ''; Restriction = 'mac' }
        Android = @{ Compliance = 'android'; Config = 'android'; Mam = 'androidManagedAppProtection'; Restriction = 'android' }
    }

    $compliantDeviceCa = @($caPolicies | Where-Object {
            $_.state -eq 'enabled' -and (
                @($_.grantControls.builtInControls) -contains 'compliantDevice' -or
                @($_.grantControls.builtInControls) -contains 'domainJoinedDevice'
            )
        }).Count -gt 0
    $appProtectionCa = @($caPolicies | Where-Object {
            $_.state -eq 'enabled' -and @($_.grantControls.builtInControls) -contains 'approvedApplication'
        }).Count -gt 0

    $profiles = [System.Collections.Generic.List[object]]::new()

    foreach ($platform in @('Windows', 'iOS', 'macOS', 'Android')) {
        $platformClasses = @($DeviceClasses | Where-Object { $_.Platform -eq $platform })
        if ($platformClasses.Count -eq 0) { continue }

        $matcher = $platformMatchers[$platform]
        $platformManaged = @($managedDevices | Where-Object { $_.operatingSystem -match $platform -or ($platform -eq 'iOS' -and $_.operatingSystem -match 'iPadOS') })

        $platformProfile = [ZTAssessPlatformProfile]::new()
        $platformProfile.Platform = $platform

        # Ownership split from the classification engine.
        $split = @{}
        foreach ($group in ($platformClasses | Group-Object -Property Class)) {
            $split[$group.Name] = $group.Count
        }
        $platformProfile.OwnershipSplit = $split

        # Enrolment methods in use.
        $platformProfile.EnrolmentMethodsInUse = @($platformManaged |
                Select-Object -ExpandProperty deviceEnrollmentType -Unique |
                Where-Object { $_ })

        # Enrolment restrictions for this platform.
        $restrictions = @($enrollmentConfigs | Where-Object {
                $_.'@odata.type' -match 'PlatformRestriction' -and ($_.'@odata.type' -match $matcher.Restriction -or $_.platformType -match $matcher.Restriction)
            })
        $personalBlocked = @($restrictions | Where-Object {
                $_.platformRestriction.personalDeviceEnrollmentBlocked -or $_.personalDeviceEnrollmentBlocked
            }).Count -gt 0
        $platformProfile.EnrolmentRestrictions = @{
            RestrictionConfigured = ($restrictions.Count -gt 0)
            PersonalBlocked       = $personalBlocked
        }

        # Coverage estimates.
        if ($platformManaged.Count -gt 0) {
            $withComplianceSignal = @($platformManaged | Where-Object { $_.complianceState -in @('compliant', 'noncompliant', 'inGracePeriod') }).Count
            $platformProfile.CompliancePolicyCoveragePercent = [math]::Round(100 * $withComplianceSignal / $platformManaged.Count, 1)
        }

        $platformProfile.ConfigProfileCoveragePercent = if (@($deviceConfigurations | Where-Object { $_.'@odata.type' -match $matcher.Config }).Count -gt 0) { 100 } else { 0 }

        if ($platform -eq 'Windows') {
            $intents = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'intents'
            $platformProfile.BaselineCoveragePercent = if (@($intents | Where-Object { $_.isAssigned }).Count -gt 0) { 100 } else { 0 }
        }

        if ($matcher.Mam) {
            $mamPolicies = @($appProtectionPolicies | Where-Object { $_.'@odata.type' -match $matcher.Mam })
            $platformProfile.AppProtectionCoveragePercent = if ($mamPolicies.Count -gt 0) { 100 } else { 0 }
        }

        $platformProfile.CADependency = @{
            CompliantDeviceRequired  = $compliantDeviceCa
            AppProtectionRequired    = $appProtectionCa
        }

        $profiles.Add($platformProfile)
    }

    return , $profiles.ToArray()
}
