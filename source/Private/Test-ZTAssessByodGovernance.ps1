#Requires -Version 7.0

# BYOD governance assessor. Implements checks BG-001 to BG-004 against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessByodGovernance {
    [CmdletBinding()]
    [OutputType([ZTAssessFinding[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [hashtable]$Settings
    )

    if (-not $Settings) {
        $Settings = Get-ZTAssessConfiguration -Name Settings
    }

    $findings = [System.Collections.Generic.List[object]]::new()

    $managedDevices = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'managedDevices'
    $appProtectionPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'appProtectionPolicies'
    $enrollmentConfigs = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'enrollmentConfigurations'
    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'

    if ($null -eq $managedDevices) {
        foreach ($checkId in 1..4 | ForEach-Object { 'BG-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'managedDevices snapshot unavailable (requires DeviceManagementManagedDevices.Read.All and an Intune licence).'))
        }
        return $findings.ToArray()
    }

    $devices = @($managedDevices)
    $personalDevices = @($devices | Where-Object { $_.managedDeviceOwnerType -eq 'personal' })

    $mamPatternByPlatform = @{
        Android = 'androidManagedAppProtection'
        iOS     = 'iosManagedAppProtection'
        Windows = 'windowsManagedAppProtection|windowsInformationProtection'
    }

    $platformsWithPersonal = @()
    foreach ($platform in $mamPatternByPlatform.Keys | Sort-Object) {
        $matchPattern = if ($platform -eq 'iOS') { 'iOS|iPadOS' } else { $platform }
        if (@($personalDevices | Where-Object { $_.operatingSystem -match $matchPattern }).Count -gt 0) {
            $platformsWithPersonal += $platform
        }
    }

    $mamByPlatform = @{}
    foreach ($platform in $mamPatternByPlatform.Keys) {
        $mamByPlatform[$platform] = @($appProtectionPolicies | Where-Object { $_.'@odata.type' -match $mamPatternByPlatform[$platform] }).Count -gt 0
    }

    $compliantDeviceCa = @($caPolicies | Where-Object {
            $_.state -eq 'enabled' -and (
                @($_.grantControls.builtInControls) -contains 'compliantDevice' -or
                @($_.grantControls.builtInControls) -contains 'approvedApplication'
            )
        }).Count -gt 0

    # --- BG-001: BYOD access has data controls ------------------------------
    if ($personalDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'BG-001' -Status Pass -Evidence 'No personally owned devices are enrolled; BYOD data-control exposure is not present.'))
    }
    else {
        $unprotected = @($platformsWithPersonal | Where-Object { -not $mamByPlatform[$_] })
        if ($unprotected.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-001' -Status Pass -Evidence "Personal devices on $($platformsWithPersonal -join ', '); every platform has app protection coverage. Compliant-device/app-protection CA in force: $compliantDeviceCa."))
        }
        elseif ($compliantDeviceCa) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-001' -Status Partial -Evidence "Platforms with personal devices but no app protection policy: $($unprotected -join ', '). Conditional Access device controls provide partial mitigation." -SeverityOverride High))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-001' -Status Fail -Evidence "Platforms with personal devices and neither app protection nor device-based Conditional Access: $($unprotected -join ', '). Corporate data flows to devices with no controls."))
        }
    }

    # --- BG-002: app protection coverage of personal estate -----------------
    if ($null -eq $appProtectionPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'BG-002' -Status NotAssessed -NotAssessedReason 'appProtectionPolicies snapshot unavailable.'))
    }
    elseif ($platformsWithPersonal.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'BG-002' -Status Pass -Evidence 'No platforms have personally owned devices enrolled.'))
    }
    else {
        $covered = @($platformsWithPersonal | Where-Object { $mamByPlatform[$_] })
        $evidence = "Platforms with personal devices: $($platformsWithPersonal -join ', '). App protection present for: $(if ($covered) { $covered -join ', ' } else { 'none' })."
        if ($covered.Count -eq $platformsWithPersonal.Count) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-002' -Status Pass -Evidence $evidence))
        }
        elseif ($covered.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-002' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-002' -Status Fail -Evidence $evidence))
        }
    }

    # --- BG-003: personal enrolment deliberately governed --------------------
    if ($null -eq $enrollmentConfigs) {
        $findings.Add((New-ZTAssessFinding -CheckId 'BG-003' -Status NotAssessed -NotAssessedReason 'enrollmentConfigurations snapshot unavailable.'))
    }
    else {
        $restrictions = @($enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'PlatformRestriction' })
        $personalBlocks = @($restrictions | Where-Object {
                $_.platformRestriction.personalDeviceEnrollmentBlocked -or $_.personalDeviceEnrollmentBlocked
            })

        if ($personalBlocks.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-003' -Status Pass -Evidence "Personal enrolment is restricted on $($personalBlocks.Count) platform restriction configuration(s); the BYOD boundary is a deliberate decision."))
        }
        elseif ($restrictions.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-003' -Status Partial -Evidence 'Enrolment restrictions exist but none block personal enrolment; confirm BYOD is intended on every platform.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-003' -Status Fail -Evidence 'No enrolment restrictions are configured; personal enrolment is default-allowed on every platform.'))
        }
    }

    # --- BG-004: BYOD and corporate treated differently ----------------------
    $corporateDevices = @($devices | Where-Object { $_.managedDeviceOwnerType -eq 'company' })
    if ($personalDevices.Count -eq 0 -or $corporateDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'BG-004' -Status NotAssessed -NotAssessedReason 'Both personal and corporate devices must be present to assess differentiation.'))
    }
    else {
        $anyMam = @($appProtectionPolicies).Count -gt 0
        $anyRestriction = @($enrollmentConfigs | Where-Object { $_.'@odata.type' -match 'PlatformRestriction' }).Count -gt 0

        if ($anyMam -or $anyRestriction) {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-004' -Status Pass -Evidence "Ownership models are differentiated (app protection policies=$anyMam, enrolment restrictions=$anyRestriction)."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'BG-004' -Status Fail -Evidence "Personal ($($personalDevices.Count)) and corporate ($($corporateDevices.Count)) devices receive identical treatment: no app protection policies and no enrolment restrictions distinguish the ownership models."))
        }
    }

    return $findings.ToArray()
}
