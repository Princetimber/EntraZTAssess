#Requires -Version 7.0

# Device trust assessor. Implements checks DT-001 to DT-004 against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessDeviceTrust {
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
    $thresholds = $Settings.Thresholds

    $findings = [System.Collections.Generic.List[object]]::new()

    $managedDevices = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'managedDevices'
    $entraDevices = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'entraDevices'
    $compliancePolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'compliancePolicies'
    $dmSettings = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'deviceManagementSettings'
    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'

    # --- DT-001: unknown/unmanaged exposure ---------------------------------
    if ($null -eq $managedDevices -and $null -eq $entraDevices) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DT-001' -Status NotAssessed -NotAssessedReason 'Device snapshots unavailable (requires DeviceManagementManagedDevices.Read.All and Directory.Read.All).'))
    }
    else {
        $classes = Get-ZTAssessDeviceClass -ManagedDevices @($managedDevices) -EntraDevices @($entraDevices) -Settings $Settings
        $total = @($classes).Count

        if ($total -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-001' -Status NotAssessed -NotAssessedReason 'No devices found in the tenant.'))
        }
        else {
            $unknown = @($classes | Where-Object { $_.Class -eq 'Unknown' }).Count
            $unknownPct = [math]::Round(100 * $unknown / $total, 1)
            $splitText = (@($classes | Group-Object Class | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')
            $evidence = "Classification of $total device(s): $splitText. Unknown/unmanaged: $unknownPct% (threshold $($thresholds.UnmanagedDeviceMaxPercent)%)."

            if ($unknown -eq 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'DT-001' -Status Pass -Evidence $evidence))
            }
            elseif ($unknownPct -le $thresholds.UnmanagedDeviceMaxPercent) {
                $findings.Add((New-ZTAssessFinding -CheckId 'DT-001' -Status Partial -Evidence $evidence))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'DT-001' -Status Fail -Evidence $evidence))
            }
        }
    }

    # --- DT-002: compliance policy per active platform ----------------------
    if ($null -eq $managedDevices -or $null -eq $compliancePolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DT-002' -Status NotAssessed -NotAssessedReason 'Managed device or compliance policy snapshots unavailable.'))
    }
    else {
        $platformPolicyPatterns = @{
            Windows = 'windows'
            iOS     = 'ios'
            macOS   = 'macOS'
            Android = 'android'
        }

        $uncovered = [System.Collections.Generic.List[string]]::new()
        foreach ($platform in $platformPolicyPatterns.Keys) {
            $hasDevices = @($managedDevices | Where-Object { $_.operatingSystem -match $platform -or ($platform -eq 'iOS' -and $_.operatingSystem -match 'iPadOS') }).Count -gt 0
            if (-not $hasDevices) { continue }

            $hasPolicy = @($compliancePolicies | Where-Object { $_.'@odata.type' -match $platformPolicyPatterns[$platform] }).Count -gt 0
            if (-not $hasPolicy) {
                $uncovered.Add($platform)
            }
        }

        if ($uncovered.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-002' -Status Pass -Evidence 'Every platform with enrolled devices has at least one compliance policy.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-002' -Status Fail -Evidence "Platforms with enrolled devices but no compliance policy: $($uncovered -join ', ')."))
        }
    }

    # --- DT-003: secure-by-default compliance setting -----------------------
    if ($null -eq $dmSettings) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DT-003' -Status NotAssessed -NotAssessedReason 'deviceManagementSettings snapshot unavailable.'))
    }
    else {
        $secureByDefault = [bool]$dmSettings.secureByDefault
        $deviceCaInUse = @($caPolicies | Where-Object {
                $_.state -eq 'enabled' -and (
                    @($_.grantControls.builtInControls) -contains 'compliantDevice' -or
                    @($_.grantControls.builtInControls) -contains 'domainJoinedDevice'
                )
            }).Count -gt 0

        if ($secureByDefault) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-003' -Status Pass -Evidence 'Devices with no compliance policy assigned are treated as not compliant (secure by default).'))
        }
        elseif ($deviceCaInUse) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-003' -Status Fail -Evidence 'Devices with no compliance policy assigned are marked compliant while compliant-device Conditional Access is in use - unassigned devices silently satisfy the device control.' -SeverityOverride Critical))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-003' -Status Fail -Evidence 'Devices with no compliance policy assigned are marked compliant. Change this before relying on compliant-device Conditional Access.'))
        }
    }

    # --- DT-004: compliance policy quality per platform ----------------------
    if ($null -eq $compliancePolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DT-004' -Status NotAssessed -NotAssessedReason 'Compliance policy snapshot unavailable.'))
    }
    elseif (@($compliancePolicies).Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DT-004' -Status Fail -Evidence 'No compliance policies exist to assess.'))
    }
    else {
        $weakPolicies = [System.Collections.Generic.List[string]]::new()
        $strongCount = 0

        foreach ($policy in $compliancePolicies) {
            $signals = 0
            if ($policy.osMinimumVersion) { $signals++ }
            if ($policy.storageRequireEncryption -or $policy.bitLockerEnabled) { $signals++ }
            if ($policy.securityBlockJailbrokenDevices) { $signals++ }
            if ($policy.passwordRequired) { $signals++ }
            if ($policy.deviceThreatProtectionEnabled -or $policy.defenderEnabled) { $signals++ }

            # Mobile platforms can hit 5 signals; desktop platforms 4.
            $isMobile = $policy.'@odata.type' -match 'ios|android'
            $expected = if ($isMobile) { 3 } else { 2 }

            if ($signals -ge $expected) {
                $strongCount++
            }
            else {
                $weakPolicies.Add("$($policy.displayName) ($signals control signal(s))")
            }
        }

        if ($weakPolicies.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-004' -Status Pass -Evidence "All $strongCount compliance policy/policies enforce core control signals (encryption, OS version, password, jailbreak/threat protection)."))
        }
        elseif ($strongCount -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-004' -Status Partial -Evidence "Compliance policies with weak control coverage: $($weakPolicies -join '; ')."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'DT-004' -Status Fail -Evidence "Every compliance policy has weak control coverage: $($weakPolicies -join '; ')."))
        }
    }

    return $findings.ToArray()
}
