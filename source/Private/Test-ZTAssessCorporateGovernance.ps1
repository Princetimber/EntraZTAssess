#Requires -Version 7.0

# Corporate device governance assessor. Implements checks CG-001 to CG-003
# against persisted snapshots. Pure function over data on disk: no network
# calls.
function Test-ZTAssessCorporateGovernance {
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
    $autopilotDevices = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'autopilotDevices'

    if ($null -eq $managedDevices) {
        foreach ($checkId in 1..3 | ForEach-Object { 'CG-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'managedDevices snapshot unavailable (requires DeviceManagementManagedDevices.Read.All and an Intune licence).'))
        }
        return $findings.ToArray()
    }

    $devices = @($managedDevices)
    $corporateDevices = @($devices | Where-Object { $_.managedDeviceOwnerType -eq 'company' })

    # --- CG-001: corporate device control coverage ---------------------------
    if ($corporateDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CG-001' -Status NotAssessed -NotAssessedReason 'No corporate-owned managed devices are enrolled.'))
    }
    else {
        $compliant = @($corporateDevices | Where-Object { $_.complianceState -eq 'compliant' }).Count
        $encrypted = @($corporateDevices | Where-Object { $_.isEncrypted }).Count
        $compliantPct = [math]::Round(100 * $compliant / $corporateDevices.Count, 1)
        $encryptedPct = [math]::Round(100 * $encrypted / $corporateDevices.Count, 1)
        $floor = [double]$thresholds.CorporateComplianceMinimumPercent
        $evidence = "Corporate devices: $($corporateDevices.Count). Compliant: $compliantPct%, encrypted: $encryptedPct% (threshold $floor%)."

        if ($compliantPct -ge $floor -and $encryptedPct -ge $floor) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CG-001' -Status Pass -Evidence $evidence))
        }
        elseif ($compliantPct -ge 50 -or $encryptedPct -ge 50) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CG-001' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'CG-001' -Status Fail -Evidence $evidence))
        }
    }

    # --- CG-002: ownership tagging hygiene -----------------------------------
    $unknownOwnership = @($devices | Where-Object { $_.managedDeviceOwnerType -notin @('company', 'personal') })
    if ($devices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CG-002' -Status NotAssessed -NotAssessedReason 'No managed devices to assess.'))
    }
    elseif ($unknownOwnership.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CG-002' -Status Pass -Evidence "All $($devices.Count) managed device(s) carry an ownership tag."))
    }
    else {
        $pct = [math]::Round(100 * $unknownOwnership.Count / $devices.Count, 1)
        $status = if ($pct -gt 10) { 'Fail' } else { 'Partial' }
        $findings.Add((New-ZTAssessFinding -CheckId 'CG-002' -Status $status -Evidence "$($unknownOwnership.Count) managed device(s) ($pct%) have unknown ownership and sit outside both governance models."))
    }

    # --- CG-003: modern corporate provisioning -------------------------------
    if ($corporateDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CG-003' -Status NotAssessed -NotAssessedReason 'No corporate-owned managed devices are enrolled.'))
    }
    else {
        $modernPattern = 'appleBulkWithUser|appleBulkWithoutUser|dep|FullyManaged|DedicatedDevice|CorporateWorkProfile|windowsAutoEnrollment|azureADJoinedUsingDeviceAuth'
        $modernEnrolled = @($corporateDevices | Where-Object { $_.deviceEnrollmentType -match $modernPattern }).Count

        # Autopilot-registered corporate Windows devices also count as modern.
        $autopilotSerials = @($autopilotDevices | Select-Object -ExpandProperty serialNumber -ErrorAction Ignore)
        $autopilotMatched = @($corporateDevices | Where-Object {
                $_.serialNumber -and $_.serialNumber -in $autopilotSerials -and $_.deviceEnrollmentType -notmatch $modernPattern
            }).Count

        $modernTotal = $modernEnrolled + $autopilotMatched
        $pct = [math]::Round(100 * $modernTotal / $corporateDevices.Count, 1)
        $floor = [double]$thresholds.ModernProvisioningMinimumPercent
        $evidence = "$modernTotal of $($corporateDevices.Count) corporate device(s) ($pct%) provisioned via modern channels (Autopilot/ADE/Android Enterprise); threshold $floor%."

        if ($pct -ge $floor) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CG-003' -Status Pass -Evidence $evidence))
        }
        elseif ($modernTotal -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CG-003' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'CG-003' -Status Fail -Evidence $evidence))
        }
    }

    return $findings.ToArray()
}
