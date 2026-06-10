#Requires -Version 7.0

# Hybrid identity assessor. Implements checks HY-001 to HY-006 against
# persisted snapshots. Pure function over data on disk: no network calls.
# On cloud-only tenants every check is NotAssessed and the domain is
# excluded from scoring as InsufficientData.
function Test-ZTAssessHybridIdentity {
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

    $organization = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'organization'
    $onPremSync = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'onPremisesSynchronization'
    $errorsSummary = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'provisioningErrorsSummary'

    $org = @($organization) | Select-Object -First 1

    # Cloud-only tenants: the entire domain is not applicable.
    if ($org -and -not $org.onPremisesSyncEnabled) {
        foreach ($checkId in 1..6 | ForEach-Object { 'HY-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'Cloud-only tenant: on-premises directory synchronisation is not enabled.'))
        }
        return $findings.ToArray()
    }

    # --- HY-001: password hash sync enabled -----------------------------------
    if ($null -eq $onPremSync) {
        $findings.Add((New-ZTAssessFinding -CheckId 'HY-001' -Status NotAssessed -NotAssessedReason 'onPremisesSynchronization snapshot unavailable (requires OnPremDirectorySynchronization.Read.All).'))
    }
    else {
        $sync = @($onPremSync) | Select-Object -First 1
        $phsEnabled = [bool]$sync.features.passwordSyncEnabled
        if ($phsEnabled) {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-001' -Status Pass -Evidence 'Password hash synchronisation is enabled; leaked-credential detection and sign-in fallback are available.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-001' -Status Fail -Evidence 'Password hash synchronisation is disabled; leaked-credential detection and authentication fallback are unavailable.'))
        }
    }

    # --- HY-002: synchronisation freshness --------------------------------------
    if (-not $org -or -not $org.onPremisesLastSyncDateTime) {
        $findings.Add((New-ZTAssessFinding -CheckId 'HY-002' -Status NotAssessed -NotAssessedReason 'The last synchronisation timestamp is unavailable on the organisation object.'))
    }
    else {
        $lastSync = [datetime]$org.onPremisesLastSyncDateTime
        $hoursSince = [math]::Round(([datetime]::UtcNow - $lastSync).TotalHours, 1)
        $evidence = "Last directory synchronisation: $($lastSync.ToString('yyyy-MM-dd HH:mm'))Z ($hoursSince hour(s) ago; warn $($thresholds.HybridSyncStaleWarnHours)h, fail $($thresholds.HybridSyncStaleFailHours)h)."

        if ($hoursSince -ge $thresholds.HybridSyncStaleFailHours) {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-002' -Status Fail -Evidence $evidence))
        }
        elseif ($hoursSince -ge $thresholds.HybridSyncStaleWarnHours) {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-002' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-002' -Status Pass -Evidence $evidence))
        }
    }

    # --- HY-003: provisioning errors ---------------------------------------------
    if ($null -eq $errorsSummary) {
        $findings.Add((New-ZTAssessFinding -CheckId 'HY-003' -Status NotAssessed -NotAssessedReason 'provisioningErrorsSummary snapshot unavailable.'))
    }
    else {
        $syncedCount = [int]$errorsSummary.syncedUserCount
        $errorCount = [int]$errorsSummary.usersWithErrors

        if ($syncedCount -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-003' -Status NotAssessed -NotAssessedReason 'No synchronised users found to evaluate.'))
        }
        elseif ($errorCount -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'HY-003' -Status Pass -Evidence "No provisioning errors across $syncedCount synchronised user(s)."))
        }
        else {
            $pct = [math]::Round(100 * $errorCount / $syncedCount, 2)
            $categories = (@($errorsSummary.errorsByCategory) | ForEach-Object { "$($_.category)=$($_.count)" }) -join ', '
            $evidence = "$errorCount of $syncedCount synchronised user(s) ($pct%) have provisioning errors ($categories); threshold $($thresholds.ProvisioningErrorMaxPercent)%."
            if ($pct -gt $thresholds.ProvisioningErrorMaxPercent) {
                $findings.Add((New-ZTAssessFinding -CheckId 'HY-003' -Status Fail -Evidence $evidence))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'HY-003' -Status Partial -Evidence $evidence))
            }
        }
    }

    # --- HY-004 / HY-005 / HY-006: manual verification items ----------------------
    $findings.Add((New-ZTAssessFinding -CheckId 'HY-004' -Status NotAssessed -NotAssessedReason 'The AZUREADSSOACC rollover cadence is not exposed via Graph; verify the Kerberos decryption key age on the on-premises domain and record the rotation procedure.'))

    if ($null -eq $onPremSync) {
        $findings.Add((New-ZTAssessFinding -CheckId 'HY-005' -Status NotAssessed -NotAssessedReason 'onPremisesSynchronization snapshot unavailable.'))
    }
    else {
        $sync = @($onPremSync) | Select-Object -First 1
        $deviceWriteback = [bool]$sync.features.deviceWritebackEnabled
        $groupWriteback = [bool]$sync.features.groupWriteBackEnabled
        $findings.Add((New-ZTAssessFinding -CheckId 'HY-005' -Status Informational -Evidence "Writeback configuration: device writeback=$deviceWriteback, group writeback=$groupWriteback. Confirm each enabled feature has a documented consumer." -SeverityOverride None))
    }

    $findings.Add((New-ZTAssessFinding -CheckId 'HY-006' -Status NotAssessed -NotAssessedReason 'The Entra Connect server version is not exposed via Graph; record it from the Connect server and compare against the supported builds list.'))

    return $findings.ToArray()
}
