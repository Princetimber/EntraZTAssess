#Requires -Version 7.0

# CloudAppSecurity assessor. Implements checks CAS-001 to CAS-003 against
# persisted snapshots. Pure function over data on disk: no network calls.
# This domain is a best-effort Microsoft Secure Score proxy, not a genuine
# Defender for Cloud Apps configuration assessment - Microsoft Graph exposes
# no API for MCAS policies, app risk scores, or OAuth app governance. It
# reuses the secureScoreLatest/secureScoreControlProfiles snapshots
# collected by Invoke-ZTAssessDefenderCollection (shared with the Defender
# domain); no separate collector exists for this module.
function Test-ZTAssessCloudAppSecurity {
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
    $setupControlNames = @($Settings.CloudAppSecurity.SetupControlNames)

    $findings = [System.Collections.Generic.List[object]]::new()

    $secureScoreLatest = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'secureScoreLatest'
    $controlProfiles = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'secureScoreControlProfiles'

    # --- CAS-001: Defender for Cloud Apps setup (proxy) -------------------------
    if ($null -eq $secureScoreLatest) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CAS-001' -Status NotAssessed -NotAssessedReason 'secureScoreLatest snapshot unavailable (requires SecurityEvents.Read.All).'))
    } else {
        $controlScores = @($secureScoreLatest.controlScores)
        $matched = @($controlScores | Where-Object { $_.controlName -and $_.controlName -in $setupControlNames })

        if ($matched.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CAS-001' -Status NotAssessed -NotAssessedReason "No matching Cloud App Security setup secure score control was found among: $($setupControlNames -join ', '). Microsoft may have renamed or retired this control; verify Defender for Cloud Apps setup manually in the Defender portal."))
        } else {
            $achieved = [double](@($matched | ForEach-Object { [double]$_.score }) | Measure-Object -Sum).Sum
            if ($achieved -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'CAS-001' -Status Pass -Evidence 'The Cloud App Security setup secure score control shows a non-zero contribution.'))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'CAS-001' -Status Fail -Evidence 'The Cloud App Security setup secure score control shows a zero contribution; Defender for Cloud Apps does not appear to be provisioned.'))
            }
        }
    }

    # --- CAS-002: relevant controls are not silently ignored --------------------
    if ($null -eq $controlProfiles) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CAS-002' -Status NotAssessed -NotAssessedReason 'secureScoreControlProfiles snapshot unavailable (requires SecurityEvents.Read.All).'))
    } else {
        $relevant = @($controlProfiles | Where-Object { $_.controlName -and $_.controlName -in $setupControlNames })

        if ($relevant.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CAS-002' -Status NotAssessed -NotAssessedReason "No matching Cloud App Security secure score control profile was found among: $($setupControlNames -join ', ')."))
        } else {
            $ignoredWithoutReview = @($relevant | Where-Object {
                    @($_.controlStateUpdates | Where-Object { $_.state -eq 'Ignored' }).Count -gt 0
                })

            if ($ignoredWithoutReview.Count -eq 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'CAS-002' -Status Pass -Evidence 'No Cloud App Security-relevant secure score control is marked Ignored.'))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'CAS-002' -Status Partial -Evidence "$($ignoredWithoutReview.Count) Cloud App Security-relevant control(s) are marked Ignored; confirm the decision was deliberate and documented."))
            }
        }
    }

    # --- CAS-003: coverage summary (informational, partial coverage) -----------
    $matchedControlCount = 0
    if ($secureScoreLatest) {
        $matchedControlCount = @(@($secureScoreLatest.controlScores) | Where-Object { $_.controlName -and $_.controlName -in $setupControlNames }).Count
    }
    $findings.Add((New-ZTAssessFinding -CheckId 'CAS-003' -Status Informational -Evidence "This domain is a best-effort Secure Score proxy: $matchedControlCount of $($setupControlNames.Count) candidate Cloud App Security control(s) were found in the tenant's secure score. Recommend a dedicated Defender for Cloud Apps portal review for full coverage." -SeverityOverride None))

    return $findings.ToArray()
}
