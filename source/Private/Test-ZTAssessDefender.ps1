#Requires -Version 7.0

# Defender assessor. Implements checks DF-001 to DF-004 against persisted
# snapshots. Pure function over data on disk: no network calls. Device
# onboarding coverage (DF-002) is a best-effort proxy derived from the
# tenant's Secure Score control contribution, since Microsoft Graph exposes
# no direct "onboarded machines" list for Defender for Endpoint.
function Test-ZTAssessDefender {
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
    $onboardingControlNames = @($Settings.Defender.OnboardingControlNames)

    $findings = [System.Collections.Generic.List[object]]::new()

    $secureScoreLatest = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'secureScoreLatest'
    $controlProfiles = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'secureScoreControlProfiles'
    $unifiedAlerts = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'unifiedAlerts'

    # --- DF-001: Secure Score meets the maturity floor -------------------------
    if ($null -eq $secureScoreLatest) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DF-001' -Status NotAssessed -NotAssessedReason 'secureScoreLatest snapshot unavailable (requires SecurityEvents.Read.All).'))
    } else {
        $maxScore = [double]$secureScoreLatest.maxScore
        if ($maxScore -le 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DF-001' -Status NotAssessed -NotAssessedReason 'Secure Score maxScore was zero or unavailable; a percentage could not be computed.'))
        } else {
            $percent = [math]::Round(([double]$secureScoreLatest.currentScore / $maxScore) * 100, 1)
            if ($percent -ge [double]$thresholds.SecureScoreMinimumPercent) {
                $findings.Add((New-ZTAssessFinding -CheckId 'DF-001' -Status Pass -Evidence "Secure Score is $percent% (threshold: $($thresholds.SecureScoreMinimumPercent)%)."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'DF-001' -Status Fail -Evidence "Secure Score is $percent%, below the $($thresholds.SecureScoreMinimumPercent)% maturity floor."))
            }
        }
    }

    # --- DF-002: Defender for Endpoint device-onboarding coverage (proxy) ------
    if ($null -eq $secureScoreLatest) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status NotAssessed -NotAssessedReason 'secureScoreLatest snapshot unavailable (requires SecurityEvents.Read.All).'))
    } else {
        $controlScores = @($secureScoreLatest.controlScores)
        $matched = @($controlScores | Where-Object { $_.controlName -and $_.controlName -in $onboardingControlNames })

        if ($matched.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status NotAssessed -NotAssessedReason "No matching device-onboarding secure score control was found among: $($onboardingControlNames -join ', '). Microsoft may have renamed or retired this control; verify device onboarding manually in the Defender portal."))
        } else {
            $achieved = [double](@($matched | ForEach-Object { [double]$_.score }) | Measure-Object -Sum).Sum
            $matchedNames = @($matched | ForEach-Object { $_.controlName })
            $maxForControls = 0.0
            if ($controlProfiles) {
                $maxForControls = [double](@($controlProfiles | Where-Object { $_.controlName -in $matchedNames } | ForEach-Object { [double]$_.maxScore }) | Measure-Object -Sum).Sum
            }

            if ($maxForControls -le 0) {
                if ($achieved -gt 0) {
                    $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status Partial -Evidence "The device-onboarding secure score control shows a non-zero contribution ($achieved), but its maximum achievable score is unavailable to compute full coverage."))
                } else {
                    $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status Fail -Evidence 'The device-onboarding secure score control shows a zero contribution; no devices appear onboarded to Microsoft Defender for Endpoint.'))
                }
            } else {
                $coveragePercent = [math]::Round(($achieved / $maxForControls) * 100, 1)
                if ($coveragePercent -ge 100) {
                    $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status Pass -Evidence "Device-onboarding secure score control is fully achieved ($coveragePercent%)."))
                } elseif ($coveragePercent -gt 0) {
                    $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status Partial -Evidence "Device-onboarding secure score control is partially achieved ($coveragePercent%); some endpoints may not be onboarded."))
                } else {
                    $findings.Add((New-ZTAssessFinding -CheckId 'DF-002' -Status Fail -Evidence 'The device-onboarding secure score control shows 0% coverage; no devices appear onboarded to Microsoft Defender for Endpoint.'))
                }
            }
        }
    }

    # --- DF-003: high-severity alerts triaged within SLA -----------------------
    if ($null -eq $unifiedAlerts) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DF-003' -Status NotAssessed -NotAssessedReason 'unifiedAlerts snapshot unavailable (requires SecurityAlert.Read.All).'))
    } else {
        $cutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.OpenHighSeverityAlertMaxAgeDays)
        $openHigh = @($unifiedAlerts | Where-Object { $_.severity -eq 'high' -and $_.status -in @('new', 'inProgress') })
        $overdue = @($openHigh | Where-Object { $_.createdDateTime -and [datetime]$_.createdDateTime -lt $cutoff })

        if ($openHigh.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DF-003' -Status Pass -Evidence 'No open high-severity alerts.'))
        } elseif ($overdue.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DF-003' -Status Pass -Evidence "$($openHigh.Count) open high-severity alert(s), all within the $($thresholds.OpenHighSeverityAlertMaxAgeDays)-day triage window."))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'DF-003' -Status Fail -Evidence "$($overdue.Count) of $($openHigh.Count) open high-severity alert(s) are overdue beyond $($thresholds.OpenHighSeverityAlertMaxAgeDays) days."))
        }
    }

    # --- DF-004: secure score improvement opportunities (informational) -------
    $topGapsText = 'secure score control gap data unavailable'
    if ($secureScoreLatest -and $controlProfiles) {
        $scoreByControl = @{}
        foreach ($controlScore in @($secureScoreLatest.controlScores)) {
            if ($controlScore.controlName) {
                $scoreByControl[$controlScore.controlName] = [double]$controlScore.score
            }
        }

        $gaps = foreach ($controlProfile in @($controlProfiles)) {
            if (-not $controlProfile.controlName) { continue }
            $achievedScore = if ($scoreByControl.ContainsKey($controlProfile.controlName)) { $scoreByControl[$controlProfile.controlName] } else { 0.0 }
            if ([double]$controlProfile.maxScore -gt 0 -and $achievedScore -le 0) {
                [pscustomobject]@{ Title = $controlProfile.title; Rank = [int]$controlProfile.rank }
            }
        }

        $topGaps = @($gaps | Sort-Object -Property Rank | Select-Object -First 5)
        $topGapsText = if ($topGaps.Count -gt 0) {
            "top unimplemented control(s) by rank: $(($topGaps | ForEach-Object { $_.Title }) -join '; ')"
        } else {
            'no unimplemented secure score controls detected'
        }
    }
    $findings.Add((New-ZTAssessFinding -CheckId 'DF-004' -Status Informational -Evidence "Secure Score improvement summary: $topGapsText." -SeverityOverride None))

    return $findings.ToArray()
}
