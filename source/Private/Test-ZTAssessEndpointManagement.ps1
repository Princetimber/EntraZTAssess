#Requires -Version 7.0

# Endpoint management assessor. Implements the estate checks EM-001 to
# EM-007 and the platform-specific checks (AND/IOS/MAC/WIN) against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessEndpointManagement {
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
    $deviceConfigurations = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'deviceConfigurations'
    $intents = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'intents'
    $configurationPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'configurationPolicies'
    $appProtectionPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'appProtectionPolicies'
    $enrollmentConfigs = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'enrollmentConfigurations'
    $autopilotDevices = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'autopilotDevices'
    $autopilotProfiles = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'autopilotProfiles'
    $applePush = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'applePushCertificate'
    $depSettings = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'depOnboardingSettings'
    $androidEnterprise = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'androidEnterpriseSettings'
    $mtdConnectors = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'mtdConnectors'
    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'

    if ($null -eq $managedDevices) {
        $allCheckIds = @(1..7 | ForEach-Object { 'EM-{0:d3}' -f $_ }) +
            @(1..4 | ForEach-Object { 'AND-{0:d3}' -f $_ }) +
            @(1..4 | ForEach-Object { 'IOS-{0:d3}' -f $_ }) +
            @(1..3 | ForEach-Object { 'MAC-{0:d3}' -f $_ }) +
            @(1..3 | ForEach-Object { 'WIN-{0:d3}' -f $_ })
        foreach ($checkId in $allCheckIds) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'managedDevices snapshot unavailable (requires DeviceManagementManagedDevices.Read.All and an Intune licence).'))
        }
        return $findings.ToArray()
    }

    $devices = @($managedDevices)
    $windowsDevices = @($devices | Where-Object { $_.operatingSystem -match 'Windows' })
    $iosDevices = @($devices | Where-Object { $_.operatingSystem -match 'iOS|iPadOS' })
    $macDevices = @($devices | Where-Object { $_.operatingSystem -match 'macOS|Mac OS' })
    $androidDevices = @($devices | Where-Object { $_.operatingSystem -match 'Android' })
    $corporate = { param($set) @($set | Where-Object { $_.managedDeviceOwnerType -eq 'company' }) }
    $personal = { param($set) @($set | Where-Object { $_.managedDeviceOwnerType -eq 'personal' }) }

    $assignedIntents = @($intents | Where-Object { $_.isAssigned })

    # =================== EM-001: Windows security baseline ===================
    if ($windowsDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-001' -Status NotAssessed -NotAssessedReason 'No Windows devices are enrolled.'))
    }
    elseif ($null -eq $intents -and $null -eq $configurationPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-001' -Status NotAssessed -NotAssessedReason 'Baseline snapshots unavailable (beta endpoints).'))
    }
    else {
        $baselineIntents = @($assignedIntents | Where-Object { $_.displayName -match 'baseline' })
        $baselineCatalog = @($configurationPolicies | Where-Object { $_.templateReference.templateFamily -match '[Bb]aseline' })

        if (($baselineIntents.Count + $baselineCatalog.Count) -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-001' -Status Pass -Evidence "Security baseline deployed: $(@($baselineIntents + $baselineCatalog | ForEach-Object { $_.displayName ?? $_.name }) -join ', '). Verify assignment coverage against the corporate Windows estate."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-001' -Status Fail -Evidence "No assigned security baseline found for the $($windowsDevices.Count)-device Windows estate."))
        }
    }

    # =================== EM-002: disk encryption coverage ====================
    $encryptables = @(& $corporate $windowsDevices) + @(& $corporate $macDevices)
    if ($encryptables.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-002' -Status NotAssessed -NotAssessedReason 'No corporate Windows or macOS devices to assess for encryption.'))
    }
    else {
        $encrypted = @($encryptables | Where-Object { $_.isEncrypted }).Count
        $pct = [math]::Round(100 * $encrypted / $encryptables.Count, 1)
        $evidence = "$encrypted of $($encryptables.Count) corporate Windows/macOS device(s) report encrypted storage ($pct%; threshold $($thresholds.EncryptionCoverageMinimumPercent)%)."

        if ($pct -ge $thresholds.EncryptionCoverageMinimumPercent) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-002' -Status Pass -Evidence $evidence))
        }
        elseif ($pct -ge 50) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-002' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-002' -Status Fail -Evidence $evidence))
        }
    }

    # =================== EM-003: MDE connector ===============================
    if ($null -eq $mtdConnectors) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-003' -Status NotAssessed -NotAssessedReason 'mobileThreatDefenseConnectors snapshot unavailable.'))
    }
    else {
        $enabledConnectors = @($mtdConnectors | Where-Object { $_.partnerState -eq 'enabled' })
        if ($enabledConnectors.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-003' -Status Pass -Evidence "Threat defence connector(s) enabled: $($enabledConnectors.Count). Device risk can inform compliance."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-003' -Status Fail -Evidence 'No enabled Defender for Endpoint / mobile threat defence connector; device risk plays no part in compliance.'))
        }
    }

    # =================== EM-004: endpoint security policy families ===========
    if ($null -eq $intents -and $null -eq $configurationPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-004' -Status NotAssessed -NotAssessedReason 'Endpoint security policy snapshots unavailable (beta endpoints).'))
    }
    else {
        $familyPatterns = @{
            Antivirus = 'antivirus|defender'
            Firewall  = 'firewall'
            ASR       = 'attack surface|asr'
            EDR       = 'edr|endpoint detection'
        }
        $allPolicies = @($assignedIntents) + @($configurationPolicies)
        $present = @()
        foreach ($family in $familyPatterns.Keys | Sort-Object) {
            $match = @($allPolicies | Where-Object {
                    ($_.displayName ?? $_.name ?? '') -match $familyPatterns[$family] -or
                    ($_.templateReference.templateFamily ?? '') -match $familyPatterns[$family]
                })
            if ($match.Count -gt 0) { $present += $family }
        }

        $evidence = "Endpoint security families detected: $(if ($present) { $present -join ', ' } else { 'none' }) of Antivirus, ASR, EDR, Firewall."
        if ($present.Count -ge 3) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-004' -Status Pass -Evidence $evidence))
        }
        elseif ($present.Count -ge 1) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-004' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-004' -Status Fail -Evidence $evidence))
        }
    }

    # =================== EM-005: Autopilot readiness ==========================
    $corporateWindows = & $corporate $windowsDevices
    if ($corporateWindows.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-005' -Status NotAssessed -NotAssessedReason 'No corporate Windows devices are enrolled.'))
    }
    elseif ($null -eq $autopilotDevices) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-005' -Status NotAssessed -NotAssessedReason 'Autopilot snapshots unavailable.'))
    }
    else {
        $profileCount = @($autopilotProfiles).Count
        $registered = @($autopilotDevices).Count
        $pct = [math]::Round(100 * [math]::Min($registered, $corporateWindows.Count) / $corporateWindows.Count, 1)
        $evidence = "Autopilot: $profileCount deployment profile(s), $registered registered device(s) against $($corporateWindows.Count) corporate Windows device(s) (~$pct%)."

        if ($profileCount -gt 0 -and $pct -ge $thresholds.AutopilotCoverageMinimumPercent) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-005' -Status Pass -Evidence $evidence))
        }
        elseif ($profileCount -gt 0 -and $registered -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-005' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-005' -Status Fail -Evidence $evidence))
        }
    }

    # =================== EM-006: co-management cloud signal ===================
    if ($windowsDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-006' -Status NotAssessed -NotAssessedReason 'No Windows devices are enrolled.'))
    }
    else {
        $configMgrOnly = @($windowsDevices | Where-Object { $_.managementAgent -eq 'configurationManagerClient' })
        if ($configMgrOnly.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-006' -Status Pass -Evidence 'All Windows devices emit a cloud (Intune or co-management) signal.'))
        }
        else {
            $pct = [math]::Round(100 * $configMgrOnly.Count / $windowsDevices.Count, 1)
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-006' -Status Partial -Evidence "$($configMgrOnly.Count) Windows device(s) ($pct%) are ConfigMgr-only with no cloud compliance signal."))
        }
    }

    # =================== EM-007: check-in hygiene =============================
    if ($devices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'EM-007' -Status NotAssessed -NotAssessedReason 'No managed devices to assess.'))
    }
    else {
        $staleCutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.StaleDeviceDays)
        $stale = @($devices | Where-Object { $_.lastSyncDateTime -and [datetime]$_.lastSyncDateTime -lt $staleCutoff })
        $pct = [math]::Round(100 * $stale.Count / $devices.Count, 1)
        $evidence = "$($stale.Count) of $($devices.Count) managed device(s) ($pct%) have not checked in within $($thresholds.StaleDeviceDays) days (threshold $($thresholds.StaleManagedDeviceMaxPercent)%)."

        if ($stale.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-007' -Status Pass -Evidence $evidence))
        }
        elseif ($pct -le $thresholds.StaleManagedDeviceMaxPercent) {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-007' -Status Partial -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'EM-007' -Status Fail -Evidence $evidence))
        }
    }

    # =================== Android: AND-001..004 ================================
    if ($androidDevices.Count -eq 0) {
        foreach ($checkId in 1..4 | ForEach-Object { 'AND-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'No Android devices are enrolled.'))
        }
    }
    else {
        # AND-001: Android Enterprise binding
        if ($null -eq $androidEnterprise) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-001' -Status NotAssessed -NotAssessedReason 'androidEnterpriseSettings snapshot unavailable (beta endpoint).'))
        }
        elseif ($androidEnterprise.bindStatus -eq 'bound' -or $androidEnterprise.bindStatus -eq 'boundAndValidated') {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-001' -Status Pass -Evidence "Tenant bound to managed Google Play (status: $($androidEnterprise.bindStatus))."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-001' -Status Fail -Evidence "Android devices are enrolled but the tenant is not bound to Android Enterprise (status: $($androidEnterprise.bindStatus ?? 'notBound'))."))
        }

        # AND-002: legacy device administrator enrolments
        $aeTypes = 'androidEnterprise|FullyManaged|DedicatedDevice|CorporateWorkProfile|WorkProfile|androidAOSP'
        $legacyDa = @($androidDevices | Where-Object { $_.deviceEnrollmentType -notmatch $aeTypes })
        if ($legacyDa.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-002' -Status Pass -Evidence 'All Android devices use Android Enterprise enrolment types.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-002' -Status Fail -Evidence "$($legacyDa.Count) Android device(s) appear to use legacy device administrator enrolment (types: $(@($legacyDa | Select-Object -ExpandProperty deviceEnrollmentType -Unique) -join ', '))."))
        }

        # AND-003: personal Android protected by MAM
        $personalAndroid = & $personal $androidDevices
        if ($personalAndroid.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-003' -Status Pass -Evidence 'No personally owned Android devices are enrolled.'))
        }
        else {
            $androidMam = @($appProtectionPolicies | Where-Object { $_.'@odata.type' -match 'androidManagedAppProtection' })
            if ($androidMam.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'AND-003' -Status Pass -Evidence "$($personalAndroid.Count) personal Android device(s); Android app protection policy present ($($androidMam.Count))."))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'AND-003' -Status Fail -Evidence "$($personalAndroid.Count) personally owned Android device(s) with no Android app protection policy."))
            }
        }

        # AND-004: corporate Android in corporate-owned profiles
        $corporateAndroid = & $corporate $androidDevices
        if ($corporateAndroid.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AND-004' -Status Pass -Evidence 'No corporate-owned Android devices are enrolled.'))
        }
        else {
            $corporateProfileTypes = 'FullyManaged|DedicatedDevice|CorporateWorkProfile'
            $misEnrolled = @($corporateAndroid | Where-Object { $_.deviceEnrollmentType -notmatch $corporateProfileTypes })
            if ($misEnrolled.Count -eq 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'AND-004' -Status Pass -Evidence "All $($corporateAndroid.Count) corporate Android device(s) use corporate-owned Android Enterprise profiles."))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'AND-004' -Status Fail -Evidence "$($misEnrolled.Count) corporate Android device(s) are not in corporate-owned profiles (types: $(@($misEnrolled | Select-Object -ExpandProperty deviceEnrollmentType -Unique) -join ', '))."))
            }
        }
    }

    # =================== iOS: IOS-001..004 ====================================
    $appleDevices = @($iosDevices) + @($macDevices)

    # IOS-001: APNs certificate
    if ($appleDevices.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IOS-001' -Status NotAssessed -NotAssessedReason 'No Apple devices are enrolled.'))
    }
    elseif ($null -eq $applePush -or -not $applePush.expirationDateTime) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IOS-001' -Status Fail -Evidence 'Apple devices are enrolled but no Apple MDM push certificate is configured.' -SeverityOverride Critical))
    }
    else {
        $expiry = [datetime]$applePush.expirationDateTime
        $daysRemaining = [int]($expiry - [datetime]::UtcNow).TotalDays
        if ($daysRemaining -lt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-001' -Status Fail -Evidence "The Apple MDM push certificate expired on $($expiry.ToString('yyyy-MM-dd')); Apple device management is inoperative." -SeverityOverride Critical))
        }
        elseif ($daysRemaining -le $thresholds.CertificateExpiryWarningDays) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-001' -Status Fail -Evidence "The Apple MDM push certificate expires in $daysRemaining day(s) ($($expiry.ToString('yyyy-MM-dd'))). Renew immediately with the same Apple ID."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-001' -Status Pass -Evidence "Apple MDM push certificate valid until $($expiry.ToString('yyyy-MM-dd')) ($daysRemaining days)."))
        }
    }

    # IOS-002: ADE token
    $corporateApple = @(& $corporate $iosDevices) + @(& $corporate $macDevices)
    if ($corporateApple.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IOS-002' -Status NotAssessed -NotAssessedReason 'No corporate Apple devices are enrolled.'))
    }
    elseif ($null -eq $depSettings -or @($depSettings).Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IOS-002' -Status Fail -Evidence "Corporate Apple devices exist ($($corporateApple.Count)) but no Apple Business Manager ADE token is configured."))
    }
    else {
        $expiring = @($depSettings | Where-Object {
                $_.tokenExpirationDateTime -and ([datetime]$_.tokenExpirationDateTime - [datetime]::UtcNow).TotalDays -le $thresholds.CertificateExpiryWarningDays
            })
        if ($expiring.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-002' -Status Partial -Evidence "ADE token(s) configured but $($expiring.Count) expire within $($thresholds.CertificateExpiryWarningDays) days: $(@($expiring | ForEach-Object { $_.tokenName }) -join ', ')."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-002' -Status Pass -Evidence "$(@($depSettings).Count) ADE token(s) configured and valid."))
        }
    }

    # IOS-003: corporate iOS supervised
    $corporateIos = & $corporate $iosDevices
    if ($corporateIos.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IOS-003' -Status NotAssessed -NotAssessedReason 'No corporate iOS devices are enrolled.'))
    }
    else {
        $supervised = @($corporateIos | Where-Object { $_.isSupervised }).Count
        $pct = [math]::Round(100 * $supervised / $corporateIos.Count, 1)
        $evidence = "$supervised of $($corporateIos.Count) corporate iOS device(s) are supervised ($pct%; threshold $($thresholds.SupervisedCorporateIosMinimumPercent)%)."
        if ($pct -ge $thresholds.SupervisedCorporateIosMinimumPercent) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-003' -Status Pass -Evidence $evidence))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-003' -Status Fail -Evidence $evidence))
        }
    }

    # IOS-004: personal iOS protected by MAM
    $personalIos = & $personal $iosDevices
    if ($personalIos.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IOS-004' -Status Pass -Evidence 'No personally owned iOS devices are enrolled.'))
    }
    else {
        $iosMam = @($appProtectionPolicies | Where-Object { $_.'@odata.type' -match 'iosManagedAppProtection' })
        if ($iosMam.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-004' -Status Pass -Evidence "$($personalIos.Count) personal iOS device(s); iOS app protection policy present ($($iosMam.Count))."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IOS-004' -Status Fail -Evidence "$($personalIos.Count) personally owned iOS device(s) with no iOS app protection policy."))
        }
    }

    # =================== macOS: MAC-001..003 ==================================
    $corporateMac = & $corporate $macDevices
    if ($macDevices.Count -eq 0) {
        foreach ($checkId in 1..3 | ForEach-Object { 'MAC-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'No macOS devices are enrolled.'))
        }
    }
    else {
        # MAC-001: ADE enrolment for corporate Macs
        if ($corporateMac.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MAC-001' -Status NotAssessed -NotAssessedReason 'No corporate macOS devices are enrolled.'))
        }
        else {
            $adeEnrolled = @($corporateMac | Where-Object { $_.deviceEnrollmentType -match 'appleBulkWithUser|appleBulkWithoutUser|dep' })
            $hasDepToken = $depSettings -and @($depSettings).Count -gt 0
            if ($adeEnrolled.Count -eq $corporateMac.Count) {
                $findings.Add((New-ZTAssessFinding -CheckId 'MAC-001' -Status Pass -Evidence "All $($corporateMac.Count) corporate Mac(s) enrolled via Automated Device Enrolment."))
            }
            elseif ($hasDepToken -and $adeEnrolled.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'MAC-001' -Status Partial -Evidence "$($adeEnrolled.Count) of $($corporateMac.Count) corporate Mac(s) enrolled via ADE; the remainder were enrolled manually and can be unenrolled by users."))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'MAC-001' -Status Fail -Evidence "No corporate Mac is enrolled via Automated Device Enrolment ($($corporateMac.Count) corporate Mac(s) present)."))
            }
        }

        # MAC-002: FileVault enforced
        $macCompliance = @($compliancePolicies | Where-Object { $_.'@odata.type' -match 'macOS' })
        $fileVaultEnforced = @($macCompliance | Where-Object { $_.storageRequireEncryption }).Count -gt 0
        $encryptedMacs = @($macDevices | Where-Object { $_.isEncrypted }).Count
        $encEvidence = "$encryptedMacs of $($macDevices.Count) Mac(s) report encrypted storage."
        if ($fileVaultEnforced) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MAC-002' -Status Pass -Evidence "FileVault required by macOS compliance policy. $encEvidence"))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'MAC-002' -Status Fail -Evidence "No macOS compliance policy requires FileVault. $encEvidence"))
        }

        # MAC-003: macOS security configuration (firewall/Gatekeeper)
        $macFirewallCompliance = @($macCompliance | Where-Object { $_.firewallEnabled }).Count -gt 0
        $macConfigs = @($deviceConfigurations | Where-Object { $_.'@odata.type' -match 'macOS' })
        if ($macFirewallCompliance -and $macConfigs.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MAC-003' -Status Pass -Evidence "macOS firewall required by compliance policy and $($macConfigs.Count) macOS configuration profile(s) deployed."))
        }
        elseif ($macFirewallCompliance -or $macConfigs.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MAC-003' -Status Partial -Evidence "Partial macOS security configuration: firewall-in-compliance=$macFirewallCompliance, configuration profiles=$($macConfigs.Count)."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'MAC-003' -Status Fail -Evidence 'No macOS security configuration (firewall or configuration profiles) is deployed.'))
        }
    }

    # =================== Windows: WIN-001..003 ================================
    if ($windowsDevices.Count -eq 0 -and @($entraDevices | Where-Object { $_.operatingSystem -match 'Windows' }).Count -eq 0) {
        foreach ($checkId in 1..3 | ForEach-Object { 'WIN-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'No Windows devices are present.'))
        }
    }
    else {
        # WIN-001: join-state strategy
        $entraWindows = @($entraDevices | Where-Object { $_.operatingSystem -match 'Windows' -and $_.accountEnabled })
        if ($entraWindows.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'WIN-001' -Status NotAssessed -NotAssessedReason 'No Entra device objects for Windows were found.'))
        }
        else {
            $joined = @($entraWindows | Where-Object { $_.trustType -eq 'AzureAd' }).Count
            $hybrid = @($entraWindows | Where-Object { $_.trustType -eq 'ServerAd' }).Count
            $registered = @($entraWindows | Where-Object { $_.trustType -eq 'Workplace' }).Count
            $evidence = "Windows join states: Entra joined=$joined, hybrid joined=$hybrid, registered=$registered."
            if ($joined -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'WIN-001' -Status Pass -Evidence $evidence))
            }
            elseif ($hybrid -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'WIN-001' -Status Partial -Evidence "$evidence The estate is hybrid-only; adopt Entra join for new devices."))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'WIN-001' -Status Fail -Evidence "$evidence Windows devices are only workplace-registered; no joined management plane exists."))
            }
        }

        # WIN-002: personal Windows enrolment mitigated
        $windowsRestrictions = @($enrollmentConfigs | Where-Object {
                $_.'@odata.type' -match 'PlatformRestriction' -and ($_.'@odata.type' -match 'windows' -or $_.platformType -match 'windows')
            })
        $personalWindowsBlocked = @($windowsRestrictions | Where-Object {
                $_.platformRestriction.personalDeviceEnrollmentBlocked -or $_.personalDeviceEnrollmentBlocked
            }).Count -gt 0
        $windowsMam = @($appProtectionPolicies | Where-Object { $_.'@odata.type' -match 'windowsManagedAppProtection|windowsInformationProtection' }).Count -gt 0
        $deviceCa = @($caPolicies | Where-Object {
                $_.state -eq 'enabled' -and @($_.grantControls.builtInControls) -contains 'compliantDevice'
            }).Count -gt 0

        if ($personalWindowsBlocked) {
            $findings.Add((New-ZTAssessFinding -CheckId 'WIN-002' -Status Pass -Evidence 'Personal Windows enrolment is blocked by enrolment restriction.'))
        }
        elseif ($windowsMam -or $deviceCa) {
            $findings.Add((New-ZTAssessFinding -CheckId 'WIN-002' -Status Pass -Evidence "Personal Windows enrolment is permitted but mitigated (Windows MAM=$windowsMam, compliant-device CA=$deviceCa)."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'WIN-002' -Status Fail -Evidence 'Personal Windows enrolment is permitted with neither Windows app protection nor compliant-device Conditional Access.'))
        }

        # WIN-003: BitLocker enforced
        $windowsCompliance = @($compliancePolicies | Where-Object { $_.'@odata.type' -match 'windows' })
        $bitLockerInCompliance = @($windowsCompliance | Where-Object { $_.bitLockerEnabled -or $_.storageRequireEncryption }).Count -gt 0
        $encryptionIntent = @($assignedIntents | Where-Object { $_.displayName -match 'encryption|bitlocker' }).Count -gt 0
        $encryptedWindows = @($windowsDevices | Where-Object { $_.isEncrypted }).Count
        $encEvidence = "$encryptedWindows of $($windowsDevices.Count) managed Windows device(s) report encrypted storage."

        if ($bitLockerInCompliance -or $encryptionIntent) {
            $findings.Add((New-ZTAssessFinding -CheckId 'WIN-003' -Status Pass -Evidence "BitLocker enforced (compliance policy=$bitLockerInCompliance, disk encryption policy=$encryptionIntent). $encEvidence"))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'WIN-003' -Status Fail -Evidence "No policy enforces BitLocker. $encEvidence"))
        }
    }

    return $findings.ToArray()
}
