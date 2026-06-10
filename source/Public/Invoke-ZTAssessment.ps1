#Requires -Version 7.0

function Invoke-ZTAssessment {
    <#
    .SYNOPSIS
    Runs a read-only Zero Trust assessment against the connected tenant.

    .DESCRIPTION
    Executes the assessment pipeline for the selected modules: collects raw
    configuration data from Microsoft Graph into redacted snapshots, runs
    the domain assessors against the persisted snapshots, scores the
    results, and writes findings.json, scores.json, and the run manifest
    into a timestamped run folder beneath the engagement's Runs folder.
    The run is read-only against the tenant; only local files are written.
    Requires an active connection established by Connect-ZTAssessment.

    .PARAMETER EngagementPath
    The engagement folder created by New-ZTAssessEngagement. Must contain
    engagement.psd1; the run folder is created beneath its Runs subfolder.

    .PARAMETER Modules
    The assessment modules to execute. Defaults to the modules selected at
    connection time. Supported: Identity, ConditionalAccess,
    PrivilegedAccess, Devices, IdentityGovernance, Applications,
    HybridIdentity, and Monitoring. The optional Sentinel module is not
    yet implemented.

    .PARAMETER SignInLookbackDays
    The number of days of sign-in data to aggregate for legacy
    authentication analysis. Defaults to the engagement settings value
    (30 days). Range 1 to 90.

    .EXAMPLE
    Invoke-ZTAssessment -EngagementPath 'D:\Assessments\Contoso-ENG-2026-042'

    Runs all modules selected at connection time and writes results to a
    new timestamped run folder.

    .EXAMPLE
    Invoke-ZTAssessment -EngagementPath $engagement.EngagementPath -Modules Identity, ConditionalAccess -SignInLookbackDays 14

    Runs only the identity and Conditional Access modules with a 14-day
    sign-in lookback.

    .OUTPUTS
    PSCustomObject
    A run summary with RunPath, Modules, FindingCounts, OverallScorePercent,
    OverallLevel, and RiskPosture.

    .NOTES
    Collector failures degrade gracefully: affected checks are reported as
    NotAssessed and the run continues. Reports are generated separately by
    Export-ZTAssessReport (later phase) from the persisted run folder.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EngagementPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules,

        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$SignInLookbackDays = 30
    )

    # Resolve tilde and relative paths, then verify this is an engagement folder.
    $EngagementPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($EngagementPath)
    if (-not (Test-Path -LiteralPath (Join-Path $EngagementPath 'engagement.psd1') -PathType Leaf)) {
        Write-Error -Message "No engagement.psd1 found in '$EngagementPath'. Create the engagement first with New-ZTAssessEngagement." -Category ObjectNotFound -ErrorAction Stop
    }

    $connection = $script:ZTAssessConnection
    if (-not $connection) {
        Write-Error -Message 'No active assessment connection. Run Connect-ZTAssessment before invoking the assessment.' -Category ConnectionError -ErrorAction Stop
    }

    # Work on a copy: the validated $Modules parameter cannot be reassigned
    # with a filtered (possibly empty) array.
    $selectedModules = if ($Modules) { @($Modules) } else { @($connection.Modules) }

    $supportedModules = @('Identity', 'ConditionalAccess', 'PrivilegedAccess', 'Devices', 'IdentityGovernance', 'Applications', 'HybridIdentity', 'Monitoring')
    $unsupported = @($selectedModules | Where-Object { $_ -notin $supportedModules })
    if ($unsupported.Count -gt 0) {
        Write-Warning ("The following selected modules are not yet implemented and will be skipped: {0}." -f ($unsupported -join ', '))
        $selectedModules = @($selectedModules | Where-Object { $_ -in $supportedModules })
    }
    if ($selectedModules.Count -eq 0) {
        Write-Error -Message "No supported modules selected. Supported modules: $($supportedModules -join ', ')." -Category InvalidArgument -ErrorAction Stop
    }

    $settings = Get-ZTAssessConfiguration -Name Settings
    $toolVersion = [string]$MyInvocation.MyCommand.Module.Version

    # --- Create the run folder ----------------------------------------------
    $runName = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $runPath = Join-Path -Path (Join-Path $EngagementPath 'Runs') -ChildPath $runName
    $null = New-Item -Path $runPath -ItemType Directory -Force -ErrorAction Stop
    $null = New-Item -Path (Join-Path $runPath 'Raw') -ItemType Directory -Force -ErrorAction Stop

    Set-LogFilePath -Path (Join-Path $runPath 'Logs/ztassess.log') -Force
    Write-ToLog -Message "Assessment run started: modules $($selectedModules -join ', ') against tenant $($connection.TenantId)." -Level INFO

    $manifest = New-ZTAssessRunManifest -ToolVersion $toolVersion -AuthMode $connection.AuthMode `
        -Account $connection.Account -TenantId $connection.TenantId -Environment $connection.Environment `
        -GrantedScopes @($connection.GrantedScopes) -MissingScopes @($connection.MissingScopes) -Modules @($selectedModules)

    # --- Collection ----------------------------------------------------------
    $collectionStatus = @{}
    $collectionStatus += Invoke-ZTAssessCoreCollection -RunPath $runPath -Manifest $manifest

    if ($selectedModules -contains 'Identity') {
        $collectionStatus += Invoke-ZTAssessIdentityCollection -RunPath $runPath -SignInLookbackDays $SignInLookbackDays -Manifest $manifest
    }
    if ($selectedModules -contains 'ConditionalAccess' -or $selectedModules -contains 'Identity' -or $selectedModules -contains 'PrivilegedAccess') {
        # CA policies feed identity (ID-003/004/009) and PA (PA-010) checks too.
        $collectionStatus += Invoke-ZTAssessConditionalAccessCollection -RunPath $runPath -Manifest $manifest
    }
    if ($selectedModules -contains 'PrivilegedAccess' -or $selectedModules -contains 'Identity') {
        # Role data feeds identity checks ID-002 and ID-009.
        $collectionStatus += Invoke-ZTAssessPrivilegedAccessCollection -RunPath $runPath -Manifest $manifest
    }
    if ($selectedModules -contains 'Devices') {
        $collectionStatus += Invoke-ZTAssessDeviceCollection -RunPath $runPath -Manifest $manifest
    }
    if ($selectedModules -contains 'IdentityGovernance' -or $selectedModules -contains 'Applications') {
        # The authorisation and consent policies feed both IG and AS checks.
        $collectionStatus += Invoke-ZTAssessGovernanceCollection -RunPath $runPath -Manifest $manifest
    }
    if ($selectedModules -contains 'Applications') {
        $collectionStatus += Invoke-ZTAssessApplicationCollection -RunPath $runPath -Manifest $manifest
        if ($selectedModules -notcontains 'PrivilegedAccess' -and $selectedModules -notcontains 'Identity') {
            # Application checks resolve service principals collected by the
            # privileged access collector; collect them when running alone.
            $collectionStatus += Invoke-ZTAssessPrivilegedAccessCollection -RunPath $runPath -Manifest $manifest
        }
    }
    if ($selectedModules -contains 'HybridIdentity') {
        $collectionStatus += Invoke-ZTAssessHybridCollection -RunPath $runPath -Manifest $manifest
    }
    if ($selectedModules -contains 'Monitoring') {
        $collectionStatus += Invoke-ZTAssessMonitoringCollection -RunPath $runPath -Manifest $manifest
    }

    $collectionStatus | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $runPath 'Raw/_collectionStatus.json') -Encoding utf8NoBOM

    # --- Assessment -----------------------------------------------------------
    $findings = [System.Collections.Generic.List[object]]::new()
    if ($selectedModules -contains 'Identity') {
        $findings.AddRange(@(Test-ZTAssessIdentitySecurity -RunPath $runPath -Settings $settings))
    }
    if ($selectedModules -contains 'ConditionalAccess') {
        $findings.AddRange(@(Test-ZTAssessConditionalAccess -RunPath $runPath -Settings $settings))
    }
    if ($selectedModules -contains 'PrivilegedAccess') {
        $findings.AddRange(@(Test-ZTAssessPrivilegedAccess -RunPath $runPath -Settings $settings))
    }
    if ($selectedModules -contains 'IdentityGovernance') {
        $findings.AddRange(@(Test-ZTAssessIdentityGovernance -RunPath $runPath -Settings $settings))
    }
    if ($selectedModules -contains 'Applications') {
        $findings.AddRange(@(Test-ZTAssessApplicationSecurity -RunPath $runPath -Settings $settings))
    }
    if ($selectedModules -contains 'HybridIdentity') {
        $findings.AddRange(@(Test-ZTAssessHybridIdentity -RunPath $runPath -Settings $settings))
    }
    if ($selectedModules -contains 'Monitoring') {
        $findings.AddRange(@(Test-ZTAssessMonitoring -RunPath $runPath -Settings $settings))
    }

    $findingsFolder = Join-Path $runPath 'Findings'
    $null = New-Item -Path $findingsFolder -ItemType Directory -Force

    if ($selectedModules -contains 'Devices') {
        $findings.AddRange(@(Test-ZTAssessDeviceTrust -RunPath $runPath -Settings $settings))
        $findings.AddRange(@(Test-ZTAssessEndpointManagement -RunPath $runPath -Settings $settings))
        $findings.AddRange(@(Test-ZTAssessByodGovernance -RunPath $runPath -Settings $settings))
        $findings.AddRange(@(Test-ZTAssessCorporateGovernance -RunPath $runPath -Settings $settings))

        # Persist the device classification and per-platform profiles for the
        # device enrolment and BYOD comparison reports (Phase 4).
        $managedDevices = Get-ZTAssessSnapshot -RunPath $runPath -Name 'managedDevices'
        $entraDevices = Get-ZTAssessSnapshot -RunPath $runPath -Name 'entraDevices'
        if ($managedDevices -or $entraDevices) {
            $deviceClasses = Get-ZTAssessDeviceClass -ManagedDevices @($managedDevices) -EntraDevices @($entraDevices) -Settings $settings
            ConvertTo-Json -InputObject @($deviceClasses) -Depth 10 |
                Set-Content -LiteralPath (Join-Path $findingsFolder 'deviceClassification.json') -Encoding utf8NoBOM

            $platformProfiles = Get-ZTAssessPlatformProfile -RunPath $runPath -DeviceClasses @($deviceClasses)
            ConvertTo-Json -InputObject @($platformProfiles) -Depth 10 |
                Set-Content -LiteralPath (Join-Path $findingsFolder 'platformProfiles.json') -Encoding utf8NoBOM
        }
    }
    ConvertTo-Json -InputObject @($findings) -Depth 10 |
        Set-Content -LiteralPath (Join-Path $findingsFolder 'findings.json') -Encoding utf8NoBOM

    # --- Scoring ---------------------------------------------------------------
    $scores = Measure-ZTAssessScore -Findings @($findings) -Settings $settings
    $scoresFolder = Join-Path $runPath 'Scores'
    $null = New-Item -Path $scoresFolder -ItemType Directory -Force
    $scores | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath (Join-Path $scoresFolder 'scores.json') -Encoding utf8NoBOM

    # --- Manifest ----------------------------------------------------------------
    $manifest.Complete()
    $null = Save-ZTAssessRunManifest -Manifest $manifest -RunPath $runPath

    $statusCounts = [ordered]@{}
    foreach ($group in ($findings | Group-Object -Property Status | Sort-Object -Property Name)) {
        $statusCounts[$group.Name] = $group.Count
    }

    Write-ToLog -Message "Assessment run complete: $($findings.Count) finding(s); overall maturity $($scores.OverallScorePercent)% ($($scores.OverallLevel))." -Level SUCCESS

    return [pscustomobject]@{
        PSTypeName          = 'ZTAssess.RunSummary'
        RunPath             = $runPath
        Modules             = @($selectedModules)
        FindingCounts       = [pscustomobject]$statusCounts
        OverallScorePercent = $scores.OverallScorePercent
        OverallLevel        = $scores.OverallLevel
        RiskPosture         = $scores.RiskPosture
    }
}
