#Requires -Version 7.0

function Get-ZTAssessFinding {
    <#
    .SYNOPSIS
    Retrieves the findings from a completed assessment run.

    .DESCRIPTION
    Reads the persisted findings.json from a run folder produced by
    Invoke-ZTAssessment and returns the findings as objects, optionally
    filtered by domain, status, or severity. Reading from disk means
    findings can be inspected, filtered, and re-reported at any time
    without tenant access.

    .PARAMETER RunPath
    The run folder produced by Invoke-ZTAssessment (the folder containing
    the Findings subfolder).

    .PARAMETER Domain
    Optionally filters findings to one or more assessment domains, for
    example IdentitySecurity or ConditionalAccess.

    .PARAMETER Status
    Optionally filters findings to one or more statuses: Pass, Fail,
    Partial, NotAssessed, or Informational.

    .PARAMETER Severity
    Optionally filters findings to one or more severities: Critical, High,
    Medium, Low, or None.

    .EXAMPLE
    Get-ZTAssessFinding -RunPath 'D:\Assessments\Contoso-ENG-2026-042\Runs\20260610-0930'

    Returns every finding from the run.

    .EXAMPLE
    Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail -Severity Critical, High

    Returns only the failed findings rated Critical or High - the core of
    the remediation conversation.

    .OUTPUTS
    PSCustomObject
    One object per finding with CheckId, Domain, Title, Status, Severity,
    Evidence, Rationale, Remediation, and related properties.

    .NOTES
    Performs no network calls; operates entirely on the persisted run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath (Join-Path $_ 'Findings/findings.json') -PathType Leaf })]
        [string]$RunPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Domain,

        [Parameter()]
        [ValidateSet('Pass', 'Fail', 'Partial', 'NotAssessed', 'Informational')]
        [string[]]$Status,

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'None')]
        [string[]]$Severity
    )

    $findingsPath = Join-Path $RunPath 'Findings/findings.json'

    try {
        $findings = Get-Content -LiteralPath $findingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20
    }
    catch {
        Write-Error -Message "Failed to read findings from '$findingsPath': $($_.Exception.Message)" -Category ReadError -ErrorAction Stop
    }

    $results = @($findings)
    if ($Domain) { $results = @($results | Where-Object { $_.Domain -in $Domain }) }
    if ($Status) { $results = @($results | Where-Object { $_.Status -in $Status }) }
    if ($Severity) { $results = @($results | Where-Object { $_.Severity -in $Severity }) }

    return $results | Sort-Object -Property CheckId
}
