#Requires -Version 7.0

function New-ZTAssessEngagement {
    <#
    .SYNOPSIS
    Scaffolds a new assessment engagement folder and settings file.

    .DESCRIPTION
    Creates the engagement folder structure used by every assessment run and
    writes an engagement.psd1 settings file capturing the customer name,
    engagement reference, and report branding placeholders. Runs are stored
    beneath the engagement folder, one timestamped folder per run, keeping
    raw evidence, findings, scores, logs, and reports together per customer.
    The engagement folder should reside on an encrypted volume.

    .PARAMETER CustomerName
    The customer's display name as it should appear on report covers and
    headers, for example 'Contoso Ltd'.

    .PARAMETER Reference
    The consultancy's engagement reference, for example 'ENG-2026-042'.
    Used in the folder name and on report covers. Letters, digits, hyphens,
    and underscores only.

    .PARAMETER OutputPath
    The parent folder beneath which the engagement folder is created. Must
    already exist; the engagement folder itself must not.

    .PARAMETER Classification
    The protective marking applied to all generated reports, for example
    'Confidential - Contoso'. Defaults to 'Confidential'.

    .EXAMPLE
    New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-042' -OutputPath 'D:\Assessments'

    Creates D:\Assessments\Contoso-Ltd-ENG-2026-042 with its engagement.psd1
    and empty Runs folder.

    .EXAMPLE
    New-ZTAssessEngagement -CustomerName 'Fabrikam' -Reference 'ENG-2026-007' -OutputPath '/assess' -Classification 'Official-Sensitive' -WhatIf

    Shows what would be created without making any change.

    .OUTPUTS
    PSCustomObject
    An engagement summary with EngagementPath, SettingsPath, CustomerName,
    and Reference.

    .NOTES
    This function only creates local folders and a settings file; it makes
    no tenant connection and no Graph calls.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CustomerName,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
        [string]$Reference,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
        [string]$OutputPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Classification = 'Confidential'
    )

    # Folder-safe customer name: letters, digits, hyphens.
    $safeCustomer = ($CustomerName -replace '[^a-zA-Z0-9]+', '-').Trim('-')
    $engagementFolderName = "$safeCustomer-$Reference"
    $engagementPath = Join-Path -Path $OutputPath -ChildPath $engagementFolderName

    if (Test-Path -LiteralPath $engagementPath) {
        Write-Error -Message "Engagement folder already exists: $engagementPath. Use a different reference or remove the existing folder." -Category ResourceExists -ErrorAction Stop
    }

    $settingsPath = Join-Path -Path $engagementPath -ChildPath 'engagement.psd1'

    if ($PSCmdlet.ShouldProcess($engagementPath, 'Create engagement folder structure')) {
        try {
            $null = New-Item -Path $engagementPath -ItemType Directory -ErrorAction Stop
            $null = New-Item -Path (Join-Path -Path $engagementPath -ChildPath 'Runs') -ItemType Directory -ErrorAction Stop

            $engagementContent = @"
@{
    # EntraZTAssess engagement settings.
    CustomerName   = '$($CustomerName -replace "'", "''")'
    Reference      = '$Reference'
    Classification = '$($Classification -replace "'", "''")'
    Created        = '$([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))'

    # Report branding (paths relative to this folder, or absolute).
    Branding = @{
        ConsultancyName = ''
        ConsultantName  = ''
        CustomerLogo    = ''
        ConsultancyLogo = ''
    }

    # Per-engagement threshold overrides. Any key from the module's
    # settings.psd1 Thresholds table may be overridden here.
    ThresholdOverrides = @{
    }
}
"@
            Set-Content -LiteralPath $settingsPath -Value $engagementContent -Encoding utf8NoBOM -ErrorAction Stop
            Write-ToLog -Message "Engagement scaffolded at $engagementPath" -Level SUCCESS -NoConsole
        }
        catch {
            Write-Error -Message "Failed to scaffold engagement at '$engagementPath': $($_.Exception.Message)" -Category WriteError -ErrorAction Stop
        }
    }

    return [pscustomobject]@{
        PSTypeName     = 'ZTAssess.Engagement'
        EngagementPath = $engagementPath
        SettingsPath   = $settingsPath
        CustomerName   = $CustomerName
        Reference      = $Reference
        Classification = $Classification
    }
}
