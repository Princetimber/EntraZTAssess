#Requires -Version 7.0

# Wraps Connect-ExchangeOnline and Connect-IPPSSession for Pester mocking and
# dependency checking. Both surfaces use certificate-based, app-only
# authentication, matching the Microsoft Graph connection this module already
# establishes. -CommandName restricts the proxy functions imported into the
# session to the read-only allow-list (Get-ZTAssessExoAllowedCmdletName), so
# write cmdlets are never present in the session even before the static
# read-only QA gate is considered.
#
# NOTE: -CommandName support and the minimum required ExchangeOnlineManagement
# version for app-only Connect-IPPSSession should be verified against the
# pinned module version before relying on this in production; the static QA
# gate remains the authoritative read-only guarantee regardless.
function Connect-ExchangeOnlineWrapper {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ExchangeOnline', 'IPPS')]
        [string]$Surface,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Organization,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AppId,

        [Parameter()]
        [string]$CertificateThumbprint,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $commandName = if ($Surface -eq 'ExchangeOnline') { 'Connect-ExchangeOnline' } else { 'Connect-IPPSSession' }

    if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
        throw 'The ExchangeOnlineManagement module is required. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }

    if (-not $Certificate -and -not $CertificateThumbprint) {
        throw 'Either -Certificate or -CertificateThumbprint must be supplied.'
    }

    $connectParameters = @{
        Organization = $Organization
        AppId        = $AppId
        ShowBanner   = $false
        CommandName  = Get-ZTAssessExoAllowedCmdletName
        ErrorAction  = 'Stop'
    }

    if ($Certificate) {
        $connectParameters['Certificate'] = $Certificate
    } else {
        $connectParameters['CertificateThumbprint'] = $CertificateThumbprint
    }

    if ($Surface -eq 'ExchangeOnline') {
        $null = Connect-ExchangeOnline @connectParameters
    } else {
        $null = Connect-IPPSSession @connectParameters
    }
}
