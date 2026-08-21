#Requires -Version 7.0

# Wraps Connect-ExchangeOnline and Connect-IPPSSession for Pester mocking and
# dependency checking. Two auth modes are supported:
#   - Certificate-based, app-only (AppId + Certificate/CertificateThumbprint),
#     matching the Microsoft Graph connection this module already
#     establishes.
#   - A pre-obtained OAuth access token (-AccessToken), used to bridge the
#     device-code flow when Graph itself authenticated via -UseDeviceCode -
#     Connect-IPPSSession has no -Device switch of its own, so the token is
#     obtained separately (see Get-ZTAssessExchangeOnlineDeviceCodeToken) and
#     passed straight through here.
# -CommandName restricts the proxy functions imported into the session to
# the read-only allow-list (Get-ZTAssessExoAllowedCmdletName), so write
# cmdlets are never present in the session even before the static read-only
# QA gate is considered.
#
# NOTE: -CommandName support and the minimum required ExchangeOnlineManagement
# version for app-only Connect-IPPSSession (and -AccessToken support: EXO
# since v3.1.0, IPPS since v3.8.0-Preview1) should be verified against the
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

        [Parameter()]
        [string]$AppId,

        [Parameter()]
        [string]$CertificateThumbprint,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [string]$AccessToken
    )

    $commandName = if ($Surface -eq 'ExchangeOnline') { 'Connect-ExchangeOnline' } else { 'Connect-IPPSSession' }

    if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
        throw 'The ExchangeOnlineManagement module is required. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }

    if (-not $AccessToken -and -not $Certificate -and -not $CertificateThumbprint) {
        throw 'Either -AccessToken, -Certificate, or -CertificateThumbprint must be supplied.'
    }

    $connectParameters = @{
        Organization = $Organization
        ShowBanner   = $false
        CommandName  = Get-ZTAssessExoAllowedCmdletName
        ErrorAction  = 'Stop'
    }

    if ($AccessToken) {
        $connectParameters['AccessToken'] = $AccessToken
    } else {
        if (-not $AppId) {
            throw '-AppId is required for certificate-based authentication.'
        }
        $connectParameters['AppId'] = $AppId
        if ($Certificate) {
            $connectParameters['Certificate'] = $Certificate
        } else {
            $connectParameters['CertificateThumbprint'] = $CertificateThumbprint
        }
    }

    if ($Surface -eq 'ExchangeOnline') {
        $null = Connect-ExchangeOnline @connectParameters
    } else {
        $null = Connect-IPPSSession @connectParameters
    }
}
