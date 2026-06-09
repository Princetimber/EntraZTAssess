#Requires -Version 7.0

# Wraps Connect-MgGraph for Pester mocking and dependency checking.
# All Microsoft Graph SDK calls in this module go through wrapper functions
# so unit tests never require a live tenant or the Graph SDK itself.
function Connect-MgGraphWrapper {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter()]
        [string[]]$Scopes,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [string]$CertificateThumbprint,

        [Parameter()]
        [string]$Environment = 'Global',

        [Parameter()]
        [switch]$UseDeviceCode
    )

    if (-not (Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    $connectParameters = @{
        Environment = $Environment
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }

    if ($TenantId) {
        $connectParameters['TenantId'] = $TenantId
    }

    if ($ClientId -and $CertificateThumbprint) {
        # App-only (certificate) authentication: scopes are pre-consented
        # application permissions, so -Scopes is not passed.
        $connectParameters['ClientId'] = $ClientId
        $connectParameters['CertificateThumbprint'] = $CertificateThumbprint
    }
    else {
        if ($Scopes) {
            $connectParameters['Scopes'] = $Scopes
        }

        if ($UseDeviceCode) {
            $connectParameters['UseDeviceCode'] = $true
        }
    }

    $null = Connect-MgGraph @connectParameters
}
