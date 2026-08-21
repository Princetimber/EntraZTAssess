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
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

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

    if ($ClientId -and $Certificate) {
        # App-only (certificate) authentication, cross-platform path: the
        # certificate object is passed directly so no Windows certificate
        # store lookup is needed. Scopes are pre-consented application
        # permissions, so -Scopes is not passed.
        $connectParameters['ClientId'] = $ClientId
        $connectParameters['Certificate'] = $Certificate
    } elseif ($ClientId -and $CertificateThumbprint) {
        # App-only (certificate) authentication, Windows certificate store
        # path: Connect-MgGraph resolves the thumbprint from the store.
        # Scopes are pre-consented application permissions, so -Scopes is
        # not passed.
        $connectParameters['ClientId'] = $ClientId
        $connectParameters['CertificateThumbprint'] = $CertificateThumbprint
    } else {
        if ($Scopes) {
            $connectParameters['Scopes'] = $Scopes
        }

        if ($UseDeviceCode) {
            $connectParameters['UseDeviceCode'] = $true
        }
    }

    if ($UseDeviceCode) {
        # Device-code sign-in must NOT have its output captured. On several
        # Microsoft.Graph.Authentication SDK versions the "To sign in, use a
        # web browser..." device-code prompt is emitted through the same
        # stream as the cmdlet's return value rather than reliably via
        # Write-Host, so assigning the call to a variable (even `$null =`)
        # or piping it to Out-Null silently swallows the prompt the user
        # needs to read and act on - confirmed by a Microsoft maintainer:
        # https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/1403#issuecomment-1191685915
        # and tracked as an open SDK defect:
        # https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/2798
        # Connect-ZTAssessment retrieves the resulting context separately via
        # Get-MgContextWrapper, so no return value is needed here.
        Connect-MgGraph @connectParameters
    } else {
        $null = Connect-MgGraph @connectParameters
    }
}
