#Requires -Version 7.0

function Connect-ZTAssessment {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph with least-privilege scopes for an assessment.

    .DESCRIPTION
    Establishes a read-only Microsoft Graph connection requesting only the
    scopes required by the selected assessment modules. After connecting, the
    granted scopes are compared with the required scopes; any shortfall is
    reported as a warning so the assessment can continue with graceful
    degradation (affected checks will be marked NotAssessed). Supports
    delegated interactive sign-in, device code sign-in, and app-only
    certificate authentication. No secrets are accepted or stored.

    .PARAMETER Modules
    The assessment modules the connection must support. Scopes are computed
    as the union for these modules plus the always-included Core module. Use
    Get-ZTAssessModuleCatalog to list valid names.

    .PARAMETER TenantId
    The directory (tenant) ID or domain name to connect to. Optional for
    delegated sign-in; mandatory guidance is to supply it for app-only
    authentication so the token is issued by the correct tenant.

    .PARAMETER Environment
    The national cloud environment to connect to. Valid values are Global,
    USGov, and China. Defaults to Global.

    .PARAMETER ClientId
    The application (client) ID of a customer-created app registration for
    app-only authentication. Must be used together with CertificateThumbprint.

    .PARAMETER CertificateThumbprint
    The thumbprint of a certificate in the current user or local machine
    certificate store used for app-only authentication. Must be used
    together with ClientId. Client secrets are deliberately not supported.

    .PARAMETER UseDeviceCode
    Uses the device code flow for delegated sign-in in environments where a
    local browser is unavailable. Ignored for app-only authentication.

    .EXAMPLE
    Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess

    Connects interactively requesting only the scopes those modules require
    and reports any scopes the tenant did not grant.

    .EXAMPLE
    Connect-ZTAssessment -Modules Devices -TenantId 'contoso.onmicrosoft.com' -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'

    Connects app-only with a certificate for an unattended device assessment.

    .OUTPUTS
    PSCustomObject
    A connection summary with TenantId, Account, AuthMode, Environment,
    Modules, RequiredScopes, GrantedScopes, and MissingScopes.

    .NOTES
    Requires the Microsoft.Graph.Authentication module. The connection is
    read-only by design: every scope in the catalogue is a Read scope and
    the toolkit's request helper rejects non-GET methods.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Delegated')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Delegated')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules,

        [Parameter(ParameterSetName = 'Delegated')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Delegated')]
        [Parameter(ParameterSetName = 'AppOnly')]
        [ValidateSet('Global', 'USGov', 'China')]
        [string]$Environment = 'Global',

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Delegated')]
        [switch]$UseDeviceCode
    )

    $requiredScopes = Get-ZTAssessRequiredPermission -Modules $Modules -AsScopeList -ErrorAction Stop

    $authMode = switch ($PSCmdlet.ParameterSetName) {
        'AppOnly' { 'AppOnly' }
        default { if ($UseDeviceCode) { 'DeviceCode' } else { 'Delegated' } }
    }

    Write-ToLog -Message "Connecting to Microsoft Graph ($authMode, $Environment) for module(s): $($Modules -join ', ')" -Level INFO -NoConsole

    try {
        $connectSplat = @{
            Environment = $Environment
        }

        if ($TenantId) {
            $connectSplat['TenantId'] = $TenantId
        }

        if ($authMode -eq 'AppOnly') {
            $connectSplat['ClientId'] = $ClientId
            $connectSplat['CertificateThumbprint'] = $CertificateThumbprint
        }
        else {
            $connectSplat['Scopes'] = $requiredScopes
            if ($UseDeviceCode) {
                $connectSplat['UseDeviceCode'] = $true
            }
        }

        Connect-MgGraphWrapper @connectSplat
    }
    catch {
        Write-ToLog -ErrorRecord $_ -NoConsole
        Write-Error -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Category ConnectionError -ErrorAction Stop
    }

    $context = Get-MgContextWrapper

    if (-not $context) {
        Write-Error -Message 'Connection completed but no Microsoft Graph context is available. The session may have been cancelled.' -Category ConnectionError -ErrorAction Stop
    }

    $grantedScopes = @($context.Scopes | Where-Object { $_ })
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin $grantedScopes })

    if ($authMode -ne 'AppOnly' -and $missingScopes.Count -gt 0) {
        Write-Warning ("The following required scopes were not granted: {0}. Checks that depend on them will be reported as NotAssessed." -f ($missingScopes -join ', '))
        Write-ToLog -Message "Missing scopes: $($missingScopes -join ', ')" -Level WARN -NoConsole
    }

    $summary = [pscustomobject]@{
        PSTypeName     = 'ZTAssess.ConnectionSummary'
        TenantId       = $context.TenantId
        Account        = $context.Account
        AuthMode       = $authMode
        Environment    = $Environment
        Modules        = @($Modules)
        RequiredScopes = @($requiredScopes)
        GrantedScopes  = $grantedScopes
        MissingScopes  = $missingScopes
    }

    # Cache the summary for use by Invoke-ZTAssessment and the run manifest.
    $script:ZTAssessConnection = $summary

    Write-ToLog -Message "Connected to tenant $($context.TenantId) as $($context.Account) ($authMode)" -Level SUCCESS -NoConsole

    return $summary
}
