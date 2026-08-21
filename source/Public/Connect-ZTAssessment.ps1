#Requires -Version 7.0

function Connect-ZTAssessment {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph with least-privilege scopes for an assessment.

    .DESCRIPTION
    Establishes a read-only Microsoft Graph connection requesting only the
    scopes required by the selected assessment modules. No secrets are accepted
    or stored.

    Certificate-based authentication (CBA) is the default. When called with just
    -Modules, the toolkit resolves app-only configuration from environment
    variables (ZTASSESS_TENANTID, ZTASSESS_CLIENTID, ZTASSESS_CERT_THUMBPRINT,
    ZTASSESS_CERT_PATH, ZTASSESS_ENVIRONMENT) and then a non-secret JSON config
    file at ~/.ztassess/auth.json, with environment variables overriding file
    values. If a complete app-only configuration is found it connects
    unattended with the certificate; otherwise it falls back to interactive
    delegated sign-in unless -NoInteractiveFallback is specified. App-only and
    delegated modes can also be selected explicitly via their parameters.

    After connecting, the granted scopes are compared with the required scopes;
    for delegated sign-in any shortfall is reported as a warning so the
    assessment can continue with graceful degradation (affected checks are
    marked NotAssessed).

    When a selected module requires the read-only Exchange Online / Security
    & Compliance (IPPS) surface (see Get-ZTAssessModuleCatalog), a second,
    lazily-established connection is attempted after Microsoft Graph
    connects. In app-only mode this reuses the same certificate. In
    device-code mode (-UseDeviceCode), the IPPS session-establishing cmdlet
    has no device-code switch of its own, so a separate Exchange Online
    device-code sign-in is performed and the resulting access token is used
    for both the Exchange Online and IPPS surfaces. This surface is skipped
    for plain interactive delegated sign-in. A failed or skipped Exchange
    Online / IPPS connection
    never fails the overall connection or affects Graph-only modules -
    dependent checks are simply reported as NotAssessed.

    .PARAMETER Modules
    The assessment modules the connection must support. Scopes are computed
    as the union for these modules plus the always-included Core module. Use
    Get-ZTAssessModuleCatalog to list valid names.

    .PARAMETER TenantId
    The directory (tenant) ID or domain name to connect to. Optional for
    delegated and auto sign-in; mandatory for the explicit app-only parameter
    sets so the token is issued by the correct tenant.

    .PARAMETER Environment
    The national cloud environment to connect to. Valid values are Global,
    USGov, and China. Defaults to Global.

    .PARAMETER ClientId
    The application (client) ID of a customer-created app registration for
    explicit app-only authentication. Used with CertificateThumbprint or
    CertificatePath.

    .PARAMETER CertificateThumbprint
    The thumbprint of a certificate in the Windows certificate store used for
    app-only authentication. Used together with ClientId. Client secrets are
    deliberately not supported.

    .PARAMETER CertificatePath
    The path to a PFX (PKCS#12) certificate file used for cross-platform
    app-only authentication. Loaded into memory and passed to Microsoft Graph;
    used together with ClientId on macOS, Linux, and Windows.

    .PARAMETER CertificatePassword
    The optional password protecting the PFX file supplied via CertificatePath,
    provided as a SecureString. Omit it for an unprotected PFX file.

    .PARAMETER Organization
    The verified domain (for example contoso.onmicrosoft.com) Exchange Online
    / Security & Compliance (IPPS) requires for modules that need that
    surface. Optional: resolved from ZTASSESS_ORGANIZATION, then
    ~/.ztassess/auth.json, then a domain-looking -TenantId, then derived from
    the connected tenant's initial verified domain if omitted entirely.

    .PARAMETER NoInteractiveFallback
    Disables the interactive delegated sign-in fallback in the default (auto)
    mode. When no certificate-based configuration can be resolved, the command
    throws instead of prompting, which is useful for automation contexts.

    .PARAMETER UseDeviceCode
    Uses the device code flow for delegated sign-in in environments where a
    local browser is unavailable. Ignored for app-only authentication.

    .EXAMPLE
    Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess

    Connects using the default certificate-based configuration when one is
    resolved, otherwise falls back to interactive delegated sign-in, requesting
    only the scopes those modules require.

    .EXAMPLE
    Connect-ZTAssessment -Modules Devices -TenantId 'contoso.onmicrosoft.com' -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -CertificatePath ~/certs/ztassess.pfx -CertificatePassword (Read-Host -AsSecureString)

    Connects app-only from a PFX file for a cross-platform unattended
    assessment on macOS, Linux, or Windows.

    .EXAMPLE
    Connect-ZTAssessment -Modules Identity -TenantId 'contoso.onmicrosoft.com' -ClientId '0bb09f73-1f0f-43e2-bebd-9b675a4e2ab3' -CertificateThumbprint 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0'

    Connects app-only using a certificate resolved from the Windows certificate
    store by thumbprint.

    .OUTPUTS
    PSCustomObject
    A connection summary with TenantId, Account, AuthMode, Environment,
    Modules, RequiredScopes, GrantedScopes, MissingScopes,
    ExchangeOnlineConnected, and ExchangeOnlineWarning.

    .NOTES
    Requires the Microsoft.Graph.Authentication module. The connection is
    read-only by design: every scope in the catalogue is a Read scope and
    the toolkit's request helper rejects non-GET methods.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Auto')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Auto')]
        [Parameter(Mandatory, ParameterSetName = 'Delegated')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnlyThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnlyCertificate')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules,

        [Parameter(ParameterSetName = 'Auto')]
        [Parameter(ParameterSetName = 'Delegated')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnlyThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnlyCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Auto')]
        [Parameter(ParameterSetName = 'Delegated')]
        [Parameter(ParameterSetName = 'AppOnlyThumbprint')]
        [Parameter(ParameterSetName = 'AppOnlyCertificate')]
        [ValidateSet('Global', 'USGov', 'China')]
        [string]$Environment = 'Global',

        [Parameter(Mandatory, ParameterSetName = 'AppOnlyThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'AppOnlyCertificate')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnlyThumbprint')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'AppOnlyCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificatePath,

        [Parameter(ParameterSetName = 'AppOnlyCertificate')]
        [securestring]$CertificatePassword,

        [Parameter(ParameterSetName = 'Auto')]
        [Parameter(ParameterSetName = 'Delegated')]
        [Parameter(ParameterSetName = 'AppOnlyThumbprint')]
        [Parameter(ParameterSetName = 'AppOnlyCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$Organization,

        [Parameter(ParameterSetName = 'Auto')]
        [switch]$NoInteractiveFallback,

        [Parameter(ParameterSetName = 'Delegated')]
        [switch]$UseDeviceCode
    )

    $requiredScopes = Get-ZTAssessRequiredPermission -Modules $Modules -AsScopeList -ErrorAction Stop

    # Module names are already validated by the call above; this second
    # lookup only determines whether the read-only Exchange Online / IPPS
    # surface needs to be established alongside Graph.
    $needsExchangeOnline = [bool](Get-ZTAssessModuleCatalog -Name $Modules | Where-Object { $_.RequiresExchangeOnline })

    $effectiveEnvironment = $Environment
    # $connectSplat is assembled per-mode below; $authMode records the mode for
    # the summary; $cbaConfigResolved flags a CBA attempt with known config so a
    # connect failure is surfaced loudly rather than silently falling back.
    $connectSplat = $null
    $authMode = $null
    $cbaConfigResolved = $false

    switch ($PSCmdlet.ParameterSetName) {
        'AppOnlyThumbprint' {
            $authMode = 'AppOnly'
            $connectSplat = @{
                Environment           = $effectiveEnvironment
                TenantId              = $TenantId
                ClientId              = $ClientId
                CertificateThumbprint = $CertificateThumbprint
            }
        }

        'AppOnlyCertificate' {
            $authMode = 'AppOnly'
            $certificate = Get-ZTAssessCertificate -Path $CertificatePath -Password $CertificatePassword -ErrorAction Stop
            $connectSplat = @{
                Environment = $effectiveEnvironment
                TenantId    = $TenantId
                ClientId    = $ClientId
                Certificate = $certificate
            }
        }

        'Delegated' {
            $authMode = if ($UseDeviceCode) { 'DeviceCode' } else { 'Delegated' }
            $connectSplat = @{
                Environment = $effectiveEnvironment
                Scopes      = $requiredScopes
            }
            if ($TenantId) {
                $connectSplat['TenantId'] = $TenantId
            }
            if ($UseDeviceCode) {
                $connectSplat['UseDeviceCode'] = $true
            }
        }

        default {
            # 'Auto' (the default): prefer certificate-based authentication,
            # fall back to interactive delegated sign-in unless disabled.
            $authConfig = Resolve-ZTAssessAuthConfig

            if ($authConfig) {
                $authMode = 'AppOnly'
                $cbaConfigResolved = $true
                if ($authConfig.Environment) {
                    $effectiveEnvironment = $authConfig.Environment
                }

                $connectSplat = @{
                    Environment = $effectiveEnvironment
                    TenantId    = $authConfig.TenantId
                    ClientId    = $authConfig.ClientId
                }

                if ($authConfig.CertificateThumbprint) {
                    $connectSplat['CertificateThumbprint'] = $authConfig.CertificateThumbprint
                } else {
                    $connectSplat['Certificate'] = Get-ZTAssessCertificate -Path $authConfig.CertificatePath -Password $CertificatePassword -ErrorAction Stop
                }

                Write-ToLog -Message "Resolved app-only configuration (source: $($authConfig.Source)); attempting certificate-based authentication." -Level INFO -NoConsole
            } elseif ($NoInteractiveFallback) {
                Write-Error -Message 'No certificate-based authentication configuration was found (checked ZTASSESS_* environment variables and ~/.ztassess/auth.json) and interactive fallback was disabled with -NoInteractiveFallback.' -Category ObjectNotFound -ErrorAction Stop
            } else {
                $authMode = 'Delegated'
                $connectSplat = @{
                    Environment = $effectiveEnvironment
                    Scopes      = $requiredScopes
                }
                if ($TenantId) {
                    $connectSplat['TenantId'] = $TenantId
                }
            }
        }
    }

    Write-ToLog -Message "Connecting to Microsoft Graph ($authMode, $effectiveEnvironment) for module(s): $($Modules -join ', ')" -Level INFO -NoConsole

    try {
        Connect-MgGraphWrapper @connectSplat
    } catch {
        Write-ToLog -ErrorRecord $_ -NoConsole
        if ($cbaConfigResolved) {
            Write-Error -Message "Failed to connect to Microsoft Graph using the resolved certificate-based configuration: $($_.Exception.Message)" -Category ConnectionError -ErrorAction Stop
        }
        Write-Error -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Category ConnectionError -ErrorAction Stop
    }

    $context = Get-MgContextWrapper

    if (-not $context) {
        Write-Error -Message 'Connection completed but no Microsoft Graph context is available. The session may have been cancelled.' -Category ConnectionError -ErrorAction Stop
    }

    $grantedScopes = @($context.Scopes | Where-Object { $_ })
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin $grantedScopes })

    if ($authMode -ne 'AppOnly' -and $missingScopes.Count -gt 0) {
        Write-Warning ('The following required scopes were not granted: {0}. Checks that depend on them will be reported as NotAssessed.' -f ($missingScopes -join ', '))
        Write-ToLog -Message "Missing scopes: $($missingScopes -join ', ')" -Level WARN -NoConsole
    }

    # --- Exchange Online / Security & Compliance (IPPS), lazily -------------
    # Only attempted when a selected module needs it, and only in app-only or
    # device-code mode. A failure here never fails the overall connection:
    # Graph-only modules must keep working, and dependent checks degrade to
    # NotAssessed, matching the existing collector-failure pattern.
    $exchangeOnlineConnected = $false
    $exchangeOnlineWarning = $null

    if ($needsExchangeOnline) {
        if ($authMode -eq 'AppOnly') {
            $resolvedOrganization = Resolve-ZTAssessOrganization -Organization $Organization -AuthConfig $authConfig -TenantId $context.TenantId

            if (-not $resolvedOrganization) {
                $exchangeOnlineWarning = 'Could not resolve an Exchange Online organization (verified domain). Supply -Organization or set ZTASSESS_ORGANIZATION. Dependent checks will be reported as NotAssessed.'
                Write-Warning $exchangeOnlineWarning
                Write-ToLog -Message $exchangeOnlineWarning -Level WARN -NoConsole
            } else {
                $exoConnectParameters = @{
                    Organization = $resolvedOrganization
                    AppId        = $connectSplat['ClientId']
                }
                if ($connectSplat.ContainsKey('Certificate')) {
                    $exoConnectParameters['Certificate'] = $connectSplat['Certificate']
                } else {
                    $exoConnectParameters['CertificateThumbprint'] = $connectSplat['CertificateThumbprint']
                }

                try {
                    Connect-ExchangeOnlineWrapper -Surface ExchangeOnline @exoConnectParameters
                    Connect-ExchangeOnlineWrapper -Surface IPPS @exoConnectParameters
                    $exchangeOnlineConnected = $true
                    Write-ToLog -Message "Connected to Exchange Online / Security & Compliance ($resolvedOrganization)." -Level SUCCESS -NoConsole
                } catch {
                    $exchangeOnlineWarning = "Failed to connect to Exchange Online / Security & Compliance: $($_.Exception.Message). Dependent checks will be reported as NotAssessed."
                    Write-Warning $exchangeOnlineWarning
                    Write-ToLog -ErrorRecord $_ -NoConsole
                }
            }
        } elseif ($authMode -eq 'DeviceCode') {
            $resolvedOrganization = Resolve-ZTAssessOrganization -Organization $Organization -AuthConfig $authConfig -TenantId $context.TenantId

            if (-not $resolvedOrganization) {
                $exchangeOnlineWarning = 'Could not resolve an Exchange Online organization (verified domain). Supply -Organization or set ZTASSESS_ORGANIZATION. Dependent checks will be reported as NotAssessed.'
                Write-Warning $exchangeOnlineWarning
                Write-ToLog -Message $exchangeOnlineWarning -Level WARN -NoConsole
            } else {
                try {
                    Write-ToLog -Message 'Exchange Online / Security & Compliance requires a separate device-code sign-in (Microsoft Graph and Exchange Online use different resources and cannot share a token).' -Level INFO -NoConsole
                    $exoAccessToken = Get-ZTAssessExchangeOnlineDeviceCodeToken -TenantId $context.TenantId -ErrorAction Stop

                    Connect-ExchangeOnlineWrapper -Surface ExchangeOnline -Organization $resolvedOrganization -AccessToken $exoAccessToken
                    Connect-ExchangeOnlineWrapper -Surface IPPS -Organization $resolvedOrganization -AccessToken $exoAccessToken
                    $exchangeOnlineConnected = $true
                    Write-ToLog -Message "Connected to Exchange Online / Security & Compliance via device code ($resolvedOrganization)." -Level SUCCESS -NoConsole
                } catch {
                    $exchangeOnlineWarning = "Failed to connect to Exchange Online / Security & Compliance via device code: $($_.Exception.Message). Dependent checks will be reported as NotAssessed."
                    Write-Warning $exchangeOnlineWarning
                    Write-ToLog -ErrorRecord $_ -NoConsole
                }
            }
        } else {
            $exchangeOnlineWarning = 'Exchange Online / Security & Compliance requires certificate-based app-only authentication or device-code sign-in (-UseDeviceCode); it was skipped for interactive delegated sign-in. Dependent checks will be reported as NotAssessed.'
            Write-Warning $exchangeOnlineWarning
            Write-ToLog -Message $exchangeOnlineWarning -Level WARN -NoConsole
        }
    }

    $summary = [pscustomobject]@{
        PSTypeName              = 'ZTAssess.ConnectionSummary'
        TenantId                = $context.TenantId
        Account                 = $context.Account
        AuthMode                = $authMode
        Environment             = $effectiveEnvironment
        Modules                 = @($Modules)
        RequiredScopes          = @($requiredScopes)
        GrantedScopes           = $grantedScopes
        MissingScopes           = $missingScopes
        ExchangeOnlineConnected = $exchangeOnlineConnected
        ExchangeOnlineWarning   = $exchangeOnlineWarning
    }

    # Cache the summary for use by Invoke-ZTAssessment and the run manifest.
    $script:ZTAssessConnection = $summary

    Write-ToLog -Message "Connected to tenant $($context.TenantId) as $($context.Account) ($authMode)" -Level SUCCESS -NoConsole

    return $summary
}
