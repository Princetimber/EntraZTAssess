#Requires -Version 7.0

function New-ZTAssessAppRegistration {
    <#
    .SYNOPSIS
    Provisions the EntraZTAssess app registration with read-only Graph permissions.

    .DESCRIPTION
    Creates an Entra ID application registration and service principal for the
    EntraZTAssess assessment toolkit, grants it the least-privilege, read-only
    Microsoft Graph application permissions required by the selected assessment
    modules, uploads the assessment certificate as a credential, and writes a
    non-secret JSON configuration for Connect-ZTAssessment to consume.

    This is an admin-run, one-time setup step. It uses the Microsoft.Graph SDK
    directly and therefore performs Graph WRITE operations, which is why it lives
    in the repo-local EntraZTAssess.Provisioning module rather than in the
    read-only assessment module under source/.

    The interactive sign-in for THIS function requests elevated setup scopes,
    requested only as needed: Application.ReadWrite.All is always requested to
    create the application and service principal; AppRoleAssignment.ReadWrite.All
    is additionally requested only when -GrantAdminConsent is supplied, since it
    is only exercised when creating app role assignments directly. Those elevated
    scopes are used only for this provisioning step; they are NOT the scopes the
    assessment itself uses. The assessment runs exclusively with the read-only
    application permissions granted to the new app.

    By default the function does NOT grant admin consent programmatically. It emits
    an admin-consent URL that a Privileged Role Administrator (or Global
    Administrator) must approve, since every permission granted is a Microsoft
    Graph application permission and Application Administrator / Cloud
    Application Administrator cannot consent to those. Supply -GrantAdminConsent
    to create the app role assignments directly (also requires a Privileged Role
    Administrator or Global Administrator session).

    Re-running this function against a tenant that already has an application
    registered under the same -DisplayName does not silently create a duplicate.
    It stops with an actionable error naming the existing application's AppId
    unless -Force is supplied, in which case a new application is created
    alongside the existing one.

    .PARAMETER TenantId
    The directory (tenant) ID or domain name in which to create the application.

    .PARAMETER Modules
    The assessment modules whose read-only Graph scopes should be granted to the
    application. Defaults to every non-optional module in the assessment
    catalogue. The always-included Core module is added automatically.

    .PARAMETER CertificatePath
    Path to the public certificate (.cer) produced by New-ZTAssessCertificate.
    Its public key is uploaded to the application as a verification credential and
    its thumbprint is recorded in the output configuration.

    .PARAMETER DisplayName
    The display name of the application registration. Defaults to
    'EntraZTAssess-Assessment'.

    .PARAMETER Environment
    The national cloud to provision in. Valid values are Global, USGov, and China.
    Defaults to Global.

    .PARAMETER UseDeviceCode
    Uses the device code flow for the one-time interactive Microsoft Graph
    sign-in this function performs, instead of the default interactive
    browser sign-in. Use this when a local browser is unavailable, or when
    the tenant's Conditional Access policy blocks interactive browser
    sign-in and requires device code authentication instead.

    .PARAMETER GrantAdminConsent
    Grants the read-only application permissions programmatically by creating app
    role assignments on the new service principal. Requires a Privileged Role
    Administrator or Global Administrator session. When omitted, an admin-consent
    URL is emitted for a Privileged Role Administrator (or Global Administrator)
    to approve instead.

    .PARAMETER Force
    Creates a new application registration even when one with the same
    -DisplayName already exists in the tenant. Without this switch, the function
    stops with an actionable error naming the existing application's AppId rather
    than silently creating a duplicate.

    .PARAMETER ConfigOutputPath
    Path of the non-secret JSON configuration file to write for
    Connect-ZTAssessment. Defaults to ~/.ztassess/auth.json. No password or secret
    is ever written to this file.

    .EXAMPLE
    New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' -CertificatePath ~/.ztassess/EntraZTAssess.cer

    Creates the application with the default read-only scopes, uploads the
    certificate, writes ~/.ztassess/auth.json, and prints an admin-consent URL for
    a Privileged Role Administrator (or Global Administrator) to approve.

    .EXAMPLE
    New-ZTAssessAppRegistration -TenantId '00000000-0000-0000-0000-000000000000' -CertificatePath ./EntraZTAssess.cer -Modules Identity, ConditionalAccess, Devices -GrantAdminConsent

    Creates the application scoped to three assessment modules and grants admin
    consent programmatically.

    .EXAMPLE
    New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' -CertificatePath ~/.ztassess/EntraZTAssess.cer -UseDeviceCode

    Creates the application using the device code flow for the interactive
    sign-in, for tenants whose Conditional Access policy blocks interactive
    browser sign-in.

    .OUTPUTS
    PSCustomObject
    A summary with ClientId, TenantId, CertificateThumbprint, ConfigPath,
    ConsentUrl, and FailedGrants (an empty array unless -GrantAdminConsent
    was supplied and one or more app role assignments failed).

    .NOTES
    Requires the Microsoft.Graph SDK modules (Microsoft.Graph.Authentication,
    Microsoft.Graph.Applications). All permissions granted to the created
    application are read-only Graph application permissions and require admin
    consent before the assessment can run.

    Supports -WhatIf/-Confirm. The Microsoft Graph sign-in itself is gated by
    ShouldProcess because it can create or refresh a delegated consent grant in
    the directory; under -WhatIf the function reports what would happen and
    returns without connecting.

    If Microsoft Graph returns a transient throttling (429) or service (5xx)
    error while creating the application, service principal, credential, or an
    app role assignment, rerun this function. If a partial application
    registration was already created before the failure, supply -Force to
    proceed rather than stopping on the idempotency guard.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive admin-run provisioning function; coloured console guidance is intentional and not pipeline output.')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+)$',
            ErrorMessage = 'TenantId must be a directory (tenant) GUID or a verified domain name, e.g. contoso.onmicrosoft.com.'
        )]
        [string]$TenantId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificatePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName = 'EntraZTAssess-Assessment',

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'China')]
        [string]$Environment = 'Global',

        [Parameter()]
        [switch]$UseDeviceCode,

        [Parameter()]
        [switch]$GrantAdminConsent,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigOutputPath = (Join-Path -Path $HOME -ChildPath '.ztassess/auth.json')
    )

    $ErrorActionPreference = 'Stop'

    # The well-known Microsoft Graph resource application ID. Application permission
    # (app role) GUIDs are resolved from this service principal at runtime.
    $graphAppId = '00000003-0000-0000-c000-000000000000'

    # Elevated scopes used ONLY for this one-time provisioning step, not by the
    # assessment itself. Requested least-privilege: AppRoleAssignment.ReadWrite.All
    # is only needed when -GrantAdminConsent will create app role assignments.
    $setupScopes = [System.Collections.Generic.List[string]]::new()
    $setupScopes.Add('Application.ReadWrite.All')
    if ($GrantAdminConsent) {
        $setupScopes.Add('AppRoleAssignment.ReadWrite.All')
    }

    # --- Preconditions --------------------------------------------------------

    # Fail fast with an actionable message if the Graph SDK is not installed.
    $requiredCommands = @(
        'Connect-MgGraph'
        'Get-MgApplication'
        'Get-MgServicePrincipal'
        'New-MgApplication'
        'New-MgServicePrincipal'
        'New-MgServicePrincipalAppRoleAssignment'
    )
    $missingCommands = @($requiredCommands | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
    if ($missingCommands.Count -gt 0) {
        throw ('The Microsoft Graph SDK is required but these commands were not found: {0}. Install it with: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser' -f ($missingCommands -join ', '))
    }

    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        throw ('Certificate file not found: {0}. Run New-ZTAssessCertificate first.' -f $CertificatePath)
    }

    # --- Compute the read-only scope union ------------------------------------

    # Bundled with this module at Settings/permissions.psd1 (a sibling of
    # Public/), sourced from source/Settings/permissions.psd1 in the main
    # repo - see Settings/permissions.psd1's header. Resolved relative to the
    # module's own root so it works from a PSGallery install, not just a git
    # checkout.
    $permissionsPath = Join-Path -Path $PSScriptRoot -ChildPath '../Settings/permissions.psd1'
    if (-not (Test-Path -LiteralPath $permissionsPath)) {
        throw ('Permission catalogue not found at {0}.' -f $permissionsPath)
    }

    $catalogue = Import-PowerShellDataFile -Path $permissionsPath
    $moduleCatalogue = $catalogue.Modules

    # Default to every non-optional module that is not already always-included.
    if (-not $Modules) {
        $Modules = @(
            $moduleCatalogue.GetEnumerator() |
                Where-Object { -not $_.Value.Optional -and -not $_.Value.AlwaysIncluded } |
                    Select-Object -ExpandProperty Key
        )
    }

    # Validate the requested module names against the catalogue.
    $unknownModules = @($Modules | Where-Object { -not $moduleCatalogue.ContainsKey($_) })
    if ($unknownModules.Count -gt 0) {
        throw ('Unknown module(s): {0}. Valid modules: {1}.' -f ($unknownModules -join ', '), (($moduleCatalogue.Keys | Sort-Object) -join ', '))
    }

    # Always include the AlwaysIncluded (Core) modules, then union the selected.
    $alwaysIncluded = @(
        $moduleCatalogue.GetEnumerator() |
            Where-Object { $_.Value.AlwaysIncluded } |
                Select-Object -ExpandProperty Key
    )

    $scopeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($moduleName in (@($alwaysIncluded) + @($Modules))) {
        foreach ($scope in $moduleCatalogue[$moduleName].Scopes) {
            $null = $scopeSet.Add($scope)
        }
    }
    $requiredScopes = @($scopeSet | Sort-Object)

    if ($requiredScopes.Count -eq 0) {
        throw 'No read-only Graph scopes were resolved for the selected modules.'
    }

    Write-Host ('Required read-only Graph application permissions ({0}):' -f $requiredScopes.Count) -ForegroundColor Cyan
    $requiredScopes | ForEach-Object { Write-Host ('  {0}' -f $_) }
    Write-Host ''

    # --- Connect with elevated setup scopes -----------------------------------

    Write-Host 'Connecting to Microsoft Graph with elevated one-time setup scopes...' -ForegroundColor Cyan
    Write-Host ('  Setup scopes (not assessment scopes): {0}' -f ($setupScopes -join ', '))

    # The sign-in itself can create or refresh a delegated consent grant in the
    # directory, so it is a write operation and is gated by ShouldProcess. Under
    # -WhatIf, report what would happen and stop before connecting, since every
    # subsequent step depends on an authenticated Graph context.
    if (-not $PSCmdlet.ShouldProcess($TenantId, 'Connect to Microsoft Graph with elevated setup scopes')) {
        return
    }

    # Splatted rather than called with fixed parameters so -UseDeviceCode can
    # be added only when requested, and -NoWelcome only when the installed
    # Connect-MgGraph actually declares it - older Microsoft.Graph.Authentication
    # releases predate that parameter and would otherwise fail to bind it.
    $connectParameters = @{
        TenantId    = $TenantId
        Scopes      = $setupScopes
        Environment = $Environment
        ErrorAction = 'Stop'
    }
    if ($UseDeviceCode) {
        $connectParameters['UseDeviceCode'] = $true
    }
    if ((Get-Command -Name 'Connect-MgGraph').Parameters.ContainsKey('NoWelcome')) {
        $connectParameters['NoWelcome'] = $true
    }

    try {
        Connect-MgGraph @connectParameters
    } catch {
        throw ('Failed to connect to Microsoft Graph: {0}' -f $_.Exception.Message)
    }

    # --- Resolve Graph app role GUIDs at runtime ------------------------------

    try {
        $graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    } catch {
        throw ('Failed to resolve the Microsoft Graph service principal: {0}' -f $_.Exception.Message)
    }

    if (-not $graphServicePrincipal) {
        throw 'The Microsoft Graph service principal could not be found in this tenant.'
    }

    # For each required scope string, find the Application app role by Value.
    $resolvedRoles = [System.Collections.Generic.List[object]]::new()
    $unmatchedScopes = [System.Collections.Generic.List[string]]::new()
    foreach ($scope in $requiredScopes) {
        $appRole = $graphServicePrincipal.AppRoles |
            Where-Object { $_.Value -eq $scope -and $_.AllowedMemberTypes -contains 'Application' } |
                Select-Object -First 1

        if ($appRole) {
            $resolvedRoles.Add([pscustomobject]@{ Scope = $scope; Id = $appRole.Id })
        } else {
            $unmatchedScopes.Add($scope)
        }
    }

    if ($unmatchedScopes.Count -gt 0) {
        Write-Warning ('No matching Application app role was found for the following scope(s); they will be skipped: {0}' -f ($unmatchedScopes -join ', '))
    }

    if ($resolvedRoles.Count -eq 0) {
        throw 'No application app roles could be resolved for the required scopes.'
    }

    # --- Read the certificate bytes -------------------------------------------

    # X509CertificateLoader (the non-obsolete replacement for the path-based
    # X509Certificate2 constructor, SYSLIB0057) is only available on newer .NET
    # runtimes. Prefer it when present; fall back to the constructor so this
    # still runs on the project's PowerShell 7.0 minimum.
    $certificateLoaderType = [type]::GetType('System.Security.Cryptography.X509Certificates.X509CertificateLoader')
    $certificate = if ($certificateLoaderType) {
        $certificateLoaderType::LoadCertificateFromFile($CertificatePath)
    } else {
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
    }
    $certThumbprint = $certificate.Thumbprint
    $certRawBytes = $certificate.GetRawCertData()
    # Thumbprint and raw bytes are captured; the handle is not used again.
    $certificate.Dispose()

    # --- Build the application resource access + key credential ----------------

    $resourceAccess = @($resolvedRoles | ForEach-Object {
            @{ Id = $_.Id; Type = 'Role' }
        })

    $requiredResourceAccess = @(
        @{
            ResourceAppId  = $graphAppId
            ResourceAccess = $resourceAccess
        }
    )

    $keyCredential = @{
        Type  = 'AsymmetricX509Cert'
        Usage = 'Verify'
        Key   = $certRawBytes
    }

    # --- Idempotency guard: refuse to silently duplicate an existing app -------

    try {
        $escapedDisplayName = $DisplayName.Replace("'", "''")
        $existingApplication = Get-MgApplication -Filter "displayName eq '$escapedDisplayName'" -ErrorAction Stop | Select-Object -First 1
    } catch {
        throw ("Failed to check for an existing application registration named '{0}': {1}" -f $DisplayName, $_.Exception.Message)
    }

    if ($existingApplication -and -not $Force) {
        throw ("An application registration named '{0}' already exists (appId {1}). Re-running this function would create a duplicate and orphan the existing application's consent grants. Supply -Force to create a new application anyway, or reuse the existing appId." -f $DisplayName, $existingApplication.AppId)
    }

    if ($existingApplication -and $Force) {
        Write-Warning ("An application registration named '{0}' already exists (appId {1}); -Force was supplied, so a new, separate application will be created." -f $DisplayName, $existingApplication.AppId)
    }

    # --- Create the application ------------------------------------------------

    $application = $null
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create Entra ID application registration')) {
        try {
            $application = New-MgApplication -DisplayName $DisplayName `
                -SignInAudience 'AzureADMyOrg' `
                -RequiredResourceAccess $requiredResourceAccess `
                -KeyCredentials @($keyCredential) `
                -ErrorAction Stop
        } catch {
            throw ('Failed to create the application registration: {0}' -f $_.Exception.Message)
        }

        Write-Host ("Created application '{0}' (appId {1})." -f $application.DisplayName, $application.AppId) -ForegroundColor Green
    }

    # --- Create the service principal -----------------------------------------

    $servicePrincipal = $null
    if ($application -and $PSCmdlet.ShouldProcess($application.AppId, 'Create service principal')) {
        try {
            $servicePrincipal = New-MgServicePrincipal -AppId $application.AppId -ErrorAction Stop
        } catch {
            throw ('Failed to create the service principal: {0}' -f $_.Exception.Message)
        }

        Write-Host ('Created service principal (objectId {0}).' -f $servicePrincipal.Id) -ForegroundColor Green
    }

    # --- Admin consent ---------------------------------------------------------

    # National-cloud aware admin-consent host.
    $consentHost = switch ($Environment) {
        'USGov' { 'login.microsoftonline.us' }
        'China' { 'login.partner.microsoftonline.cn' }
        default { 'login.microsoftonline.com' }
    }
    $consentUrl = if ($application) {
        ('https://{0}/{1}/adminconsent?client_id={2}' -f $consentHost, $TenantId, $application.AppId)
    } else {
        ('https://{0}/{1}/adminconsent?client_id=<appId>' -f $consentHost, $TenantId)
    }

    $failedGrants = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($GrantAdminConsent) {
        if ($servicePrincipal -and $PSCmdlet.ShouldProcess($DisplayName, 'Grant admin consent (create app role assignments)')) {
            foreach ($role in $resolvedRoles) {
                try {
                    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id `
                        -PrincipalId $servicePrincipal.Id `
                        -ResourceId $graphServicePrincipal.Id `
                        -AppRoleId $role.Id `
                        -ErrorAction Stop
                    Write-Host ('  Granted: {0}' -f $role.Scope) -ForegroundColor Green
                } catch {
                    Write-Warning ("Failed to grant '{0}': {1}" -f $role.Scope, $_.Exception.Message)
                    $failedGrants.Add([pscustomobject]@{ Scope = $role.Scope; Error = $_.Exception.Message })
                }
            }
        }
    } else {
        Write-Host ''
        Write-Host 'Admin consent is required before the assessment can run.' -ForegroundColor Yellow
        Write-Host 'Ask a Privileged Role Administrator (or Global Administrator) to approve this URL:' -ForegroundColor Yellow
        Write-Host ('  {0}' -f $consentUrl)
    }

    # --- Write the non-secret configuration ------------------------------------

    # Prefer the sibling .pfx (cross-platform private key) if present, else the .cer.
    $pfxSibling = [System.IO.Path]::ChangeExtension($CertificatePath, '.pfx')
    $configCertPath = if (Test-Path -LiteralPath $pfxSibling) { $pfxSibling } else { $CertificatePath }

    $config = [ordered]@{
        TenantId              = $TenantId
        ClientId              = if ($application) { $application.AppId } else { $null }
        CertificateThumbprint = $certThumbprint
        CertificatePath       = $configCertPath
        Environment           = $Environment
    }

    $configDir = Split-Path -Path $ConfigOutputPath -Parent
    if ($configDir -and -not (Test-Path -LiteralPath $configDir)) {
        if ($PSCmdlet.ShouldProcess($configDir, 'Create configuration directory')) {
            $null = New-Item -Path $configDir -ItemType Directory -Force
        }
    }

    if ($PSCmdlet.ShouldProcess($ConfigOutputPath, 'Write non-secret connection configuration')) {
        $json = $config | ConvertTo-Json -Depth 4
        Set-Content -Path $ConfigOutputPath -Value $json -Encoding utf8
        Write-Host ('Wrote connection configuration to {0}' -f $ConfigOutputPath) -ForegroundColor Green
    }

    # --- Final summary ---------------------------------------------------------

    $summary = [pscustomobject]@{
        PSTypeName            = 'ZTAssess.AppRegistration'
        ClientId              = $config.ClientId
        TenantId              = $TenantId
        CertificateThumbprint = $certThumbprint
        ConfigPath            = $ConfigOutputPath
        ConsentUrl            = $consentUrl
        FailedGrants          = @($failedGrants)
    }

    Write-Host ''
    Write-Host 'Provisioning summary:' -ForegroundColor Cyan
    Write-Host ('  ClientId   : {0}' -f $summary.ClientId)
    Write-Host ('  TenantId   : {0}' -f $summary.TenantId)
    Write-Host ('  Thumbprint : {0}' -f $summary.CertificateThumbprint)
    Write-Host ('  Config     : {0}' -f $summary.ConfigPath)
    Write-Host ('  Consent URL: {0}' -f $summary.ConsentUrl)
    if ($summary.FailedGrants.Count -gt 0) {
        Write-Host ('  Failed grants: {0}' -f (($summary.FailedGrants | ForEach-Object { $_.Scope }) -join ', ')) -ForegroundColor Yellow
    }
    Write-Host ''

    return $summary
}
