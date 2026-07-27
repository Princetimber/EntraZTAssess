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

    The interactive sign-in for THIS function requests elevated setup scopes
    (Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.Read.All)
    so it can create the application and, optionally, grant consent. Those elevated
    scopes are used only for this provisioning step; they are NOT the scopes the
    assessment itself uses. The assessment runs exclusively with the read-only
    application permissions granted to the new app.

    By default the function does NOT grant admin consent programmatically. It emits
    an admin-consent URL that a Global Administrator must approve. Supply
    -GrantAdminConsent to create the app role assignments directly (also requires
    a Global Administrator or Privileged Role Administrator session).

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

    .PARAMETER GrantAdminConsent
    Grants the read-only application permissions programmatically by creating app
    role assignments on the new service principal. Requires a Global Administrator
    or Privileged Role Administrator session. When omitted, an admin-consent URL is
    emitted for a Global Administrator to approve instead.

    .PARAMETER ConfigOutputPath
    Path of the non-secret JSON configuration file to write for
    Connect-ZTAssessment. Defaults to ~/.ztassess/auth.json. No password or secret
    is ever written to this file.

    .EXAMPLE
    New-ZTAssessAppRegistration -TenantId 'contoso.onmicrosoft.com' -CertificatePath ~/.ztassess/EntraZTAssess.cer

    Creates the application with the default read-only scopes, uploads the
    certificate, writes ~/.ztassess/auth.json, and prints an admin-consent URL for
    a Global Administrator to approve.

    .EXAMPLE
    New-ZTAssessAppRegistration -TenantId '00000000-0000-0000-0000-000000000000' -CertificatePath ./EntraZTAssess.cer -Modules Identity, ConditionalAccess, Devices -GrantAdminConsent

    Creates the application scoped to three assessment modules and grants admin
    consent programmatically.

    .OUTPUTS
    PSCustomObject
    A summary with ClientId, TenantId, CertificateThumbprint, ConfigPath, and
    ConsentUrl.

    .NOTES
    Requires the Microsoft.Graph SDK modules (Microsoft.Graph.Authentication,
    Microsoft.Graph.Applications). All permissions granted to the created
    application are read-only Graph application permissions and require admin
    consent before the assessment can run.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive admin-run provisioning function; coloured console guidance is intentional and not pipeline output.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
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
        [switch]$GrantAdminConsent,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigOutputPath = (Join-Path -Path $HOME -ChildPath '.ztassess/auth.json')
    )

    $ErrorActionPreference = 'Stop'

    # The well-known Microsoft Graph resource application ID. Application permission
    # (app role) GUIDs are resolved from this service principal at runtime.
    $graphAppId = '00000003-0000-0000-c000-000000000000'

    # Elevated scopes used ONLY for this one-time provisioning step, not by the
    # assessment itself.
    $setupScopes = @(
        'Application.ReadWrite.All'
        'AppRoleAssignment.ReadWrite.All'
        'Directory.Read.All'
    )

    # --- Preconditions --------------------------------------------------------

    # Fail fast with an actionable message if the Graph SDK is not installed.
    $requiredCommands = @(
        'Connect-MgGraph'
        'Get-MgServicePrincipal'
        'New-MgApplication'
        'New-MgServicePrincipal'
        'New-MgServicePrincipalAppRoleAssignment'
    )
    $missingCommands = @($requiredCommands | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
    if ($missingCommands.Count -gt 0) {
        throw ("The Microsoft Graph SDK is required but these commands were not found: {0}. Install it with: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser" -f ($missingCommands -join ', '))
    }

    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        throw ("Certificate file not found: {0}. Run New-ZTAssessCertificate first." -f $CertificatePath)
    }

    # --- Compute the read-only scope union ------------------------------------

    $permissionsPath = Join-Path -Path $PSScriptRoot -ChildPath '../../../source/Settings/permissions.psd1'
    if (-not (Test-Path -LiteralPath $permissionsPath)) {
        throw ("Permission catalogue not found at {0}." -f $permissionsPath)
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
        throw ("Unknown module(s): {0}. Valid modules: {1}." -f ($unknownModules -join ', '), (($moduleCatalogue.Keys | Sort-Object) -join ', '))
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

    Write-Host ("Required read-only Graph application permissions ({0}):" -f $requiredScopes.Count) -ForegroundColor Cyan
    $requiredScopes | ForEach-Object { Write-Host ("  {0}" -f $_) }
    Write-Host ''

    # --- Connect with elevated setup scopes -----------------------------------

    Write-Host 'Connecting to Microsoft Graph with elevated one-time setup scopes...' -ForegroundColor Cyan
    Write-Host ("  Setup scopes (not assessment scopes): {0}" -f ($setupScopes -join ', '))

    try {
        Connect-MgGraph -TenantId $TenantId -Scopes $setupScopes -Environment $Environment -NoWelcome -ErrorAction Stop
    }
    catch {
        throw ("Failed to connect to Microsoft Graph: {0}" -f $_.Exception.Message)
    }

    # --- Resolve Graph app role GUIDs at runtime ------------------------------

    try {
        $graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    }
    catch {
        throw ("Failed to resolve the Microsoft Graph service principal: {0}" -f $_.Exception.Message)
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
        }
        else {
            $unmatchedScopes.Add($scope)
        }
    }

    if ($unmatchedScopes.Count -gt 0) {
        Write-Warning ("No matching Application app role was found for the following scope(s); they will be skipped: {0}" -f ($unmatchedScopes -join ', '))
    }

    if ($resolvedRoles.Count -eq 0) {
        throw 'No application app roles could be resolved for the required scopes.'
    }

    # --- Read the certificate bytes -------------------------------------------

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
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

    # --- Create the application ------------------------------------------------

    $application = $null
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create Entra ID application registration')) {
        try {
            $application = New-MgApplication -DisplayName $DisplayName `
                -SignInAudience 'AzureADMyOrg' `
                -RequiredResourceAccess $requiredResourceAccess `
                -KeyCredentials @($keyCredential) `
                -ErrorAction Stop
        }
        catch {
            throw ("Failed to create the application registration: {0}" -f $_.Exception.Message)
        }

        Write-Host ("Created application '{0}' (appId {1})." -f $application.DisplayName, $application.AppId) -ForegroundColor Green
    }

    # --- Create the service principal -----------------------------------------

    $servicePrincipal = $null
    if ($application -and $PSCmdlet.ShouldProcess($application.AppId, 'Create service principal')) {
        try {
            $servicePrincipal = New-MgServicePrincipal -AppId $application.AppId -ErrorAction Stop
        }
        catch {
            throw ("Failed to create the service principal: {0}" -f $_.Exception.Message)
        }

        Write-Host ("Created service principal (objectId {0})." -f $servicePrincipal.Id) -ForegroundColor Green
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
    }
    else {
        ('https://{0}/{1}/adminconsent?client_id=<appId>' -f $consentHost, $TenantId)
    }

    if ($GrantAdminConsent) {
        if ($servicePrincipal -and $PSCmdlet.ShouldProcess($DisplayName, 'Grant admin consent (create app role assignments)')) {
            foreach ($role in $resolvedRoles) {
                try {
                    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id `
                        -PrincipalId $servicePrincipal.Id `
                        -ResourceId $graphServicePrincipal.Id `
                        -AppRoleId $role.Id `
                        -ErrorAction Stop
                    Write-Host ("  Granted: {0}" -f $role.Scope) -ForegroundColor Green
                }
                catch {
                    Write-Warning ("Failed to grant '{0}': {1}" -f $role.Scope, $_.Exception.Message)
                }
            }
        }
    }
    else {
        Write-Host ''
        Write-Host 'Admin consent is required before the assessment can run.' -ForegroundColor Yellow
        Write-Host 'Ask a Global Administrator to approve this URL:' -ForegroundColor Yellow
        Write-Host ("  {0}" -f $consentUrl)
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
        Write-Host ("Wrote connection configuration to {0}" -f $ConfigOutputPath) -ForegroundColor Green
    }

    # --- Final summary ---------------------------------------------------------

    $summary = [pscustomobject]@{
        PSTypeName            = 'ZTAssess.AppRegistration'
        ClientId              = $config.ClientId
        TenantId              = $TenantId
        CertificateThumbprint = $certThumbprint
        ConfigPath            = $ConfigOutputPath
        ConsentUrl            = $consentUrl
    }

    Write-Host ''
    Write-Host 'Provisioning summary:' -ForegroundColor Cyan
    Write-Host ("  ClientId   : {0}" -f $summary.ClientId)
    Write-Host ("  TenantId   : {0}" -f $summary.TenantId)
    Write-Host ("  Thumbprint : {0}" -f $summary.CertificateThumbprint)
    Write-Host ("  Config     : {0}" -f $summary.ConfigPath)
    Write-Host ("  Consent URL: {0}" -f $summary.ConsentUrl)
    Write-Host ''

    return $summary
}
