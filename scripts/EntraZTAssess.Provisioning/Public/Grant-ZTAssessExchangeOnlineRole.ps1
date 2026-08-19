#Requires -Version 7.0

function Grant-ZTAssessExchangeOnlineRole {
    <#
    .SYNOPSIS
    Grants the Exchange Online / Security & Compliance (IPPS) roles required
    by the selected assessment modules to the app registration's service
    principal.

    .DESCRIPTION
    Connects to Exchange Online / Security & Compliance as the calling
    Exchange administrator (interactive delegated sign-in — never as the
    assessment app itself), ensures the EntraZTAssess app registration has a
    corresponding Exchange Online service principal (creating one with
    New-ServicePrincipal if it does not already exist), and grants the app
    each Exchange Online / Security & Compliance entry required by the
    selected modules (resolved from the same catalogue used by
    Get-ZTAssessExchangeOnlineRoleGuidance).

    Connecting as the calling administrator rather than as the app is
    deliberate: the app being granted roles may not yet be authorized to
    connect to Exchange Online / IPPS at all (this is exactly the gap this
    function exists to close), so authenticating as the app here would be
    circular. Run this as yourself, signed in with an account that already
    holds sufficient Exchange Online / Security & Compliance administrative
    rights (for example Exchange Administrator or a member of Organization
    Management).

    Each catalogue entry is granted with whichever mechanism actually
    matches what it is in the connected tenant — these two are NOT
    interchangeable, and getting this wrong is a documented risk of this
    function, not a hypothetical one. Verified against a live tenant across
    the full permission catalogue:

    - A **role group** (only 'Security Reader', of the entries this
      catalogue currently uses) is granted with Add-RoleGroupMember, adding
      the app's Exchange Online service principal as a member.
    - A **management role** — 'View-Only Configuration' and 'View-Only
      Recipients' (visible in the Exchange Online session), and 'View-Only
      Retention Management' and 'View-Only DLP Compliance Management'
      (visible only in the Security & Compliance / IPPS session) — is
      granted directly to the app with New-ManagementRoleAssignment -App,
      which does not require the app to be a member of any role group.
      Despite reading like role-group names, none of these four are role
      groups in Exchange Online RBAC.

    For each entry this function first attempts the role-group path; if
    that fails because the name is not a role group, it falls back to the
    management-role path against the same Exchange Online connection. If
    both fail, it additionally attempts a lazily-established
    Connect-IPPSSession and retries the management-role mechanism against
    that connection before giving up on the entry — this is the path that
    resolves the two Purview retention/DLP roles above, which exist only in
    the Security & Compliance / IPPS RBAC namespace, not Exchange Online
    proper.

    Re-running this function is safe: it skips creating the service
    principal if one already exists for the AppId, and treats an
    "already granted" response from either mechanism as success rather
    than a failure.

    .PARAMETER AppId
    The application (client) ID of the EntraZTAssess app registration.

    .PARAMETER ServicePrincipalObjectId
    The Entra ID object ID of the app's service principal, required only
    when no Exchange Online service principal exists yet for -AppId. Obtain
    it from New-ZTAssessAppRegistration's output, the Entra admin center, or
    Get-MgServicePrincipal. Not needed when an EXO service principal for
    -AppId already exists, and not needed at all for entries granted via
    the management-role path, which targets -AppId directly.

    .PARAMETER Modules
    Assessment modules to resolve required Exchange Online / IPPS entries
    for. Defaults to every module that requires Exchange Online / IPPS
    (SecurityCompliance, Collaboration, DataProtection, ThreatProtection).

    .PARAMETER Organization
    The verified domain of the tenant, for example contoso.onmicrosoft.com.

    .PARAMETER UserPrincipalName
    The calling Exchange administrator's sign-in name, passed to
    Connect-ExchangeOnline to skip the account-picker prompt. Optional; when
    omitted, Connect-ExchangeOnline prompts interactively for the signing-in
    account.

    .PARAMETER DisplayName
    Display name to use if a new Exchange Online service principal must be
    created. Defaults to 'EntraZTAssess-Assessment'.

    .EXAMPLE
    Grant-ZTAssessExchangeOnlineRole -AppId '11111111-1111-1111-1111-111111111111' `
        -ServicePrincipalObjectId '22222222-2222-2222-2222-222222222222' `
        -Organization 'contoso.onmicrosoft.com' -UserPrincipalName 'admin@contoso.onmicrosoft.com' `
        -Modules ThreatProtection

    Signs in interactively as the Exchange administrator, creates the
    Exchange Online service principal for the app if it does not already
    exist, and grants ThreatProtection's required entries using whichever
    mechanism (role group or management role) matches each one.

    .OUTPUTS
    PSCustomObject
    A summary with AppId, Organization, ServicePrincipalCreated,
    RoleGroupsGranted, RoleGroupsAlreadyMember, and FailedGrants (an empty
    array unless one or more grants failed against both Exchange Online and
    IPPS).

    .NOTES
    Requires the ExchangeOnlineManagement module. Must be run by an account
    that already holds sufficient Exchange Online / Security & Compliance
    administrative rights to grant role groups and management roles — this
    function does not elevate or grant that right to the caller.

    Exact role and role-group names vary by tenant license and national
    cloud; confirm the entries in source/Settings/permissions.psd1 against
    Get-RoleGroup / Get-ManagementRole in the target tenant if a grant
    fails. A failure for a specific entry is recorded in FailedGrants with
    the underlying Exchange Online error rather than aborting the run, so
    one unresolvable entry never prevents the rest from being granted.

    Supports -WhatIf/-Confirm. The Exchange Online sign-in itself is gated
    by ShouldProcess because obtaining a session is a prerequisite for every
    write this function performs; under -WhatIf the function reports what
    would happen and returns without connecting.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive admin-run provisioning function; coloured console guidance is intentional and not pipeline output.')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$',
            ErrorMessage = 'AppId must be a GUID.'
        )]
        [string]$AppId,

        [Parameter()]
        [ValidatePattern(
            '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$',
            ErrorMessage = 'ServicePrincipalObjectId must be a GUID.'
        )]
        [string]$ServicePrincipalObjectId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Organization,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName = 'EntraZTAssess-Assessment'
    )

    $ErrorActionPreference = 'Stop'

    # --- Preconditions ----------------------------------------------------

    # Connect-ExchangeOnline / Connect-IPPSSession / Disconnect-ExchangeOnline
    # are static, always-exported commands from the ExchangeOnlineManagement
    # module, so they can be checked before connecting. The RBAC commands
    # (Get-ServicePrincipal, New-ServicePrincipal, Get-RoleGroupMember,
    # Add-RoleGroupMember, New-ManagementRoleAssignment) are dynamic proxy
    # commands that the module only injects into the session AFTER a
    # successful connection -- checking for them here would always report
    # them missing even when ExchangeOnlineManagement is correctly
    # installed, so that check happens after Connect-ExchangeOnline below.
    $requiredPreConnectCommands = @(
        'Connect-ExchangeOnline'
        'Connect-IPPSSession'
        'Disconnect-ExchangeOnline'
    )
    $missingPreConnectCommands = @($requiredPreConnectCommands | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
    if ($missingPreConnectCommands.Count -gt 0) {
        throw ("The ExchangeOnlineManagement module is required but these commands were not found: {0}. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser" -f ($missingPreConnectCommands -join ', '))
    }

    # --- Resolve required entries from the same catalogue used by ----------
    # --- Get-ZTAssessExchangeOnlineRoleGuidance -----------------------------

    $guidance = @(Get-ZTAssessExchangeOnlineRoleGuidance -Modules $Modules)
    if ($guidance.Count -eq 0) {
        throw 'None of the selected modules require Exchange Online / Security & Compliance role groups.'
    }

    $requiredEntries = @($guidance.ExchangeOnlineRoles | Sort-Object -Unique)

    Write-Host ("Required Exchange Online / Security & Compliance entries ({0}):" -f $requiredEntries.Count) -ForegroundColor Cyan
    $requiredEntries | ForEach-Object { Write-Host ("  {0}" -f $_) }
    Write-Host ''

    # --- Connect to Exchange Online as the calling administrator -----------

    # Connecting as the app being granted roles would be circular: it may
    # not yet be authorized to connect at all, which is the gap this
    # function closes. Obtaining a session is a prerequisite for every
    # subsequent write, so the sign-in itself is gated by ShouldProcess.
    # Under -WhatIf, report what would happen and stop before connecting.
    if (-not $PSCmdlet.ShouldProcess($Organization, 'Connect to Exchange Online as the calling administrator')) {
        return
    }

    $connectParams = @{
        Organization = $Organization
        ShowBanner   = $false
        ErrorAction  = 'Stop'
    }
    if ($UserPrincipalName) {
        $connectParams.UserPrincipalName = $UserPrincipalName
    }

    try {
        Connect-ExchangeOnline @connectParams
    }
    catch {
        throw ("Failed to connect to Exchange Online: {0}" -f $_.Exception.Message)
    }

    # Lazily established only if an entry cannot be resolved against the
    # Exchange Online connection above (some Purview retention/DLP roles
    # exist only in the Security & Compliance / IPPS RBAC namespace).
    $ippsConnected = $false

    try {
        # --- Verify the RBAC proxy commands are now available -------------

        $requiredPostConnectCommands = @(
            'Get-ServicePrincipal'
            'New-ServicePrincipal'
            'Get-RoleGroupMember'
            'Add-RoleGroupMember'
            'New-ManagementRoleAssignment'
        )
        $missingPostConnectCommands = @($requiredPostConnectCommands | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
        if ($missingPostConnectCommands.Count -gt 0) {
            throw ("Connected to Exchange Online, but these commands were not available in the session: {0}. This usually means the signed-in account lacks sufficient Exchange Online / Security & Compliance administrative rights, or the ExchangeOnlineManagement module version is outdated." -f ($missingPostConnectCommands -join ', '))
        }

        # --- Ensure an Exchange Online service principal exists for AppId ---

        $servicePrincipal = Get-ServicePrincipal -Identity $AppId -ErrorAction SilentlyContinue
        $servicePrincipalCreated = $false

        if (-not $servicePrincipal) {
            if (-not $ServicePrincipalObjectId) {
                throw ("No Exchange Online service principal exists yet for AppId '{0}', and -ServicePrincipalObjectId was not supplied. Provide the app's Entra ID service principal object ID (from New-ZTAssessAppRegistration's output, the Entra admin center, or Get-MgServicePrincipal) so New-ServicePrincipal can create it." -f $AppId)
            }

            if ($PSCmdlet.ShouldProcess($AppId, 'Create Exchange Online service principal')) {
                try {
                    $servicePrincipal = New-ServicePrincipal -AppId $AppId -ObjectId $ServicePrincipalObjectId -DisplayName $DisplayName -ErrorAction Stop
                    $servicePrincipalCreated = $true
                    Write-Host ("Created Exchange Online service principal for AppId '{0}'." -f $AppId) -ForegroundColor Green
                }
                catch {
                    throw ("Failed to create the Exchange Online service principal: {0}" -f $_.Exception.Message)
                }
            }
        }

        # Role-group membership is keyed on the Exchange Online-side service
        # principal identity, not the Entra AppId — resolve whichever
        # identity-bearing property the SDK populated.
        $spIdentity = @($servicePrincipal.Identity, $servicePrincipal.Guid, $servicePrincipal.ObjectId, $servicePrincipal.DisplayName) |
            Where-Object { $_ } | Select-Object -First 1
        if (-not $spIdentity) {
            $spIdentity = $DisplayName
        }

        # --- Grant each required entry, trying role-group then ------------
        # --- management-role mechanisms, then IPPS as a last resort -------

        $granted = [System.Collections.Generic.List[string]]::new()
        $alreadyMember = [System.Collections.Generic.List[string]]::new()
        $failedGrants = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($entryName in $requiredEntries) {
            $outcome = $null
            $lastError = $null

            # 1. Try as a role group (Add-RoleGroupMember).
            try {
                $existingMembers = @(Get-RoleGroupMember -Identity $entryName -ErrorAction Stop)
                $isAlreadyMember = $existingMembers | Where-Object {
                    $_.Identity -eq $spIdentity -or $_.Guid -eq $spIdentity -or $_.DisplayName -eq $DisplayName -or $_.Name -eq $DisplayName
                }

                if ($isAlreadyMember) {
                    $outcome = 'AlreadyGranted'
                }
                elseif ($PSCmdlet.ShouldProcess($entryName, ('Add {0} as a role group member' -f $DisplayName))) {
                    Add-RoleGroupMember -Identity $entryName -Member $spIdentity -Confirm:$false -ErrorAction Stop
                    $outcome = 'Granted'
                }
                else {
                    $outcome = 'SkippedWhatIf'
                }
            }
            catch {
                # Not resolvable as a role group in this connection; fall
                # through and try the management-role mechanism instead.
                $lastError = $_.Exception.Message
            }

            # 2. Fall back to a direct management-role assignment.
            if (-not $outcome) {
                try {
                    if ($PSCmdlet.ShouldProcess($entryName, ('Assign management role to AppId {0}' -f $AppId))) {
                        New-ManagementRoleAssignment -Role $entryName -App $AppId -ErrorAction Stop
                        $outcome = 'Granted'
                    }
                    else {
                        $outcome = 'SkippedWhatIf'
                    }
                }
                catch {
                    if ($_.Exception.Message -match 'already') {
                        $outcome = 'AlreadyGranted'
                    }
                    else {
                        $lastError = $_.Exception.Message
                    }
                }
            }

            # 3. Last resort: some Purview retention/DLP entries only exist
            #    in the Security & Compliance (IPPS) RBAC namespace.
            if (-not $outcome) {
                if (-not $ippsConnected) {
                    if ($PSCmdlet.ShouldProcess($Organization, 'Connect to Security & Compliance (IPPS) as the calling administrator')) {
                        try {
                            Connect-IPPSSession @connectParams
                            $ippsConnected = $true
                        }
                        catch {
                            $lastError = ("{0} (also failed to connect to IPPS: {1})" -f $lastError, $_.Exception.Message)
                        }
                    }
                }

                if ($ippsConnected) {
                    try {
                        New-ManagementRoleAssignment -Role $entryName -App $AppId -ErrorAction Stop
                        $outcome = 'Granted'
                    }
                    catch {
                        if ($_.Exception.Message -match 'already') {
                            $outcome = 'AlreadyGranted'
                        }
                        else {
                            $lastError = $_.Exception.Message
                        }
                    }
                }
            }

            switch ($outcome) {
                'AlreadyGranted' { $alreadyMember.Add($entryName) }
                'Granted' {
                    $granted.Add($entryName)
                    Write-Host ("  Granted: {0}" -f $entryName) -ForegroundColor Green
                }
                'SkippedWhatIf' { }
                default {
                    Write-Warning ("Failed to grant '{0}' to '{1}': {2}" -f $entryName, $DisplayName, $lastError)
                    $failedGrants.Add([pscustomobject]@{ RoleGroup = $entryName; Error = $lastError })
                }
            }
        }

        $summary = [pscustomobject]@{
            PSTypeName              = 'ZTAssess.ExchangeOnlineRoleGrant'
            AppId                   = $AppId
            Organization            = $Organization
            ServicePrincipalCreated = $servicePrincipalCreated
            RoleGroupsGranted       = @($granted)
            RoleGroupsAlreadyMember = @($alreadyMember)
            FailedGrants            = @($failedGrants)
        }

        Write-Host ''
        Write-Host 'Role grant summary:' -ForegroundColor Cyan
        Write-Host ("  AppId               : {0}" -f $summary.AppId)
        Write-Host ("  Organization        : {0}" -f $summary.Organization)
        Write-Host ("  SP created          : {0}" -f $summary.ServicePrincipalCreated)
        Write-Host ("  Granted             : {0}" -f (($summary.RoleGroupsGranted) -join ', '))
        Write-Host ("  Already member of   : {0}" -f (($summary.RoleGroupsAlreadyMember) -join ', '))
        if ($summary.FailedGrants.Count -gt 0) {
            Write-Host ("  Failed              : {0}" -f (($summary.FailedGrants | ForEach-Object { $_.RoleGroup }) -join ', ')) -ForegroundColor Yellow
        }
        Write-Host ''

        return $summary
    }
    finally {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
}
