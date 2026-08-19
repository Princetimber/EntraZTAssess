#Requires -Version 7.0

# Resolves the verified domain Exchange Online/IPPS requires for -Organization.
# Unlike Graph's TenantId (which accepts a GUID or a domain), EXO/IPPS require
# a verified domain string. Resolution order: explicit parameter ->
# ZTASSESS_ORGANIZATION env var -> the CBA auth config's Organization value ->
# a domain-looking TenantId used as-is -> derived from the already-connected
# Graph tenant's initial verified domain. Returns $null if none can be
# resolved; the caller treats that as a connection failure for the Exchange
# Online / IPPS surface only, never for Graph.
function Resolve-ZTAssessOrganization {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]$Organization,

        [Parameter()]
        [pscustomobject]$AuthConfig,

        [Parameter()]
        [string]$TenantId
    )

    if ($Organization) { return $Organization }
    if ($env:ZTASSESS_ORGANIZATION) { return $env:ZTASSESS_ORGANIZATION }
    if ($AuthConfig -and $AuthConfig.Organization) { return $AuthConfig.Organization }

    # A domain-looking TenantId (contains a dot and is not a GUID) can be used as-is.
    $isGuid = $TenantId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    if ($TenantId -and -not $isGuid -and $TenantId -match '\.') {
        return $TenantId
    }

    # Derive from the connected Graph tenant's initial verified domain.
    try {
        $organizationInfo = Invoke-ZTAssessGraphRequest -Uri '/v1.0/organization?$select=verifiedDomains' -ErrorAction Stop
        $initialDomain = @($organizationInfo.value[0].verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1
        if ($initialDomain) { return $initialDomain.name }
    } catch {
        Write-ToLog -Message "Could not derive an Exchange Online organization domain from Microsoft Graph: $($_.Exception.Message)" -Level WARN -NoConsole
    }

    return $null
}
