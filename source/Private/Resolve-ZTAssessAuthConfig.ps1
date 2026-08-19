#Requires -Version 7.0

# Resolves app-only (certificate-based) authentication configuration from
# environment variables first, then a non-secret JSON config file. Environment
# variables always override file values. Returns a pscustomobject when a
# complete configuration is found (ClientId AND TenantId AND a certificate
# reference), otherwise $null. Never throws on a missing or malformed file -
# it warns and continues so the caller can fall back to interactive sign-in.
function Resolve-ZTAssessAuthConfig {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    # Default config location under the cross-platform home directory.
    $configFilePath = if ($ConfigPath) {
        $ConfigPath
    } else {
        Join-Path -Path $HOME -ChildPath '.ztassess/auth.json'
    }

    # File values are read defensively; a missing or invalid file yields none.
    $fileTenantId = $null
    $fileClientId = $null
    $fileThumbprint = $null
    $fileCertPath = $null
    $fileEnvironment = $null
    $fileOrganization = $null
    $fileContributed = $false

    if (Test-Path -LiteralPath $configFilePath -PathType Leaf) {
        try {
            $rawContent = Get-Content -LiteralPath $configFilePath -Raw -ErrorAction Stop
            $parsed = $rawContent | ConvertFrom-Json -ErrorAction Stop

            $fileTenantId = $parsed.TenantId
            $fileClientId = $parsed.ClientId
            $fileThumbprint = $parsed.CertificateThumbprint
            $fileCertPath = $parsed.CertificatePath
            $fileEnvironment = $parsed.Environment
            $fileOrganization = $parsed.Organization
            $fileContributed = $true
        } catch {
            Write-ToLog -Message "Ignoring malformed auth config file '$configFilePath': $($_.Exception.Message)" -Level WARN -NoConsole
        }
    }

    # Environment variables take precedence over file values.
    $envValues = @(
        $env:ZTASSESS_TENANTID
        $env:ZTASSESS_CLIENTID
        $env:ZTASSESS_CERT_THUMBPRINT
        $env:ZTASSESS_CERT_PATH
        $env:ZTASSESS_ENVIRONMENT
        $env:ZTASSESS_ORGANIZATION
    )
    $envContributed = [bool]($envValues | Where-Object { $_ })

    $tenantId = if ($env:ZTASSESS_TENANTID) { $env:ZTASSESS_TENANTID } else { $fileTenantId }
    $clientId = if ($env:ZTASSESS_CLIENTID) { $env:ZTASSESS_CLIENTID } else { $fileClientId }
    $thumbprint = if ($env:ZTASSESS_CERT_THUMBPRINT) { $env:ZTASSESS_CERT_THUMBPRINT } else { $fileThumbprint }
    $certificatePath = if ($env:ZTASSESS_CERT_PATH) { $env:ZTASSESS_CERT_PATH } else { $fileCertPath }
    $environment = if ($env:ZTASSESS_ENVIRONMENT) { $env:ZTASSESS_ENVIRONMENT } else { $fileEnvironment }
    # Organization (Exchange Online / IPPS verified domain) is optional: a
    # missing value does not block CBA resolution, it is resolved later by
    # Resolve-ZTAssessOrganization with additional fallbacks (including
    # deriving it from the connected Graph tenant).
    $organization = if ($env:ZTASSESS_ORGANIZATION) { $env:ZTASSESS_ORGANIZATION } else { $fileOrganization }

    # A configuration only counts as resolved with an app id, a tenant, and a
    # certificate reference (store thumbprint or on-disk PFX path).
    $hasCertificate = [bool]$thumbprint -or [bool]$certificatePath
    if (-not ($clientId -and $tenantId -and $hasCertificate)) {
        return $null
    }

    # Describe where the resolved values came from for diagnostics.
    $sources = @()
    if ($envContributed) { $sources += 'Environment' }
    if ($fileContributed) { $sources += 'File' }
    $source = if ($sources.Count -gt 0) { $sources -join '+' } else { 'Unknown' }

    return [pscustomobject]@{
        TenantId              = $tenantId
        ClientId              = $clientId
        CertificateThumbprint = $thumbprint
        CertificatePath       = $certificatePath
        Environment           = $environment
        Organization          = $organization
        Source                = $source
    }
}
