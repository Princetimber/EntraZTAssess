#Requires -Version 7.0

# Loads a PFX (PKCS#12) file from disk into an X509Certificate2 object.
# Cross-platform: uses the byte[] constructor so no Windows certificate store
# is required. Used by the app-only (certificate-based) authentication path.
function Get-ZTAssessCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [securestring]$Password
    )

    # Fail fast with an actionable message if the file is not present.
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Certificate file not found at path '$Path'. Provide the full path to a readable .pfx/.p12 file."
    }

    try {
        $certificateBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).ProviderPath)

        if ($Password) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes, $Password)
        }

        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes)
    } catch {
        throw "Failed to load certificate from '$Path': $($_.Exception.Message)"
    }
}
