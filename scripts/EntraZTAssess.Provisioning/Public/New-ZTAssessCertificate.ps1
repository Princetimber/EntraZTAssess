#Requires -Version 7.0

function New-ZTAssessCertificate {
    <#
    .SYNOPSIS
    Creates a self-signed certificate for EntraZTAssess app-only authentication.

    .DESCRIPTION
    Generates a self-signed X.509 certificate using pure .NET cryptography so the
    function behaves identically on macOS, Linux, and Windows (it does not depend
    on the Windows-only New-SelfSignedCertificate cmdlet).

    Two artifacts are produced:

      * A DER-encoded public certificate (.cer) that is uploaded to the Entra ID
        app registration by New-ZTAssessAppRegistration.
      * A password-protected PKCS#12 archive (.pfx) that holds the private key.
        The .pfx is the cross-platform private-key artifact used by
        Connect-ZTAssessment for certificate-based authentication on macOS and
        Linux, which have no reliable certificate store.

    This is a one-time, admin-run setup step. It performs no network calls and
    writes nothing sensitive to disk beyond the password-protected .pfx. The PFX
    password is never written to disk or emitted to logs. On macOS and Linux the
    output directory and .pfx file are restricted to the owner (0700/0600) after
    they are written.

    .PARAMETER SubjectName
    The X.500 distinguished name (subject) of the certificate. Defaults to
    'CN=EntraZTAssess'.

    .PARAMETER ValidityMonths
    The number of months the certificate remains valid, from 1 to 60. Defaults
    to 24.

    .PARAMETER OutputPath
    The directory that receives EntraZTAssess.cer and EntraZTAssess.pfx. Created
    if it does not exist. Defaults to the .ztassess folder under the current
    user's home directory.

    .PARAMETER PfxPassword
    The password protecting the exported .pfx private key, supplied as a
    SecureString. If omitted, the function prompts for it securely. The password
    is never persisted.

    .PARAMETER InstallToWindowsStore
    On Windows only, also imports the certificate (with its private key) into the
    CurrentUser\My certificate store so Connect-ZTAssessment can authenticate by
    thumbprint. Ignored with a warning on macOS and Linux.

    .EXAMPLE
    New-ZTAssessCertificate

    Creates EntraZTAssess.cer and EntraZTAssess.pfx under ~/.ztassess, prompting
    for the PFX password.

    .EXAMPLE
    $pw = Read-Host -AsSecureString 'PFX password'
    New-ZTAssessCertificate -SubjectName 'CN=Contoso ZTAssess' -ValidityMonths 12 -PfxPassword $pw

    Creates a 12-month certificate with a custom subject using a pre-collected
    SecureString password.

    .EXAMPLE
    New-ZTAssessCertificate -InstallToWindowsStore

    On Windows, also installs the certificate into CurrentUser\My so it can be
    referenced by thumbprint alone.

    .OUTPUTS
    PSCustomObject
    An object with Thumbprint, Subject, NotAfter, CerPath, PfxPath, and Platform.

    .NOTES
    Upload the resulting .cer with New-ZTAssessAppRegistration. Keep the .pfx
    and its password safe; anyone holding both can authenticate as the assessment
    application.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive admin-run provisioning function; coloured console guidance is intentional and not pipeline output.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SubjectName = 'CN=EntraZTAssess',

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$ValidityMonths = 24,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Join-Path -Path $HOME -ChildPath '.ztassess'),

        [Parameter()]
        [securestring]$PfxPassword,

        [Parameter()]
        [switch]$InstallToWindowsStore
    )

    $ErrorActionPreference = 'Stop'

    # Prompt for the PFX password only when the caller did not supply one.
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host -AsSecureString -Prompt 'Enter a password to protect the exported .pfx private key'
    }

    if (-not $PfxPassword -or $PfxPassword.Length -eq 0) {
        throw 'A non-empty PFX password is required to protect the exported private key.'
    }

    # Ensure the output directory exists before exporting.
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        if ($PSCmdlet.ShouldProcess($OutputPath, 'Create output directory')) {
            $null = New-Item -Path $OutputPath -ItemType Directory -Force
        }
    }

    # Restrict the output directory to the owner on macOS/Linux, since it holds
    # a password-protected private key archive. SetUnixFileMode throws on
    # Windows, so it is only ever attempted off-Windows.
    if ((Test-Path -LiteralPath $OutputPath) -and -not (Test-ZTAssessIsWindowsPlatform)) {
        $ownerRwx = [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute'
        Invoke-ZTAssessSetUnixFileMode -Path $OutputPath -Mode $ownerRwx
    }

    $cerPath = Join-Path -Path $OutputPath -ChildPath 'EntraZTAssess.cer'
    $pfxPath = Join-Path -Path $OutputPath -ChildPath 'EntraZTAssess.pfx'

    # Build the key pair and self-signed certificate with pure .NET so the flow is
    # identical on macOS, Linux, and Windows.
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)

    try {
        $certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $SubjectName,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        $notBefore = [System.DateTimeOffset]::UtcNow.AddMinutes(-5)
        $notAfter = [System.DateTimeOffset]::UtcNow.AddMonths($ValidityMonths)

        $certificate = $certRequest.CreateSelfSigned($notBefore, $notAfter)
    }
    finally {
        $rsa.Dispose()
    }

    try {
        # Export the DER-encoded public certificate (.cer) for upload to the app.
        if ($PSCmdlet.ShouldProcess($cerPath, 'Write public certificate (.cer)')) {
            $cerBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($cerPath, $cerBytes)
        }

        # Export the password-protected private key archive (.pfx). The SecureString
        # overload keeps the plaintext password from ever materializing in memory.
        if ($PSCmdlet.ShouldProcess($pfxPath, 'Write password-protected private key (.pfx)')) {
            $pfxBytes = $certificate.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
                $PfxPassword
            )
            [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

            # Restrict the .pfx to the owner on macOS/Linux; it holds the private key.
            if (-not (Test-ZTAssessIsWindowsPlatform)) {
                $ownerRw = [System.IO.UnixFileMode]'UserRead, UserWrite'
                Invoke-ZTAssessSetUnixFileMode -Path $pfxPath -Mode $ownerRw
            }
        }

        # On Windows only, optionally import into the user's personal store so the
        # certificate can be referenced by thumbprint alone.
        if ($InstallToWindowsStore) {
            if (Test-ZTAssessIsWindowsPlatform) {
                if (-not $pfxBytes) {
                    Write-Warning 'InstallToWindowsStore requires the .pfx to have been exported first; it was skipped (likely due to -WhatIf). Store import was not performed.'
                }
                elseif ($PSCmdlet.ShouldProcess('Cert:\CurrentUser\My', 'Install certificate to Windows store')) {
                    # $certificate's private key is ephemeral (from CreateSelfSigned) and
                    # is not guaranteed to persist through X509Store.Add on every .NET/OS
                    # combination. Round-trip it through the PFX bytes just exported, with
                    # PersistKeySet + Exportable, so the store copy reliably keeps a usable
                    # private key for certificate-based authentication by thumbprint.
                    $persistableCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                        $pfxBytes,
                        $PfxPassword,
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                    )
                    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
                    try {
                        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                        $store.Add($persistableCertificate)
                    }
                    finally {
                        $store.Close()
                        $persistableCertificate.Dispose()
                    }
                }
            }
            else {
                Write-Warning 'InstallToWindowsStore was requested but this is not Windows. Skipping store import; use the .pfx for certificate-based authentication instead.'
            }
        }

        $platformNote = if (Test-ZTAssessIsWindowsPlatform) {
            'Windows: reference the certificate by thumbprint (store) or by the .pfx.'
        }
        else {
            'macOS/Linux: use the .pfx with its password for certificate-based authentication.'
        }

        $result = [pscustomobject]@{
            PSTypeName = 'ZTAssess.Certificate'
            Thumbprint = $certificate.Thumbprint
            Subject    = $certificate.Subject
            NotAfter   = $certificate.NotAfter
            CerPath    = $cerPath
            PfxPath    = $pfxPath
            Platform   = $platformNote
        }

        Write-Host ''
        Write-Host 'Certificate created.' -ForegroundColor Green
        Write-Host ("  Thumbprint : {0}" -f $result.Thumbprint)
        Write-Host ("  Subject    : {0}" -f $result.Subject)
        Write-Host ("  Expires    : {0:yyyy-MM-dd}" -f $result.NotAfter)
        Write-Host ("  Public cer : {0}" -f $result.CerPath)
        Write-Host ("  Private pfx: {0}" -f $result.PfxPath)
        Write-Host ''
        Write-Host 'Next step: register the application and upload the public certificate:' -ForegroundColor Cyan
        Write-Host ("  New-ZTAssessAppRegistration -TenantId <tenant> -CertificatePath '{0}'" -f $result.CerPath)
        Write-Host ''

        return $result
    }
    finally {
        $certificate.Dispose()
    }
}
