#Requires -Version 7.0

BeforeAll {
    $script:dscModuleName = 'Get-EntraZTAssess'

    <#
        Prefer an installed or built module; fall back to the source manifest
        so bare Invoke-Pester works without a prior build or PSModulePath
        registration.
    #>
    if (Get-Module -ListAvailable -Name $script:dscModuleName -ErrorAction SilentlyContinue) {
        Import-Module -Name $script:dscModuleName -Force
    }
    else {
        Import-Module -Name (Join-Path $PSScriptRoot '../../../source/Get-EntraZTAssess.psd1') -Force
    }
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessCertificate' -Tag 'Unit' {

    Context 'When loading a password-protected PFX file' {
        It 'Should return an X509Certificate2 with the expected thumbprint' {
            InModuleScope -ModuleName $script:dscModuleName {
                # Generate a throwaway self-signed certificate fully in-memory
                # (ECDsa keeps this cross-platform without Windows CNG).
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=ZTAssessTest', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                $sourceCertificate = $request.CreateSelfSigned(
                    [System.DateTimeOffset]::UtcNow.AddDays(-1),
                    [System.DateTimeOffset]::UtcNow.AddDays(1))

                $pfxPassword = 'ZtAssessPfx!123'
                $pfxBytes = $sourceCertificate.Export(
                    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)

                $pfxPath = Join-Path $TestDrive 'protected.pfx'
                [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

                $securePassword = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
                $loaded = Get-ZTAssessCertificate -Path $pfxPath -Password $securePassword

                $loaded | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
                $loaded.Thumbprint | Should -Be $sourceCertificate.Thumbprint
            }
        }
    }

    Context 'When loading an unprotected PFX file' {
        It 'Should load the certificate without a password' {
            InModuleScope -ModuleName $script:dscModuleName {
                $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=ZTAssessTestNoPass', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                $sourceCertificate = $request.CreateSelfSigned(
                    [System.DateTimeOffset]::UtcNow.AddDays(-1),
                    [System.DateTimeOffset]::UtcNow.AddDays(1))

                $pfxBytes = $sourceCertificate.Export(
                    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)

                $pfxPath = Join-Path $TestDrive 'open.pfx'
                [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

                $loaded = Get-ZTAssessCertificate -Path $pfxPath

                $loaded.Thumbprint | Should -Be $sourceCertificate.Thumbprint
            }
        }
    }

    Context 'When the certificate file does not exist' {
        It 'Should throw an actionable not-found error' {
            InModuleScope -ModuleName $script:dscModuleName {
                $missingPath = Join-Path $TestDrive 'missing.pfx'

                { Get-ZTAssessCertificate -Path $missingPath } |
                    Should -Throw -ExpectedMessage '*not found*'
            }
        }
    }
}
