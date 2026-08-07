#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provManifest = Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1'
    Import-Module -Name $script:provManifest -Force
}

AfterAll {
    Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'New-ZTAssessCertificate' -Tag 'Unit' {

    It 'Should create a .cer and password-protected .pfx and return a summary' {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs'

        $result = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw -ValidityMonths 12

        $result.PSObject.TypeNames | Should -Contain 'ZTAssess.Certificate'
        Test-Path -LiteralPath $result.CerPath | Should -BeTrue
        Test-Path -LiteralPath $result.PfxPath | Should -BeTrue
        $result.Thumbprint | Should -Not -BeNullOrEmpty
    }

    It 'Should produce a .pfx that can be reloaded with its password' {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs2'

        $result = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw

        $reloaded = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $result.PfxPath, $securePw)
        $reloaded.Thumbprint | Should -Be $result.Thumbprint
        $reloaded.Dispose()
    }

    It 'Should throw when given an empty PFX password' {
        $empty = [securestring]::new()
        { New-ZTAssessCertificate -OutputPath (Join-Path $TestDrive 'c3') -PfxPassword $empty } |
            Should -Throw -ExpectedMessage '*password*'
    }

    It 'Should restrict the output directory and .pfx to the owner on macOS/Linux' -Skip:$IsWindows {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs-perms'

        $result = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw

        $dirMode = [System.IO.File]::GetUnixFileMode($outDir)
        $pfxMode = [System.IO.File]::GetUnixFileMode($result.PfxPath)

        $dirMode | Should -Be ([System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute')
        $pfxMode | Should -Be ([System.IO.UnixFileMode]'UserRead, UserWrite')
    }

    It 'Should warn and skip store import when -InstallToWindowsStore is used off-Windows' -Skip:$IsWindows {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs-nonwin-store'

        $warnings = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw -InstallToWindowsStore -WarningVariable warnOutput -WarningAction SilentlyContinue

        $warnOutput | Should -Not -BeNullOrEmpty
        $warnOutput[0] | Should -BeLike '*not Windows*'
    }

    It 'Should install a certificate with a usable private key into CurrentUser\My' -Skip:(-not $IsWindows) {
        $securePw = ConvertTo-SecureString 'ZtAssessPfx!123' -AsPlainText -Force
        $outDir = Join-Path $TestDrive 'certs-win-store'

        $result = New-ZTAssessCertificate -OutputPath $outDir -PfxPassword $securePw -InstallToWindowsStore

        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $installed = $store.Certificates | Where-Object { $_.Thumbprint -eq $result.Thumbprint }
            $installed | Should -Not -BeNullOrEmpty
            $installed.HasPrivateKey | Should -BeTrue
        }
        finally {
            if ($installed) {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Remove($installed)
            }
            $store.Close()
        }
    }
}
