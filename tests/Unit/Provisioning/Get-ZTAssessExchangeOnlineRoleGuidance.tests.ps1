#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provManifest = Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1'
    Import-Module -Name $script:provManifest -Force
}

AfterAll {
    Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'Get-ZTAssessExchangeOnlineRoleGuidance' -Tag 'Unit' {

    It 'Should return guidance only for modules that require Exchange Online / IPPS' {
        $result = Get-ZTAssessExchangeOnlineRoleGuidance

        $result.Module | Should -Contain 'ThreatProtection'
        $result.Module | Should -Contain 'SecurityCompliance'
        $result.Module | Should -Contain 'Collaboration'
        $result.Module | Should -Contain 'DataProtection'
        $result.Module | Should -Not -Contain 'Identity'
        $result.Module | Should -Not -Contain 'Devices'
    }

    It 'Should include non-empty role-group guidance for every returned module' {
        $result = Get-ZTAssessExchangeOnlineRoleGuidance

        foreach ($entry in $result) {
            $entry.ExchangeOnlineRoles | Should -Not -BeNullOrEmpty
        }
    }

    It 'Should filter to the requested module only' {
        $result = Get-ZTAssessExchangeOnlineRoleGuidance -Modules ThreatProtection

        $result.Count | Should -Be 1
        $result[0].Module | Should -Be 'ThreatProtection'
    }

    It 'Should return nothing for a requested module that does not require Exchange Online / IPPS' {
        $result = Get-ZTAssessExchangeOnlineRoleGuidance -Modules Identity

        $result | Should -BeNullOrEmpty
    }

    It 'Should throw on an unknown module name' {
        { Get-ZTAssessExchangeOnlineRoleGuidance -Modules 'NoSuchModule' } | Should -Throw
    }
}
