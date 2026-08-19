#Requires -Version 7.0

<#
    Read-only and secure-execution QA gate.

    The EntraZTAssess toolkit is read-only by design. These tests statically
    verify that no source file can issue a write request to Microsoft Graph,
    that all Graph traffic flows through the single guarded wrapper, and
    that no unsafe string execution exists anywhere in the module.
#>

BeforeDiscovery {
    $script:projectPath = "$($PSScriptRoot)/../.." | Convert-Path
}

BeforeAll {
    $projectPath = "$($PSScriptRoot)/../.." | Convert-Path
    $script:sourceFiles = @(Get-ChildItem -Path (Join-Path $projectPath 'source') -Recurse -Include '*.ps1', '*.psm1')
}

Describe 'Read-only enforcement' -Tag 'QA', 'ReadOnly' {

    It 'Should not call Invoke-MgGraphRequest outside the guarded wrapper' {
        $offenders = foreach ($file in $script:sourceFiles) {
            if ($file.Name -eq 'Invoke-MgGraphRequestWrapper.ps1') { continue }

            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match 'Invoke-MgGraphRequest\b(?!Wrapper)') {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'all Graph calls must flow through Invoke-MgGraphRequestWrapper, which only permits GET'
    }

    It 'Should not contain any write HTTP method tokens in Graph calls' {
        $writeMethodPattern = "-Method\s+'?(POST|PATCH|PUT|DELETE)'?"

        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match $writeMethodPattern) {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'the toolkit is read-only by default; write methods are forbidden in v1.0'
    }

    It 'Should restrict the Graph request wrapper to GET via ValidateSet' {
        $wrapper = $script:sourceFiles | Where-Object Name -eq 'Invoke-MgGraphRequestWrapper.ps1'

        $wrapper | Should -Not -BeNullOrEmpty
        (Get-Content -LiteralPath $wrapper.FullName -Raw) | Should -Match "\[ValidateSet\('GET'\)\]"
    }

    It 'Should not use Graph write SDK cmdlets anywhere under source/' {
        # Write-verb Microsoft.Graph SDK cmdlets (this also covers
        # New-MgServicePrincipalAppRoleAssignment). Read/auth cmdlets such as
        # Get-Mg*, Connect-MgGraph, and read snapshot names like
        # 'graphAppRoleAssignments' are deliberately excluded.
        $writeCmdletPattern = '\b(New|Set|Update|Remove|Add|Grant|Revoke|Enable|Disable|Send|Restore|Confirm|Deny)-Mg[A-Za-z]+\b'

        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match $writeCmdletPattern) {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'Graph write operations must live in scripts/EntraZTAssess.Provisioning, never under source/'
    }

    It 'Should restrict the Exchange Online/IPPS allow-list to Get-* cmdlets' {
        $allowListFile = $script:sourceFiles | Where-Object Name -eq 'Get-ZTAssessExoAllowedCmdletName.ps1'
        $allowListFile | Should -Not -BeNullOrEmpty

        $content = Get-Content -LiteralPath $allowListFile.FullName -Raw
        $cmdletNames = [regex]::Matches($content, "'([A-Za-z]+-[A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value }

        $cmdletNames | Should -Not -BeNullOrEmpty
        foreach ($cmdletName in $cmdletNames) {
            $cmdletName | Should -Match '^Get-' -Because 'the Exchange Online/IPPS allow-list must contain only read-only cmdlets'
        }
    }

    It 'Should not use write-verb Exchange Online/Purview cmdlets anywhere under source/' {
        $writeExoPattern = '\b(New|Set|Remove|Add|Enable|Disable|Start|Stop|Import|Export)-(DlpCompliance\w*|Label\w*|AntiPhish\w*|SafeLinks\w*|SafeAttachment\w*|TransportRule\w*|SharingPolicy\w*|RetentionCompliance\w*|ComplianceTag\w*|RoleGroup\w*|OrganizationConfig|HostedContentFilterPolicy\w*|MalwareFilterPolicy\w*)\b'

        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match $writeExoPattern) {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'Exchange Online/Purview write operations must never appear under source/'
    }

    It 'Should only call Connect-ExchangeOnline/Connect-IPPSSession/Disconnect-ExchangeOnline from their guarded wrappers' {
        $allowedFiles = @('Connect-ExchangeOnlineWrapper.ps1', 'Disconnect-ExchangeOnlineWrapper.ps1')

        $offenders = foreach ($file in $script:sourceFiles) {
            if ($file.Name -in $allowedFiles) { continue }

            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match '\b(Connect-ExchangeOnline|Connect-IPPSSession|Disconnect-ExchangeOnline)\b') {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'Exchange Online/IPPS session lifecycle must flow only through the guarded wrapper functions'
    }

    It 'Should document Exchange Online/IPPS role guidance for every module that requires it' {
        $projectPath = "$($PSScriptRoot)/../.." | Convert-Path
        $permissions = Import-PowerShellDataFile -LiteralPath (Join-Path $projectPath 'source/Settings/permissions.psd1')

        foreach ($moduleName in $permissions.Modules.Keys) {
            $module = $permissions.Modules[$moduleName]
            if ($module.RequiresExchangeOnline) {
                @($module.ExchangeOnlineRoles) | Should -Not -BeNullOrEmpty -Because "module '$moduleName' requires Exchange Online/IPPS but documents no role-group guidance"
            }
        }
    }
}

Describe 'Secure execution' -Tag 'QA', 'Security' {

    It 'Should not use Invoke-Expression anywhere in the module' {
        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match 'Invoke-Expression|\biex\b') {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'unsafe string execution is prohibited'
    }

    It 'Should not use remote PSSession invocation outside the ExchangeOnlineManagement session helpers' {
        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match 'Invoke-Command\s+-Session') {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'this module never manages PSSessions directly; ExchangeOnlineManagement owns the remote session'
    }

    It 'Should not contain hard-coded secret-like assignments' {
        $secretPattern = '(?i)\$(password|secret|apikey|token)\s*=\s*["''][^"'']{8,}["'']'

        $offenders = foreach ($file in $script:sourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match $secretPattern) {
                $file.FullName
            }
        }

        $offenders | Should -BeNullOrEmpty -Because 'secrets must never be embedded in code'
    }

    It 'Should declare only read-only Graph scopes in the permissions catalogue' {
        $projectPath = "$($PSScriptRoot)/../.." | Convert-Path
        $permissions = Import-PowerShellDataFile -LiteralPath (Join-Path $projectPath 'source/Settings/permissions.psd1')

        foreach ($moduleName in $permissions.Modules.Keys) {
            foreach ($scope in $permissions.Modules[$moduleName].Scopes) {
                $scope | Should -Not -Match '(?i)\.(ReadWrite|Write)\b' -Because "module '$moduleName' must not request write scope '$scope'"
            }
        }
    }
}
