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
