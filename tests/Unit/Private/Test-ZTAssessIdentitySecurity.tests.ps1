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

    . (Join-Path $PSScriptRoot '../../Fixtures/FixtureHelper.ps1')
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Test-ZTAssessIdentitySecurity' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessIdentitySecurity -RunPath $runPath
            }
        }

        It 'Should emit a finding for every identity check' {
            $script:findings.Count | Should -Be 12
            ($script:findings.CheckId | Sort-Object -Unique).Count | Should -Be 12
        }

        It 'Should pass check <_>' -ForEach @('ID-001', 'ID-003', 'ID-004', 'ID-005', 'ID-006', 'ID-007', 'ID-008', 'ID-009', 'ID-011', 'ID-012') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should mark ID-010 as NotAssessed (beta endpoint dependency)' {
            $finding = $script:findings | Where-Object CheckId -eq 'ID-010'
            $finding.Status | Should -Be 'NotAssessed'
            $finding.NotAssessedReason | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When MFA registration coverage is poor' {
        It 'Should fail ID-001 with High severity below the fail threshold' {
            $regDetails = @(
                @{ id = 'u-1'; userType = 'member'; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true }
                @{ id = 'u-2'; userType = 'member'; isMfaRegistered = $false; isMfaCapable = $false; isSsprEnabled = $true; isSsprRegistered = $false }
                @{ id = 'u-3'; userType = 'member'; isMfaRegistered = $false; isMfaCapable = $false; isSsprEnabled = $true; isSsprRegistered = $false }
                @{ id = 'u-4'; userType = 'member'; isMfaRegistered = $false; isMfaCapable = $false; isSsprEnabled = $true; isSsprRegistered = $false }
            )
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'low-mfa') -Overrides @{ userRegistrationDetails = $regDetails }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentitySecurity -RunPath $runPath
            }

            $id001 = $findings | Where-Object CheckId -eq 'ID-001'
            $id001.Status | Should -Be 'Fail'
            $id001.Severity | Should -Be 'High'
        }
    }

    Context 'When legacy authentication is observed with no blocking policy' {
        It 'Should escalate ID-003 to Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'legacy-open') -Overrides @{
                conditionalAccessPolicies = @()
                legacyAuthSignIns         = @{ lookbackDays = 30; totalLegacyCount = 42; countsByClientApp = @(@{ clientAppUsed = 'IMAP4'; count = 42 }) }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentitySecurity -RunPath $runPath
            }

            $id003 = $findings | Where-Object CheckId -eq 'ID-003'
            $id003.Status | Should -Be 'Fail'
            $id003.Severity | Should -Be 'Critical'
        }
    }

    Context 'When neither security defaults nor Conditional Access protect the tenant' {
        It 'Should fail ID-004 as Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-baseline') -Overrides @{
                conditionalAccessPolicies = @()
                securityDefaultsPolicy    = @{ isEnabled = $false }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentitySecurity -RunPath $runPath
            }

            $id004 = $findings | Where-Object CheckId -eq 'ID-004'
            $id004.Status | Should -Be 'Fail'
            $id004.Severity | Should -Be 'Critical'
        }
    }

    Context 'When no break-glass account is identifiable' {
        It 'Should fail ID-009' {
            # Remove the break-glass CA exclusions so no GA is excluded everywhere.
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-bg')
            $policies = Get-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Raw | ConvertFrom-Json -Depth 20
            foreach ($policy in $policies) { $policy.conditions.users.excludeUsers = @() }
            $policies | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/conditionalAccessPolicies.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentitySecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'ID-009').Status | Should -Be 'Fail'
        }
    }

    Context 'When snapshots are missing' {
        It 'Should mark registration-dependent checks NotAssessed without erroring' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'missing-reg') -ExcludeSnapshots @('userRegistrationDetails')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentitySecurity -RunPath $runPath
            }

            foreach ($checkId in @('ID-001', 'ID-002', 'ID-012')) {
                $finding = $findings | Where-Object CheckId -eq $checkId
                $finding.Status | Should -Be 'NotAssessed' -Because "$checkId depends on userRegistrationDetails"
                $finding.NotAssessedReason | Should -Not -BeNullOrEmpty
            }
        }
    }
}
