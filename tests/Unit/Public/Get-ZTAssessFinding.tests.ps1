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

    # Build a run folder with a small findings.json fixture.
    $script:runPath = Join-Path $TestDrive 'run-1'
    $null = New-Item -Path (Join-Path $script:runPath 'Findings') -ItemType Directory -Force

    @(
        @{ CheckId = 'ID-001'; Domain = 'IdentitySecurity'; Title = 'MFA coverage'; Status = 'Pass'; Severity = 'None'; MaturityWeight = 5 }
        @{ CheckId = 'CA-001'; Domain = 'ConditionalAccess'; Title = 'All users MFA'; Status = 'Fail'; Severity = 'Critical'; MaturityWeight = 5 }
        @{ CheckId = 'CA-004'; Domain = 'ConditionalAccess'; Title = 'Risk policies'; Status = 'NotAssessed'; Severity = 'None'; MaturityWeight = 4 }
        @{ CheckId = 'PA-001'; Domain = 'PrivilegedAccess'; Title = 'GA count'; Status = 'Fail'; Severity = 'High'; MaturityWeight = 5 }
    ) | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $script:runPath 'Findings/findings.json') -Encoding utf8NoBOM
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-ZTAssessFinding' -Tag 'Unit' {

    Context 'When reading a persisted run' {
        It 'Should return every finding sorted by check ID' {
            $findings = Get-ZTAssessFinding -RunPath $script:runPath

            @($findings).Count | Should -Be 4
            @($findings)[0].CheckId | Should -Be 'CA-001'
        }

        It 'Should filter by domain' {
            $findings = Get-ZTAssessFinding -RunPath $script:runPath -Domain ConditionalAccess

            @($findings).Count | Should -Be 2
            (@($findings).Domain | Sort-Object -Unique) | Should -Be 'ConditionalAccess'
        }

        It 'Should filter by status and severity together' {
            $findings = Get-ZTAssessFinding -RunPath $script:runPath -Status Fail -Severity Critical

            @($findings).Count | Should -Be 1
            @($findings)[0].CheckId | Should -Be 'CA-001'
        }

        It 'Should return nothing when no finding matches' {
            Get-ZTAssessFinding -RunPath $script:runPath -Severity Low | Should -BeNullOrEmpty
        }
    }

    Context 'When the run path is invalid' {
        It 'Should reject a folder without findings.json' {
            $bare = Join-Path $TestDrive 'no-findings'
            $null = New-Item -Path $bare -ItemType Directory

            { Get-ZTAssessFinding -RunPath $bare } | Should -Throw
        }
    }
}
