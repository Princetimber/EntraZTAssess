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

Describe 'Test-ZTAssessPrivilegedAccess' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }
        }

        It 'Should emit a finding for every privileged access check' {
            $script:findings.Count | Should -Be 10
        }

        It 'Should pass check <_>' -ForEach @('PA-001', 'PA-002', 'PA-003', 'PA-004', 'PA-005', 'PA-006', 'PA-007', 'PA-008', 'PA-009', 'PA-010') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When too many Global Administrators exist' {
        It 'Should fail PA-001' {
            $assignments = 1..7 | ForEach-Object { @{ id = "ra-$_"; principalId = "admin-$_"; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' } }
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'many-ga') -Overrides @{ roleAssignments = @($assignments) }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'PA-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When a synchronised account holds Global Administrator' {
        It 'Should fail PA-004 as Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'synced-ga')
            $users = Get-Content (Join-Path $runPath 'Raw/users.json') -Raw | ConvertFrom-Json -Depth 20
            ($users | Where-Object id -eq 'bg-1').onPremisesSyncEnabled = $true
            $users | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/users.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            $pa004 = $findings | Where-Object CheckId -eq 'PA-004'
            $pa004.Status | Should -Be 'Fail'
            $pa004.Severity | Should -Be 'Critical'
        }
    }

    Context 'When a guest holds a privileged role' {
        It 'Should fail PA-008 as Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'guest-ga')
            $users = Get-Content (Join-Path $runPath 'Raw/users.json') -Raw | ConvertFrom-Json -Depth 20
            ($users | Where-Object id -eq 'bg-2').userType = 'Guest'
            $users | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $runPath 'Raw/users.json') -Encoding utf8NoBOM

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            $pa008 = $findings | Where-Object CheckId -eq 'PA-008'
            $pa008.Status | Should -Be 'Fail'
            $pa008.Severity | Should -Be 'Critical'
        }
    }

    Context 'When a service principal holds a privileged role' {
        It 'Should fail PA-009 as Critical' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'sp-ga') -Overrides @{
                roleAssignments = @(
                    @{ id = 'ra-1'; principalId = 'bg-1'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
                    @{ id = 'ra-2'; principalId = 'bg-2'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
                    @{ id = 'ra-3'; principalId = 'sp-1'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            $pa009 = $findings | Where-Object CheckId -eq 'PA-009'
            $pa009.Status | Should -Be 'Fail'
            $pa009.Severity | Should -Be 'Critical'
            $pa009.Evidence | Should -Match 'Workload App'
        }
    }

    Context 'When a privileged role is granted to a standard group' {
        It 'Should fail PA-007' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'std-group') -Overrides @{
                groups          = @(@{ id = 'g-std'; displayName = 'Standard Group'; isAssignableToRole = $false; securityEnabled = $true })
                roleAssignments = @(
                    @{ id = 'ra-1'; principalId = 'bg-1'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
                    @{ id = 'ra-2'; principalId = 'bg-2'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
                    @{ id = 'ra-3'; principalId = 'g-std'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'PA-007').Status | Should -Be 'Fail'
        }
    }

    Context 'When PIM schedule data is unavailable (no P2)' {
        It 'Should mark PA-002 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-pim') -ExcludeSnapshots @('roleEligibilitySchedules', 'roleAssignmentSchedules')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'PA-002').Status | Should -Be 'NotAssessed'
        }
    }

    Context 'When role snapshots are missing entirely' {
        It 'Should mark every check NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-roles') -ExcludeSnapshots @('roleDefinitions', 'roleAssignments')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessPrivilegedAccess -RunPath $runPath
            }

            $findings.Count | Should -Be 10
            ($findings | Where-Object Status -ne 'NotAssessed').Count | Should -Be 0
        }
    }
}
