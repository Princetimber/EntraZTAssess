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

Describe 'Test-ZTAssessIdentityGovernance' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessIdentityGovernance -RunPath $runPath
            }
        }

        It 'Should emit a finding for every identity governance check' {
            $script:findings.Count | Should -Be 6
        }

        It 'Should pass check <_>' -ForEach @('IG-001', 'IG-002', 'IG-003', 'IG-004', 'IG-005') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }

        It 'Should report IG-006 as Informational with the trust posture' {
            $ig006 = $script:findings | Where-Object CheckId -eq 'IG-006'
            $ig006.Status | Should -Be 'Informational'
            $ig006.Evidence | Should -Match 'Inbound trust'
        }
    }

    Context 'When no access reviews cover privileged roles' {
        It 'Should fail IG-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-role-review') -Overrides @{
                accessReviewDefinitions = @(
                    @{ id = 'rev-x'; displayName = 'Quarterly app review'; scope = @{ query = '/groups/abc/members' } }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentityGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'IG-001').Status | Should -Be 'Fail'
        }
    }

    Context 'When guests exceed the threshold with no guest review' {
        It 'Should fail IG-002' {
            $guests = 1..12 | ForEach-Object {
                @{ id = "guest-$_"; userPrincipalName = "guest$_@ext.com"; accountEnabled = $true; userType = 'Guest'; onPremisesSyncEnabled = $false; assignedLicenses = @() }
            }
            $baseUsers = @(
                @{ id = 'bg-1'; userPrincipalName = 'breakglass1@contoso.com'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false; assignedLicenses = @() }
            )
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'many-guests') -Overrides @{
                users                   = @($baseUsers + $guests)
                accessReviewDefinitions = @(
                    @{ id = 'rev-1'; displayName = 'Privileged role assignments review'; scope = @{ query = '/roleManagement/directory/roleAssignments' } }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentityGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'IG-002').Status | Should -Be 'Fail'
        }
    }

    Context 'When guest settings are permissive' {
        It 'Should fail IG-005 when everyone can invite' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'open-invites') -Overrides @{
                authorizationPolicy = @{
                    id                         = 'authorizationPolicy'
                    allowInvitesFrom           = 'everyone'
                    guestUserRoleId            = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
                    defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() }
                }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentityGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'IG-005').Status | Should -Be 'Fail'
        }
    }

    Context 'When governance snapshots are missing (no P2/Governance licence)' {
        It 'Should mark licence-dependent checks NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-gov') -ExcludeSnapshots @('accessReviewDefinitions', 'accessPackages')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessIdentityGovernance -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'IG-001').Status | Should -Be 'NotAssessed'
            ($findings | Where-Object CheckId -eq 'IG-003').Status | Should -Be 'NotAssessed'
        }
    }
}
