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

Describe 'Test-ZTAssessApplicationSecurity' -Tag 'Unit' {

    Context 'When the tenant is well configured (baseline fixture)' {
        BeforeAll {
            $script:runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'good-run')
            $script:findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $script:runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }
        }

        It 'Should emit a finding for every application security check' {
            $script:findings.Count | Should -Be 7
        }

        It 'Should pass check <_>' -ForEach @('AS-001', 'AS-002', 'AS-003', 'AS-004', 'AS-005', 'AS-006', 'AS-007') {
            ($script:findings | Where-Object CheckId -eq $_).Status | Should -Be 'Pass'
        }
    }

    Context 'When legacy unrestricted user consent is enabled' {
        It 'Should fail AS-001' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'legacy-consent') -Overrides @{
                authorizationPolicy = @{
                    id                         = 'authorizationPolicy'
                    allowInvitesFrom           = 'adminsAndGuestInviters'
                    guestUserRoleId            = '2af84b1e-32c8-42b7-82bc-daa82404023b'
                    defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy') }
                }
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }

            $as001 = $findings | Where-Object CheckId -eq 'AS-001'
            $as001.Status | Should -Be 'Fail'
            $as001.Severity | Should -Be 'High'
        }
    }

    Context 'When a workload identity holds a Tier-0 Graph application permission' {
        It 'Should fail AS-002 as Critical naming the principal' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'tier0-app') -Overrides @{
                graphAppRoleAssignments = @(
                    @{ id = 'ara-1'; principalId = 'sp-1'; principalDisplayName = 'Workload App'; appRoleId = 'role-role-rw'; resourceId = 'graph-sp' }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }

            $as002 = $findings | Where-Object CheckId -eq 'AS-002'
            $as002.Status | Should -Be 'Fail'
            $as002.Severity | Should -Be 'Critical'
            $as002.Evidence | Should -Match 'RoleManagement.ReadWrite.Directory'
        }
    }

    Context 'When credentials exceed the validity ceiling' {
        It 'Should rate AS-003 Partial' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'long-cred') -Overrides @{
                applications = @(
                    @{ id = 'app-obj-1'; appId = 'app-1'; displayName = 'Long-lived app'
                        web = @{ redirectUris = @('https://app.contoso.com') }; spa = @{ redirectUris = @() }; publicClient = @{ redirectUris = @() }
                        keyCredentials = @(@{ keyId = 'kc-1'; startDateTime = [datetime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'); endDateTime = [datetime]::UtcNow.AddYears(4).ToString('yyyy-MM-ddTHH:mm:ssZ') })
                        passwordCredentials = @(); verifiedPublisher = @{ displayName = 'Contoso' }; owners = @(@{ id = 'u-1' })
                    }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'AS-003').Status | Should -Be 'Partial'
        }
    }

    Context 'When redirect URIs are risky' {
        It 'Should fail AS-005 for wildcard and HTTP URIs' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'bad-uris') -Overrides @{
                applications = @(
                    @{ id = 'app-obj-1'; appId = 'app-1'; displayName = 'Risky app'
                        web = @{ redirectUris = @('https://*.contoso.com/auth', 'http://intranet.contoso.com/cb') }
                        spa = @{ redirectUris = @() }; publicClient = @{ redirectUris = @() }
                        keyCredentials = @(); passwordCredentials = @(); verifiedPublisher = @{ displayName = 'Contoso' }; owners = @(@{ id = 'u-1' })
                    }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }

            $as005 = $findings | Where-Object CheckId -eq 'AS-005'
            $as005.Status | Should -Be 'Fail'
            $as005.Evidence | Should -Match 'Risky app'
        }
    }

    Context 'When an app registration with credentials has no owner' {
        It 'Should fail AS-007' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'ownerless') -Overrides @{
                applications = @(
                    @{ id = 'app-obj-1'; appId = 'app-1'; displayName = 'Orphan app'
                        web = @{ redirectUris = @('https://app.contoso.com') }; spa = @{ redirectUris = @() }; publicClient = @{ redirectUris = @() }
                        keyCredentials = @(@{ keyId = 'kc-1'; startDateTime = [datetime]::UtcNow.AddDays(-10).ToString('yyyy-MM-ddTHH:mm:ssZ'); endDateTime = [datetime]::UtcNow.AddDays(355).ToString('yyyy-MM-ddTHH:mm:ssZ') })
                        passwordCredentials = @(); verifiedPublisher = @{ displayName = 'Contoso' }; owners = @()
                    }
                )
            }

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'AS-007').Status | Should -Be 'Fail'
        }
    }

    Context 'When workload identity sign-in data is unavailable' {
        It 'Should mark AS-004 NotAssessed' {
            $runPath = New-ZTAssessTestRun -Path (Join-Path $TestDrive 'no-sp-signin') -ExcludeSnapshots @('spSignInActivities')

            $findings = InModuleScope -ModuleName $script:dscModuleName -Parameters @{ runPath = $runPath } {
                param($runPath)
                Test-ZTAssessApplicationSecurity -RunPath $runPath
            }

            ($findings | Where-Object CheckId -eq 'AS-004').Status | Should -Be 'NotAssessed'
        }
    }
}
