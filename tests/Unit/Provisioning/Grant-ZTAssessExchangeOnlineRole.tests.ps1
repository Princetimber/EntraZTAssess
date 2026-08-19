#Requires -Version 7.0

BeforeAll {
    $script:provModuleName = 'EntraZTAssess.Provisioning'
    $script:provManifest = Join-Path $PSScriptRoot '../../../scripts/EntraZTAssess.Provisioning/EntraZTAssess.Provisioning.psd1'

    # Advanced-function stubs for the ExchangeOnlineManagement cmdlets. They
    # declare exactly the named parameters the function passes, so both the
    # stub and the Pester-generated mock bind those arguments cleanly. This
    # lets the function's Get-Command precondition pass and the tests run
    # with no real SDK installed.
    function global:Connect-ExchangeOnline { [CmdletBinding()] param($Organization, $ShowBanner, $UserPrincipalName) }
    function global:Connect-IPPSSession { [CmdletBinding()] param($Organization, $ShowBanner, $UserPrincipalName) }
    function global:Disconnect-ExchangeOnline { [CmdletBinding()] param([switch]$Confirm) }
    function global:Get-ServicePrincipal { [CmdletBinding()] param($Identity) }
    function global:New-ServicePrincipal { [CmdletBinding()] param($AppId, $ObjectId, $DisplayName) }
    function global:Get-RoleGroupMember { [CmdletBinding()] param($Identity) }
    function global:Add-RoleGroupMember { [CmdletBinding()] param($Identity, $Member, [switch]$Confirm) }
    function global:New-ManagementRoleAssignment { [CmdletBinding()] param($Role, $App) }

    Import-Module -Name $script:provManifest -Force

    $script:appId = '11111111-1111-1111-1111-111111111111'
    $script:spObjectId = '22222222-2222-2222-2222-222222222222'
    # The EXO-side service principal identity, distinct from the Entra AppId
    # -- role-group membership must be checked/added against this, not AppId.
    $script:spIdentity = '33333333-3333-3333-3333-333333333333'
}

AfterAll {
    Get-Module -Name $script:provModuleName -All | Remove-Module -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\Connect-ExchangeOnline, Function:\Connect-IPPSSession, Function:\Disconnect-ExchangeOnline, `
        Function:\Get-ServicePrincipal, Function:\New-ServicePrincipal, `
        Function:\Get-RoleGroupMember, Function:\Add-RoleGroupMember, `
        Function:\New-ManagementRoleAssignment -ErrorAction SilentlyContinue
}

Describe 'Grant-ZTAssessExchangeOnlineRole' -Tag 'Unit' {

    BeforeEach {
        Mock -ModuleName $script:provModuleName Connect-ExchangeOnline { }
        Mock -ModuleName $script:provModuleName Connect-IPPSSession { }
        Mock -ModuleName $script:provModuleName Disconnect-ExchangeOnline { }
        Mock -ModuleName $script:provModuleName Get-ServicePrincipal { [pscustomobject]@{ Identity = $script:spIdentity } }
        Mock -ModuleName $script:provModuleName New-ServicePrincipal {
            [pscustomobject]@{ Identity = $script:spIdentity }
        }

        # Default fixture matching the confirmed live-tenant shape for
        # ThreatProtection's two entries: 'Security Reader' is a genuine role
        # group; 'View-Only Configuration' is a management role only (not a
        # role group), so Get-RoleGroupMember throws for it and the function
        # must fall back to New-ManagementRoleAssignment.
        Mock -ModuleName $script:provModuleName Get-RoleGroupMember {
            if ($Identity -eq 'View-Only Configuration') {
                throw 'The role group was not found.'
            }
            @()
        }
        Mock -ModuleName $script:provModuleName Add-RoleGroupMember { }
        Mock -ModuleName $script:provModuleName New-ManagementRoleAssignment { }
    }

    It 'Should create the Exchange Online service principal when none exists' {
        Mock -ModuleName $script:provModuleName Get-ServicePrincipal { $null }

        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -ServicePrincipalObjectId $script:spObjectId `
            -Organization 'contoso.onmicrosoft.com' -Modules 'ThreatProtection' -Confirm:$false

        $result.PSObject.TypeNames | Should -Contain 'ZTAssess.ExchangeOnlineRoleGrant'
        $result.ServicePrincipalCreated | Should -BeTrue
        Should -Invoke -ModuleName $script:provModuleName New-ServicePrincipal -Times 1 -Exactly
    }

    It 'Should not create a service principal when one already exists' {
        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.ServicePrincipalCreated | Should -BeFalse
        Should -Invoke -ModuleName $script:provModuleName New-ServicePrincipal -Times 0 -Exactly
    }

    It 'Should throw when no service principal exists and -ServicePrincipalObjectId is not supplied' {
        Mock -ModuleName $script:provModuleName Get-ServicePrincipal { $null }

        { Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
                -Modules 'ThreatProtection' -Confirm:$false
        } | Should -Throw '*ServicePrincipalObjectId*'
    }

    It 'Should not connect to Exchange Online as the app being granted roles' {
        Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -UserPrincipalName 'admin@contoso.onmicrosoft.com' -Modules 'ThreatProtection' -Confirm:$false

        Should -Invoke -ModuleName $script:provModuleName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            $UserPrincipalName -eq 'admin@contoso.onmicrosoft.com'
        }
    }

    It 'Should grant a genuine role group via Add-RoleGroupMember' {
        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.RoleGroupsGranted | Should -Contain 'Security Reader'
        Should -Invoke -ModuleName $script:provModuleName Add-RoleGroupMember -Times 1 -Exactly -ParameterFilter {
            $Identity -eq 'Security Reader' -and $Member -eq $script:spIdentity
        }
    }

    It 'Should fall back to a management-role assignment when an entry is not a role group' {
        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.RoleGroupsGranted | Should -Contain 'View-Only Configuration'
        Should -Invoke -ModuleName $script:provModuleName New-ManagementRoleAssignment -Times 1 -Exactly -ParameterFilter {
            $Role -eq 'View-Only Configuration' -and $App -eq $script:appId
        }
        Should -Invoke -ModuleName $script:provModuleName Add-RoleGroupMember -Times 0 -Exactly -ParameterFilter {
            $Identity -eq 'View-Only Configuration'
        }
    }

    It 'Should skip role groups the service principal is already a member of' {
        Mock -ModuleName $script:provModuleName Get-RoleGroupMember {
            if ($Identity -eq 'View-Only Configuration') { throw 'The role group was not found.' }
            @([pscustomobject]@{ Identity = $script:spIdentity })
        }

        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.RoleGroupsAlreadyMember | Should -Contain 'Security Reader'
        Should -Invoke -ModuleName $script:provModuleName Add-RoleGroupMember -Times 0 -Exactly
    }

    It 'Should treat an "already" error from New-ManagementRoleAssignment as already granted' {
        Mock -ModuleName $script:provModuleName New-ManagementRoleAssignment {
            if ($Role -eq 'View-Only Configuration') { throw 'This role assignment already exists.' }
        }

        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.RoleGroupsAlreadyMember | Should -Contain 'View-Only Configuration'
        $result.FailedGrants.RoleGroup | Should -Not -Contain 'View-Only Configuration'
    }

    It 'Should retry via IPPS when both role-group and management-role attempts fail against Exchange Online' {
        Mock -ModuleName $script:provModuleName New-ManagementRoleAssignment {
            if ($Role -ne 'View-Only Configuration') { return }
            # First call (against the Exchange Online connection) fails;
            # a second call after Connect-IPPSSession succeeds.
            if (-not $script:ippsAttempted) {
                $script:ippsAttempted = $true
                throw 'ManagementRoleNotFoundException'
            }
        }
        $script:ippsAttempted = $false

        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.RoleGroupsGranted | Should -Contain 'View-Only Configuration'
        Should -Invoke -ModuleName $script:provModuleName Connect-IPPSSession -Times 1 -Exactly
        Should -Invoke -ModuleName $script:provModuleName New-ManagementRoleAssignment -Times 2 -Exactly -ParameterFilter {
            $Role -eq 'View-Only Configuration'
        }
    }

    It 'Should record a failed grant without throwing when every mechanism fails for an entry' {
        Mock -ModuleName $script:provModuleName New-ManagementRoleAssignment { throw 'boom' }

        $result = Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -Confirm:$false

        $result.FailedGrants.RoleGroup | Should -Contain 'View-Only Configuration'
        $result.RoleGroupsGranted | Should -Contain 'Security Reader'
    }

    It 'Should always disconnect from Exchange Online, even on failure' {
        Mock -ModuleName $script:provModuleName Get-ServicePrincipal { $null }

        # No existing service principal and no -ServicePrincipalObjectId is an
        # unrecoverable error raised after the connection is established.
        { Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
                -Modules 'ThreatProtection' -Confirm:$false
        } | Should -Throw

        Should -Invoke -ModuleName $script:provModuleName Disconnect-ExchangeOnline -Times 1 -Exactly
    }

    It 'Should not connect to Exchange Online under -WhatIf' {
        Grant-ZTAssessExchangeOnlineRole -AppId $script:appId -Organization 'contoso.onmicrosoft.com' `
            -Modules 'ThreatProtection' -WhatIf

        Should -Invoke -ModuleName $script:provModuleName Connect-ExchangeOnline -Times 0 -Exactly
    }
}
