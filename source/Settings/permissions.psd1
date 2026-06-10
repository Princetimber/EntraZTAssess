@{
    # ==========================================================================
    # EntraZTAssess assessment module catalogue.
    #
    # Maps each assessment module to the least-privilege Microsoft Graph
    # scopes it requires. Connect-ZTAssessment computes the union of scopes
    # for the selected modules only. All scopes are read-only.
    #
    # AlwaysIncluded modules are added to every connection regardless of
    # selection. Optional modules are excluded unless explicitly requested.
    # ==========================================================================

    Modules = @{
        Core = @{
            Description    = 'Tenant metadata, licence SKUs, users, groups, and devices baseline.'
            Scopes         = @(
                'Organization.Read.All'
                'Directory.Read.All'
            )
            AlwaysIncluded = $true
            Optional       = $false
        }

        Identity = @{
            Description    = 'Identity security: MFA coverage, authentication methods, passwordless readiness, legacy authentication, break-glass accounts.'
            Scopes         = @(
                'UserAuthenticationMethod.Read.All'
                'Reports.Read.All'
                'Policy.Read.All'
                'AuditLog.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        ConditionalAccess = @{
            Description    = 'Conditional Access policies, named locations, authentication strengths, and coverage analysis.'
            Scopes         = @(
                'Policy.Read.All'
                'Agreement.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        PrivilegedAccess = @{
            Description    = 'Directory roles, PIM eligible and active assignments, and role management policies.'
            Scopes         = @(
                'RoleManagement.Read.Directory'
                'RoleEligibilitySchedule.Read.Directory'
                'RoleAssignmentSchedule.Read.Directory'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        IdentityGovernance = @{
            Description    = 'Access reviews, entitlement management, lifecycle workflows, and guest governance.'
            Scopes         = @(
                'AccessReview.Read.All'
                'EntitlementManagement.Read.All'
                'LifecycleWorkflows.Read.All'
                'Policy.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        Applications = @{
            Description    = 'App registrations, service principals, OAuth permission grants, and consent settings.'
            Scopes         = @(
                'Application.Read.All'
                'Policy.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        HybridIdentity = @{
            Description    = 'Entra Connect synchronisation status, PHS/PTA/SSO feature flags, and provisioning errors.'
            Scopes         = @(
                'OnPremDirectorySynchronization.Read.All'
                'Directory.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        Devices = @{
            Description    = 'Intune managed devices, compliance policies, configuration profiles, baselines, app protection, enrolment configuration, and Autopilot.'
            Scopes         = @(
                'DeviceManagementConfiguration.Read.All'
                'DeviceManagementManagedDevices.Read.All'
                'DeviceManagementServiceConfig.Read.All'
                'DeviceManagementApps.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        Monitoring = @{
            Description    = 'Identity Protection risk data, audit log availability, and Defender for Identity sensor health.'
            Scopes         = @(
                'IdentityRiskEvent.Read.All'
                'IdentityRiskyUser.Read.All'
                'AuditLog.Read.All'
                'SecurityIdentitiesSensors.Read.All'
            )
            AlwaysIncluded = $false
            Optional       = $false
        }

        Sentinel = @{
            Description    = 'Microsoft Sentinel data connector assessment via Azure Resource Manager. Requires Az.Accounts and Azure Reader role; no Graph scopes.'
            Scopes         = @()
            AlwaysIncluded = $false
            Optional       = $true
        }
    }
}
