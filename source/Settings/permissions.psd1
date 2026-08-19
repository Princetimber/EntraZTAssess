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

        Defender = @{
            Description    = 'Microsoft Secure Score coverage, unified security alert triage signals, and a Defender for Endpoint device-onboarding proxy via secure score controls.'
            Scopes         = @(
                'SecurityEvents.Read.All'
                'SecurityAlert.Read.All'
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

        # ----------------------------------------------------------------------
        # The four modules below have no Graph scopes: their data does not
        # exist in Microsoft Graph and is read exclusively through the
        # read-only Exchange Online / Security & Compliance (IPPS) surface
        # (Connect-ExchangeOnlineWrapper, Invoke-ZTAssessExoRequestWrapper).
        # ExchangeOnlineRoles are provisioning guidance only (surfaced by
        # Get-ZTAssessExchangeOnlineRoleGuidance) - this toolkit never grants
        # them; a tenant's own Exchange administrator must assign them.
        # Checks/collectors/assessors for these modules ship in later phases;
        # this catalogue entry only establishes the connection requirement.
        # ----------------------------------------------------------------------

        SecurityCompliance = @{
            Description            = 'Retention policies/rules and compliance tags (Microsoft Purview records-management and audit governance posture).'
            Scopes                 = @()
            ExchangeOnlineRoles    = @('View-Only Retention Management', 'View-Only Configuration')
            RequiresExchangeOnline = $true
            AlwaysIncluded         = $false
            Optional               = $false
        }

        Collaboration = @{
            Description            = 'Exchange sharing policies and transport/mail-flow rules governing external collaboration.'
            Scopes                 = @()
            ExchangeOnlineRoles    = @('View-Only Recipients', 'View-Only Configuration')
            RequiresExchangeOnline = $true
            AlwaysIncluded         = $false
            Optional               = $false
        }

        DataProtection = @{
            Description            = 'DLP policies/rules and sensitivity label policies (Microsoft Purview data classification and leak-prevention posture).'
            Scopes                 = @()
            ExchangeOnlineRoles    = @('View-Only DLP Compliance Management', 'View-Only Configuration')
            RequiresExchangeOnline = $true
            AlwaysIncluded         = $false
            Optional               = $false
        }

        ThreatProtection = @{
            Description            = 'Safe Links, Safe Attachments, anti-phishing, and hosted content filter policies (Defender for Office 365).'
            Scopes                 = @()
            ExchangeOnlineRoles    = @('Security Reader', 'View-Only Configuration')
            RequiresExchangeOnline = $true
            AlwaysIncluded         = $false
            Optional               = $false
        }
    }
}
