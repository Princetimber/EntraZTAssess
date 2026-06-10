@{
    CheckId = 'AS-004'
    Domain = 'ApplicationSecurity'
    Title = 'Unused service principals with access'
    Description = 'Flags enabled service principals holding permissions with no sign-in activity within the staleness window.'
    Rationale = 'A dormant workload identity with live permissions is pure attack surface: nobody is watching it and nothing breaks if an attacker starts using it.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra workload identities licence for sign-in data'
    PermissionDependency = @(
        'Application.Read.All'
        'Reports.Read.All'
    )
    DataSources = @(
        'servicePrincipals'
        'spSignInActivities'
        'graphAppRoleAssignments'
    )
    Remediation = 'Disable or remove service principals with no observed sign-in activity, after confirming with their owners.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/enterprise-apps/recover-deleted-apps'
    )
}
