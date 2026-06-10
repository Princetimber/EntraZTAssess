@{
    CheckId = 'PA-006'
    Domain = 'PrivilegedAccess'
    Title = 'No stale privileged assignments'
    Description = 'Flags privileged role holders with no sign-in activity within the staleness window (default 90 days).'
    Rationale = 'Dormant privileged accounts are unsupervised attack surface - nobody notices when a forgotten admin account starts being used.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'Entra ID P1 for sign-in activity'
    PermissionDependency = @(
        'RoleManagement.Read.Directory'
        'Directory.Read.All'
        'AuditLog.Read.All'
    )
    DataSources = @(
        'roleAssignments'
        'users'
    )
    Remediation = 'Remove or disable stale privileged assignments and institute periodic access reviews for all roles.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/access-reviews-overview'
    )
}
