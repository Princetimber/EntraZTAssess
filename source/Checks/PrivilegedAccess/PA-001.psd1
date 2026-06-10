@{
    CheckId = 'PA-001'
    Domain = 'PrivilegedAccess'
    Title = 'Global Administrator count within bounds'
    Description = 'Verifies the number of Global Administrators is within the recommended range (default 2 to 5, including break-glass).'
    Rationale = 'Too few GAs risks lockout; too many multiplies the tenant-takeover attack surface beyond what governance can supervise.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'RoleManagement.Read.Directory'
        'Directory.Read.All'
    )
    DataSources = @(
        'roleAssignments'
        'roleDefinitions'
        'users'
    )
    Remediation = 'Reduce Global Administrator membership to a governed core, delegating duties to least-privileged specific roles.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'
    )
}
