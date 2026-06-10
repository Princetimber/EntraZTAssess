@{
    CheckId = 'PA-009'
    Domain = 'PrivilegedAccess'
    Title = 'Service principals with privileged access'
    Description = 'Enumerates service principals holding privileged directory roles or GA-equivalent application permissions such as RoleManagement.ReadWrite.Directory.'
    Rationale = 'Workload identities with Tier-0 privilege are a favoured persistence mechanism: they have no MFA, no sign-in friction, and rarely any owner watching them.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'RoleManagement.Read.Directory'
        'Application.Read.All'
    )
    DataSources = @(
        'roleAssignments'
        'servicePrincipals'
    )
    Remediation = 'Inventory each privileged workload identity, remove unneeded privilege, and protect the remainder with credential hygiene and monitoring.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'
    )
}
