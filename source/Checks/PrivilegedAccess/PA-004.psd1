@{
    CheckId = 'PA-004'
    Domain = 'PrivilegedAccess'
    Title = 'Privileged accounts are cloud-only'
    Description = 'Verifies no synchronised (on-premises sourced) account holds a privileged directory role.'
    Rationale = 'On-premises compromise must not escalate to cloud compromise; synchronised admin accounts collapse that security boundary entirely.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'AssumeBreach'
        'LeastPrivilege'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'RoleManagement.Read.Directory'
        'Directory.Read.All'
    )
    DataSources = @(
        'roleAssignments'
        'users'
    )
    Remediation = 'Replace synchronised privileged accounts with cloud-only equivalents and remove roles from synchronised identities.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'
    )
}
