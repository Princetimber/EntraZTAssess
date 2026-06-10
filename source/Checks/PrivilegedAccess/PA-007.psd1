@{
    CheckId = 'PA-007'
    Domain = 'PrivilegedAccess'
    Title = 'Role-assignable group hygiene'
    Description = 'Verifies directory roles are granted only to role-assignable groups, never to standard groups whose membership is broadly manageable.'
    Rationale = 'A role granted to an ordinary group lets any group owner mint administrators at will, silently bypassing privileged access governance.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
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
        'groups'
    )
    Remediation = 'Migrate role grants to role-assignable groups with PIM-governed membership.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept'
    )
}
