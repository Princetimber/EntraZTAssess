@{
    CheckId = 'PA-008'
    Domain = 'PrivilegedAccess'
    Title = 'No guests in privileged roles'
    Description = 'Verifies no guest (external) account holds any privileged directory role.'
    Rationale = 'A privileged guest places tenant control in an identity governed by another organisations security posture and lifecycle.'
    DefaultSeverity = 'Critical'
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
        'users'
    )
    Remediation = 'Remove privileged roles from guest accounts immediately; where external administration is required, use governed B2B with dedicated cloud-only accounts.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/external-id/b2b-fundamentals'
    )
}
