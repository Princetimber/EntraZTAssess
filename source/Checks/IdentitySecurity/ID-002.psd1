@{
    CheckId = 'ID-002'
    Domain = 'IdentitySecurity'
    Title = 'Privileged accounts MFA capable'
    Description = 'Verifies that every holder of a privileged directory role is registered and capable of MFA.'
    Rationale = 'A single privileged account without MFA provides a direct path to tenant compromise; coverage for administrators must be absolute.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'LeastPrivilege'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Reports.Read.All'
        'RoleManagement.Read.Directory'
    )
    DataSources = @(
        'userRegistrationDetails'
        'roleAssignments'
    )
    Remediation = 'Register all privileged accounts for phishing-resistant MFA immediately and enforce via a Conditional Access policy targeting directory roles.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths'
    )
}
