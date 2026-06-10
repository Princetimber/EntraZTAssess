@{
    CheckId = 'ID-009'
    Domain = 'IdentitySecurity'
    Title = 'Break-glass accounts configured'
    Description = 'Verifies at least two cloud-only emergency access accounts exist, excluded from Conditional Access, holding Global Administrator, protected with phishing-resistant credentials.'
    Rationale = 'Without emergency access accounts, a misconfigured Conditional Access policy or federation outage can lock all administrators out of the tenant permanently.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Directory.Read.All'
        'Policy.Read.All'
        'RoleManagement.Read.Directory'
    )
    DataSources = @(
        'users'
        'conditionalAccessPolicies'
        'roleAssignments'
    )
    Remediation = 'Create two cloud-only break-glass accounts with FIDO2 credentials, exclude them from all Conditional Access policies, and alert on every sign-in.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'
    )
}
