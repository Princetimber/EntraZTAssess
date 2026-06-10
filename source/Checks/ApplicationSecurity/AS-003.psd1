@{
    CheckId = 'AS-003'
    Domain = 'ApplicationSecurity'
    Title = 'Application credential hygiene'
    Description = 'Reviews app registration credentials for excessive validity, expired leftovers, and client secrets on highly privileged apps.'
    Rationale = 'Long-lived secrets are durable attacker capital; a leaked two-year secret on a privileged app is a two-year breach window.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Application.Read.All'
    )
    DataSources = @(
        'applications'
        'graphAppRoleAssignments'
    )
    Remediation = 'Replace client secrets with certificates or managed identities on privileged apps, cap credential validity, and remove expired credentials.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/enterprise-apps/certificate-credentials'
    )
}
