@{
    CheckId = 'CA-012'
    Domain = 'ConditionalAccess'
    Title = 'High-risk authentication flows blocked'
    Description = 'Checks whether device code flow and other high-risk authentication flows are restricted by policy.'
    Rationale = 'Device code phishing is a prevalent real-world technique for stealing tokens without touching passwords or MFA.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Create a policy blocking device code flow except for audited exception groups that require it.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows'
    )
}
