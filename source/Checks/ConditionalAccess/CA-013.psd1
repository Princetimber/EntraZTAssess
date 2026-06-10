@{
    CheckId = 'CA-013'
    Domain = 'ConditionalAccess'
    Title = 'Guest access protected by MFA'
    Description = 'Verifies guest and external users are required to satisfy MFA through an enabled policy.'
    Rationale = 'Guests authenticate from tenants whose security posture is unknown; your policies are the only enforceable control.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Deploy a policy requiring MFA for all guest and external user types, with cross-tenant trust settings reviewed deliberately.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-policy-guests-mfa'
    )
}
