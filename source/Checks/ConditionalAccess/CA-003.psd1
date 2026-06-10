@{
    CheckId = 'CA-003'
    Domain = 'ConditionalAccess'
    Title = 'Legacy authentication block policy'
    Description = 'Verifies an enabled Conditional Access policy blocks legacy authentication client apps for all users.'
    Rationale = 'This is the policy-side control underpinning ID-003; without it legacy protocols bypass every other Conditional Access control.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
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
    Remediation = 'Create a block policy for Exchange ActiveSync and other legacy clients targeting all users.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy'
    )
}
