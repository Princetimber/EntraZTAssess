@{
    CheckId = 'CA-004'
    Domain = 'ConditionalAccess'
    Title = 'Risk-based access policies enforced'
    Description = 'Checks for enabled sign-in risk and user risk policies enforced through Conditional Access.'
    Rationale = 'Risk-based policies respond automatically to credential leaks and anomalous sign-ins, shrinking the attacker window without user friction.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P2'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Create Conditional Access policies requiring MFA on medium-and-above sign-in risk and secure password change on high user risk.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-risk'
    )
}
