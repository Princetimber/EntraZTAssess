@{
    CheckId = 'CA-005'
    Domain = 'ConditionalAccess'
    Title = 'Device-based access controls'
    Description = 'Verifies at least one enabled policy requires a compliant or hybrid-joined device for broad user access to corporate resources.'
    Rationale = 'Device trust signals are central to Zero Trust; without device conditions, fully unmanaged endpoints access corporate data unchecked.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Entra ID P1 and Intune'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Deploy policies requiring compliant devices for broad access, with app protection policies as the BYOD alternative grant.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device'
    )
}
