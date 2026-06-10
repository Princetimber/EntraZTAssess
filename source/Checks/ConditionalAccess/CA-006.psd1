@{
    CheckId = 'CA-006'
    Domain = 'ConditionalAccess'
    Title = 'Session controls deployed'
    Description = 'Assesses use of session controls: sign-in frequency for privileged access and persistent browser restrictions for unmanaged devices.'
    Rationale = 'Session controls limit token replay value and reduce data persistence on unmanaged endpoints - key assume-breach mitigations.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Apply sign-in frequency to administrator sessions and never-persistent browser sessions on unmanaged devices.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-session-lifetime'
    )
}
