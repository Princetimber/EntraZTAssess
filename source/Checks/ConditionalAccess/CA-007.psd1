@{
    CheckId = 'CA-007'
    Domain = 'ConditionalAccess'
    Title = 'Named locations and trusted-location reliance'
    Description = 'Reviews named locations and flags policies that bypass MFA solely on the basis of a trusted network location.'
    Rationale = 'Network location is a weak, spoofable signal; location-based MFA bypass recreates the perimeter model Zero Trust replaces.'
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
        'namedLocations'
        'conditionalAccessPolicies'
    )
    Remediation = 'Remove location-only MFA bypasses and use locations solely as additional risk signals or block conditions.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/concept-assignment-network'
    )
}
