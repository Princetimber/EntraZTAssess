@{
    CheckId = 'AS-005'
    Domain = 'ApplicationSecurity'
    Title = 'Redirect URI hygiene'
    Description = 'Reviews app registration redirect URIs for wildcards, plain HTTP, and other token-leakage patterns.'
    Rationale = 'A wildcard or HTTP redirect URI lets an attacker receive the tokens your users sign in to obtain.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Application.Read.All'
    )
    DataSources = @(
        'applications'
    )
    Remediation = 'Replace wildcard and HTTP redirect URIs with exact HTTPS URIs; localhost exceptions only for native development apps.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity-platform/reply-url'
    )
}
