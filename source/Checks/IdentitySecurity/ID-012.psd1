@{
    CheckId = 'ID-012'
    Domain = 'IdentitySecurity'
    Title = 'Self-service password reset enabled'
    Description = 'Checks that SSPR is enabled with at least two registration methods required.'
    Rationale = 'SSPR reduces helpdesk-mediated resets, which are a social-engineering target, and pairs with combined registration for MFA.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
        'Reports.Read.All'
    )
    DataSources = @(
        'authenticationMethodsPolicy'
        'userRegistrationDetails'
    )
    Remediation = 'Enable SSPR for all users with two methods required, using combined security information registration.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks'
    )
}
