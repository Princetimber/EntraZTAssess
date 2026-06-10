@{
    CheckId = 'ID-005'
    Domain = 'IdentitySecurity'
    Title = 'Weak telephony methods restricted'
    Description = 'Checks whether SMS and voice call authentication methods are disabled or restricted, particularly for privileged users.'
    Rationale = 'Telephony methods are vulnerable to SIM swapping and social engineering and should not protect privileged access.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'authenticationMethodsPolicy'
    )
    Remediation = 'Restrict SMS and voice methods to targeted exception groups and move users to Microsoft Authenticator, passkeys, or Windows Hello for Business.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods'
    )
}
