@{
    CheckId = 'ID-006'
    Domain = 'IdentitySecurity'
    Title = 'FIDO2/passkey enablement and adoption'
    Description = 'Checks that FIDO2 security keys or passkeys are enabled in the authentication methods policy and reports adoption, with emphasis on privileged users.'
    Rationale = 'Phishing-resistant credentials remove the credential-theft attack class entirely; enablement is the prerequisite for adoption.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
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
    Remediation = 'Enable the FIDO2/passkey authentication method and run a phased adoption programme starting with privileged users.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-passwordless-passkeys'
    )
}
