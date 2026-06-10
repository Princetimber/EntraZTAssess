@{
    CheckId = 'AS-001'
    Domain = 'ApplicationSecurity'
    Title = 'User consent restricted'
    Description = 'Verifies users cannot grant applications access to corporate data unsupervised, and whether the admin consent workflow is enabled.'
    Rationale = 'Illicit consent grants are a top OAuth attack: one phished user consents and the attacker holds durable API access with no password to steal.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'authorizationPolicy'
        'adminConsentRequestPolicy'
    )
    Remediation = 'Disable unrestricted user consent (allow verified-publisher low-impact consent at most) and enable the admin consent request workflow.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent'
    )
}
