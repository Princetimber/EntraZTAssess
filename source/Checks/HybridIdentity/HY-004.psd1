@{
    CheckId = 'HY-004'
    Domain = 'HybridIdentity'
    Title = 'Seamless SSO computer account rollover'
    Description = 'Checks the AZUREADSSOACC computer account password rollover discipline (manual verification; not exposed via Graph).'
    Rationale = 'The Seamless SSO computer account key decrypts user Kerberos tickets; an unrotated key is a long-lived skeleton key for the tenant.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @()
    DataSources = @()
    Remediation = 'Roll the AZUREADSSOACC Kerberos decryption key at least every 30 days via the documented procedure, and record the cadence.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso-faq'
    )
}
