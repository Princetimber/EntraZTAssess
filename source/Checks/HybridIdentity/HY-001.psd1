@{
    CheckId = 'HY-001'
    Domain = 'HybridIdentity'
    Title = 'Password hash sync enabled'
    Description = 'Verifies password hash synchronisation is enabled (including alongside PTA or federation) for leaked-credential detection and sign-in resilience.'
    Rationale = 'PHS powers Entra ID leaked-credential detection and provides authentication fallback if on-premises infrastructure is down.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'OnPremDirectorySynchronization.Read.All'
    )
    DataSources = @(
        'onPremisesSynchronization'
        'organization'
    )
    Remediation = 'Enable password hash synchronisation in Entra Connect, even when PTA or federation remains the primary sign-in method.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs'
    )
}
