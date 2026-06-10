@{
    CheckId = 'HY-002'
    Domain = 'HybridIdentity'
    Title = 'Directory synchronisation freshness'
    Description = 'Verifies the last directory synchronisation completed within the expected window (warn 2 hours, fail 24 hours).'
    Rationale = 'A stalled sync engine means joiners, leavers, and password changes silently stop flowing to the cloud.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Directory.Read.All'
    )
    DataSources = @(
        'organization'
    )
    Remediation = 'Investigate the Entra Connect server and scheduler; restore synchronisation and alert on future staleness.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler'
    )
}
