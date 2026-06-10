@{
    CheckId = 'HY-003'
    Domain = 'HybridIdentity'
    Title = 'Provisioning and synchronisation errors'
    Description = 'Measures objects with on-premises provisioning errors against the synchronised population.'
    Rationale = 'Sync errors are objects in limbo: attribute clashes and quarantined objects accumulate into authentication and licensing faults.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Directory.Read.All'
    )
    DataSources = @(
        'provisioningErrorsSummary'
    )
    Remediation = 'Resolve duplicate attribute and quarantine errors at source in on-premises AD, then re-run synchronisation.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-sync-errors'
    )
}
