@{
    CheckId = 'HY-005'
    Domain = 'HybridIdentity'
    Title = 'Device and group writeback posture'
    Description = 'Records the device and group writeback configuration (manual verification; not reliably exposed via Graph).'
    Rationale = 'Writeback features extend cloud objects into on-premises AD; undocumented writeback is hidden coupling between the two directories.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @()
    DataSources = @(
        'onPremisesSynchronization'
    )
    Remediation = 'Document whether device and group writeback are intended, and disable whichever is enabled without a consumer.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-group-writeback-v2'
    )
}
