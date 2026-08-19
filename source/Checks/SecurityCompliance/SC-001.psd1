@{
    CheckId = 'SC-001'
    Domain = 'SecurityCompliance'
    Title = 'Retention policies cover core workloads'
    Description = 'Evaluates whether at least one enabled Microsoft Purview retention policy covers Exchange mailboxes together with SharePoint or OneDrive content.'
    Rationale = 'Records-management and legal-hold obligations require retention to span the workloads where regulated content actually lives, not just email.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Purview retention policies (Microsoft 365 E3/E5 or standalone Compliance add-on)'
    PermissionDependency = @()
    DataSources = @(
        'retentionCompliancePolicies'
    )
    Remediation = 'Create or extend a retention policy so it covers Exchange mailboxes together with SharePoint and/or OneDrive content, and confirm it is enabled.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/purview/create-retention-policies'
    )
}
