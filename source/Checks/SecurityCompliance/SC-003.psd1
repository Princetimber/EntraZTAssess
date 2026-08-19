@{
    CheckId = 'SC-003'
    Domain = 'SecurityCompliance'
    Title = 'Records-declaring compliance tags are published'
    Description = 'Evaluates whether at least one Microsoft Purview compliance tag (retention label) is configured as a record label, enabling immutable records declaration.'
    Rationale = 'Records management depends on labels that lock content against further edits or deletion; without a record label, "retention" is advisory rather than enforced.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Purview records management (Microsoft 365 E5 or standalone add-on)'
    PermissionDependency = @()
    DataSources = @(
        'complianceTags'
    )
    Remediation = 'Publish at least one compliance tag configured as a record label for content that must be declared a record, and apply it via a label policy or auto-labeling rule.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/purview/records-management'
    )
}
