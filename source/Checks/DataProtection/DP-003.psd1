@{
    CheckId = 'DP-003'
    Domain = 'DataProtection'
    Title = 'Sensitivity labels are published for data classification'
    Description = 'Evaluates whether at least one sensitivity label exists and is published to users or services through a label policy, rather than only defined but never rolled out.'
    Rationale = 'A label that exists but is never published cannot be applied by users or auto-labeling, leaving content unclassified and unprotected regardless of the label''s configured encryption or marking.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Microsoft Purview Information Protection (Microsoft 365 E3/E5 or standalone add-on)'
    PermissionDependency = @()
    DataSources = @(
        'sensitivityLabels'
        'labelPolicies'
    )
    Remediation = 'Publish at least one sensitivity label to a user, group, or site scope via a label policy so it becomes available for manual or automatic labeling.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/purview/create-sensitivity-labels'
    )
}
