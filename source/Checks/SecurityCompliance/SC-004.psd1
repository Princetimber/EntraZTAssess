@{
    CheckId = 'SC-004'
    Domain = 'SecurityCompliance'
    Title = 'Retention and records-management inventory (informational)'
    Description = 'Summarises the count of retention policies, retention rules, and compliance tags as informational telemetry for the consultant.'
    Rationale = 'Grounds the records-management narrative in the tenant''s actual Purview configuration inventory.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = ''
    PermissionDependency = @()
    DataSources = @(
        'retentionCompliancePolicies'
        'retentionComplianceRules'
        'complianceTags'
    )
    Remediation = 'No remediation; informational evidence for the assessment report.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/purview/create-retention-policies'
    )
}
