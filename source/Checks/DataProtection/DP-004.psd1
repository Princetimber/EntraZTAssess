@{
    CheckId = 'DP-004'
    Domain = 'DataProtection'
    Title = 'Data protection configuration inventory (informational)'
    Description = 'Summarises the count of DLP policies, DLP rules, sensitivity labels, and label policies as informational telemetry for the consultant.'
    Rationale = 'Grounds the data-protection narrative in the tenant''s actual Purview configuration inventory.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = ''
    PermissionDependency = @()
    DataSources = @(
        'dlpCompliancePolicies'
        'dlpComplianceRules'
        'sensitivityLabels'
        'labelPolicies'
    )
    Remediation = 'No remediation; informational evidence for the assessment report.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/purview/dlp-create-deploy-policy'
    )
}
