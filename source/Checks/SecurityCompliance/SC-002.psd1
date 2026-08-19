@{
    CheckId = 'SC-002'
    Domain = 'SecurityCompliance'
    Title = 'Retention rules enforce a minimum retention duration'
    Description = 'Evaluates whether Microsoft Purview retention rules retain content for at least the consultancy-defined minimum duration, or indefinitely.'
    Rationale = 'A retention rule with too short a duration, or none at all, allows content subject to legal, regulatory, or investigative hold requirements to be lost before it is needed.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Purview retention policies (Microsoft 365 E3/E5 or standalone Compliance add-on)'
    PermissionDependency = @()
    DataSources = @(
        'retentionComplianceRules'
    )
    Remediation = 'Set every retention rule''s duration to at least the consultancy-defined minimum, or to Unlimited for content that must never expire.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/purview/create-retention-policies'
    )
}
