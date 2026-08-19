@{
    CheckId = 'CO-004'
    Domain = 'Collaboration'
    Title = 'External collaboration configuration inventory (informational)'
    Description = 'Summarises the count of Exchange sharing policies and mail-flow rules that redirect or blind-copy messages, as informational telemetry for the consultant.'
    Rationale = 'Grounds the external-collaboration narrative in the tenant''s actual Exchange sharing and mail-flow configuration inventory.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = ''
    PermissionDependency = @()
    DataSources = @(
        'sharingPolicies'
        'transportRules'
    )
    Remediation = 'No remediation; informational evidence for the assessment report.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/exchange/sharing/sharing-policies/sharing-policies'
    )
}
