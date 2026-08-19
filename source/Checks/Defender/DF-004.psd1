@{
    CheckId = 'DF-004'
    Domain = 'Defender'
    Title = 'Secure Score improvement opportunities (informational)'
    Description = 'Summarises the highest-ranked unimplemented Microsoft Secure Score controls as informational telemetry for the consultant.'
    Rationale = 'Highlights the next most impactful configuration changes without asserting pass/fail against a specific check.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = ''
    PermissionDependency = @(
        'SecurityEvents.Read.All'
    )
    DataSources = @(
        'secureScoreLatest'
        'secureScoreControlProfiles'
    )
    Remediation = 'No remediation; informational evidence for the assessment report.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score'
    )
}
