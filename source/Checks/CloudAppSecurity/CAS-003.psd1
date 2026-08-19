@{
    CheckId = 'CAS-003'
    Domain = 'CloudAppSecurity'
    Title = 'Cloud App Security coverage summary (informational, partial coverage by design)'
    Description = 'Summarises the Cloud App Security-relevant secure score controls found and their status. This domain is a best-effort Microsoft Graph secure-score proxy, not a full Defender for Cloud Apps configuration assessment; Microsoft Graph exposes no API for MCAS policies, app catalogue risk scores, or OAuth app governance.'
    Rationale = 'Sets accurate client expectations for the depth of Cloud App Security coverage in this assessment before the report is read.'
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
    Remediation = 'No remediation; informational evidence and coverage disclaimer for the assessment report. Recommend a dedicated Defender for Cloud Apps portal review to cover app risk scoring, OAuth app governance, and session policies.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/defender-cloud-apps/what-is-defender-for-cloud-apps'
    )
}
