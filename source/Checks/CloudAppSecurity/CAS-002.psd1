@{
    CheckId = 'CAS-002'
    Domain = 'CloudAppSecurity'
    Title = 'Cloud App Security secure score controls are not silently ignored'
    Description = 'Evaluates whether the Cloud App Security-relevant Microsoft Secure Score controls have been left in an Ignored state without any recorded review.'
    Rationale = 'A control marked Ignored without review may reflect a considered risk-acceptance decision, or may simply have been dismissed and forgotten; the latter is a governance gap the consultant should surface.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Microsoft Defender for Cloud Apps'
    PermissionDependency = @(
        'SecurityEvents.Read.All'
    )
    DataSources = @(
        'secureScoreControlProfiles'
    )
    Remediation = 'For every Cloud App Security-relevant control marked Ignored, confirm the decision was deliberate and documented, or re-enable it for scoring.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score'
    )
}
