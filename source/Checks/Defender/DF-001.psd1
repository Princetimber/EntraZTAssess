@{
    CheckId = 'DF-001'
    Domain = 'Defender'
    Title = 'Microsoft Secure Score meets the maturity floor'
    Description = 'Evaluates whether the tenant''s current Microsoft Secure Score percentage meets the consultancy-defined maturity floor.'
    Rationale = 'Secure Score aggregates dozens of Defender/Entra configuration recommendations into a single comparable maturity signal; a low score indicates broad gaps across the Microsoft security stack.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = ''
    PermissionDependency = @(
        'SecurityEvents.Read.All'
    )
    DataSources = @(
        'secureScoreLatest'
    )
    Remediation = 'Review the Microsoft Secure Score recommendations in the Microsoft Defender portal and prioritise unimplemented controls by rank and impact.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score'
    )
}
