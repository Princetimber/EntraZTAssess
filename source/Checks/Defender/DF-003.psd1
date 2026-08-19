@{
    CheckId = 'DF-003'
    Domain = 'Defender'
    Title = 'High-severity alerts triaged within SLA'
    Description = 'Checks whether open, high-severity unified security alerts are being triaged within the consultancy-defined age threshold.'
    Rationale = 'Untriaged high-severity alerts represent active, unaddressed detections; an assume-breach posture requires timely triage.'
    DefaultSeverity = 'High'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = ''
    PermissionDependency = @(
        'SecurityAlert.Read.All'
    )
    DataSources = @(
        'unifiedAlerts'
    )
    Remediation = 'Triage and close open high-severity alerts in the Microsoft Defender portal within the engagement''s target SLA, and review the alert queue''s staffing or automation if the backlog recurs.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/microsoft-365/security/defender/incidents-overview'
    )
}
