@{
    CheckId = 'MD-006'
    Domain = 'MonitoringDetection'
    Title = 'Sign-in and risk telemetry summary'
    Description = 'Summarises legacy authentication volumes and risk detection counts as engagement evidence (informational).'
    Rationale = 'The telemetry summary grounds the narrative findings in observed tenant activity.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P1/P2 for the underlying data'
    PermissionDependency = @(
        'AuditLog.Read.All'
        'IdentityRiskEvent.Read.All'
    )
    DataSources = @(
        'legacyAuthSignIns'
        'riskDetectionsSummary'
    )
    Remediation = 'No remediation; informational evidence for the assessment report.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/id-protection/overview-identity-protection'
    )
}
