@{
    CheckId = 'MD-003'
    Domain = 'MonitoringDetection'
    Title = 'Audit log availability and retention'
    Description = 'Confirms directory audit logs are available and that retention beyond the licence default is arranged (export verified manually).'
    Rationale = 'Incident response is bounded by log retention: default 30-day retention means any older intrusion is unreconstructable.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P1 for 30-day retention'
    PermissionDependency = @(
        'AuditLog.Read.All'
    )
    DataSources = @(
        'directoryAuditProbe'
    )
    Remediation = 'Export Entra ID audit and sign-in logs via diagnostic settings to Log Analytics, Sentinel, or storage with retention matching IR requirements.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/monitoring-health/howto-archive-logs-to-storage-account'
    )
}
