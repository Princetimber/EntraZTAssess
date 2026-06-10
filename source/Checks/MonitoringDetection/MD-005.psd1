@{
    CheckId = 'MD-005'
    Domain = 'MonitoringDetection'
    Title = 'SIEM integration for identity signals'
    Description = 'Checks whether Entra ID and endpoint signals flow into Microsoft Sentinel or an equivalent SIEM (optional module; manual verification by default).'
    Rationale = 'Detection happens where the signals are; identity logs that reach no SIEM generate no alerts.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Sentinel'
    PermissionDependency = @()
    DataSources = @()
    Remediation = 'Connect the Entra ID, Identity Protection, and Defender connectors to Microsoft Sentinel (or the in-use SIEM) and confirm analytics rules cover identity attack paths.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/azure/sentinel/data-connectors-reference'
    )
}
