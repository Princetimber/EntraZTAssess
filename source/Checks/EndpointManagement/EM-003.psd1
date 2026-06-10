@{
    CheckId = 'EM-003'
    Domain = 'EndpointManagement'
    Title = 'Defender for Endpoint connector enabled'
    Description = 'Verifies the Microsoft Defender for Endpoint connector is enabled so device risk signals flow into compliance.'
    Rationale = 'Without the MDE connector, device risk plays no part in compliance or Conditional Access - assume-breach telemetry is disconnected from access decisions.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'AssumeBreach'
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune and Defender for Endpoint'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'mtdConnectors'
    )
    Remediation = 'Enable the Microsoft Defender for Endpoint connector and require machine risk score in compliance policy.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/advanced-threat-protection-configure'
    )
}
