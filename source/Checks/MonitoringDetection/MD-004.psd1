@{
    CheckId = 'MD-004'
    Domain = 'MonitoringDetection'
    Title = 'Defender for Identity sensor health'
    Description = 'Verifies Defender for Identity sensors are deployed and healthy on domain controllers in hybrid tenants.'
    Rationale = 'On-premises AD is the assumed-breach blind spot of cloud monitoring; MDI sensors are the detection coverage for it.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Defender for Identity'
    PermissionDependency = @(
        'SecurityIdentitiesSensors.Read.All'
    )
    DataSources = @(
        'mdiSensors'
        'organization'
    )
    Remediation = 'Deploy Defender for Identity sensors to every domain controller and remediate unhealthy sensors.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/defender-for-identity/deploy/deploy-defender-identity'
    )
}
