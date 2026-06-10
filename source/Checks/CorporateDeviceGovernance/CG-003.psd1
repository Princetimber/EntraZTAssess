@{
    CheckId = 'CG-003'
    Domain = 'CorporateDeviceGovernance'
    Title = 'Modern corporate provisioning'
    Description = 'Measures the share of corporate devices provisioned through modern channels: Autopilot (Windows), ADE (Apple), and Android Enterprise corporate profiles (threshold 50 per cent).'
    Rationale = 'Modern provisioning guarantees corporate devices start from a known-good state and cannot silently leave management.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'managedDevices'
        'autopilotDevices'
        'depOnboardingSettings'
        'androidEnterpriseSettings'
    )
    Remediation = 'Adopt Autopilot, ADE, and Android Enterprise corporate enrolment for all new corporate hardware, registering devices at purchase.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/fundamentals/deployment-guide-enrollment'
    )
}
