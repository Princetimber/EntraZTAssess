@{
    CheckId = 'EM-005'
    Domain = 'EndpointManagement'
    Title = 'Windows Autopilot readiness'
    Description = 'Verifies an Autopilot deployment profile exists and measures the share of corporate Windows devices registered to Autopilot.'
    Rationale = 'Autopilot ensures rebuilt and new devices land in a known-good, policy-managed state without manual imaging.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'autopilotDevices'
        'autopilotProfiles'
        'managedDevices'
    )
    Remediation = 'Register corporate Windows hardware with Autopilot and assign a deployment profile, ideally with hardware-vendor registration at purchase.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/windows-autopilot'
    )
}
