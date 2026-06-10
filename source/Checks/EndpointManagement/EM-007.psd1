@{
    CheckId = 'EM-007'
    Domain = 'EndpointManagement'
    Title = 'Managed device check-in hygiene'
    Description = 'Measures the share of managed devices that have not checked in within the staleness window (default 90 days).'
    Rationale = 'Stale device records distort coverage metrics and may retain access tokens and company data on lost or retired hardware.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'managedDevices'
    )
    Remediation = 'Implement a device clean-up rule and retire devices beyond the staleness window.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/remote-actions/devices-wipe'
    )
}
