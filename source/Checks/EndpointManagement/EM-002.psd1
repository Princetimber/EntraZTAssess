@{
    CheckId = 'EM-002'
    Domain = 'EndpointManagement'
    Title = 'Disk encryption coverage'
    Description = 'Measures the percentage of corporate Windows and macOS managed devices reporting encrypted storage against the threshold (default 90 per cent).'
    Rationale = 'Unencrypted endpoints turn every lost or stolen laptop into a data breach.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
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
    Remediation = 'Enforce BitLocker (Windows) and FileVault (macOS) through endpoint security disk encryption policy and remediate unencrypted devices.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices'
    )
}
