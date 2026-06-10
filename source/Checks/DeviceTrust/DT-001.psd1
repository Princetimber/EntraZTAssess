@{
    CheckId = 'DT-001'
    Domain = 'DeviceTrust'
    Title = 'Unknown and unmanaged device exposure'
    Description = 'Classifies every device (corporate, BYOD, shared, kiosk, PAW, unknown) and measures the share of active devices that are unknown or unmanaged.'
    Rationale = 'Unmanaged endpoints carry no compliance signal and no endpoint protection; a large unmanaged share means Conditional Access device controls protect only part of the estate.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
        'Directory.Read.All'
    )
    DataSources = @(
        'managedDevices'
        'entraDevices'
    )
    Remediation = 'Enrol or register unknown devices, retire stale device objects, and require device signals through Conditional Access so unmanaged access is the exception.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/fundamentals/deployment-guide-enrollment'
    )
}
