@{
    CheckId = 'EM-006'
    Domain = 'EndpointManagement'
    Title = 'Co-management cloud signal'
    Description = 'Reviews the management agent distribution and flags devices managed by Configuration Manager only, without an Intune co-management signal.'
    Rationale = 'ConfigMgr-only devices provide no cloud compliance signal, so they cannot satisfy device-based Conditional Access.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune/ConfigMgr'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'managedDevices'
    )
    Remediation = 'Enable co-management and shift the compliance workload to Intune so all Windows devices emit cloud compliance signals.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/intune/configmgr/comanage/overview'
    )
}
