@{
    CheckId = 'MAC-002'
    Domain = 'EndpointManagement'
    Title = 'FileVault enforced on macOS'
    Description = 'Verifies a macOS compliance or configuration policy enforces FileVault disk encryption, with estate encryption percentage as evidence.'
    Rationale = 'An unencrypted Mac is a portable copy of corporate data; FileVault with escrowed recovery keys is the baseline.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'compliancePolicies'
        'managedDevices'
    )
    Remediation = 'Enforce FileVault via endpoint security disk encryption policy with recovery keys escrowed to Intune.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices-filevault'
    )
}
