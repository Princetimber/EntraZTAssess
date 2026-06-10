@{
    CheckId = 'WIN-003'
    Domain = 'EndpointManagement'
    Title = 'BitLocker enforced on Windows'
    Description = 'Verifies BitLocker is enforced through compliance or endpoint security policy, with estate encryption percentage as evidence.'
    Rationale = 'BitLocker with escrowed recovery keys is the difference between a lost laptop and a reportable data breach.'
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
        'intents'
        'managedDevices'
    )
    Remediation = 'Enforce BitLocker via endpoint security disk encryption policy and require encryption in Windows compliance policy.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices'
    )
}
