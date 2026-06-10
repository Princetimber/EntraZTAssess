@{
    CheckId = 'CG-001'
    Domain = 'CorporateDeviceGovernance'
    Title = 'Corporate device control coverage'
    Description = 'Measures corporate managed devices against the core control set: compliant state and encrypted storage (threshold 90 per cent).'
    Rationale = 'Corporate devices are the organisations own attack surface; anything below near-total control coverage on owned hardware is unmanaged risk by choice.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'managedDevices'
    )
    Remediation = 'Remediate non-compliant and unencrypted corporate devices and investigate devices that persistently fail to apply policy.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started'
    )
}
