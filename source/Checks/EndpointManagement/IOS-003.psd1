@{
    CheckId = 'IOS-003'
    Domain = 'EndpointManagement'
    Title = 'Corporate iOS supervised'
    Description = 'Measures the share of corporate iOS/iPadOS devices that are supervised (threshold 80 per cent).'
    Rationale = 'Unsupervised corporate iOS devices cannot receive many security-relevant restrictions; supervision is the corporate control plane for Apple mobile devices.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'managedDevices'
    )
    Remediation = 'Enrol corporate iOS devices through Automated Device Enrolment so they are supervised; existing devices require a reset to supervise.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/device-enrollment-program-enroll-ios'
    )
}
