@{
    CheckId = 'MAC-001'
    Domain = 'EndpointManagement'
    Title = 'Corporate macOS via Automated Device Enrolment'
    Description = 'Verifies corporate macOS devices are enrolled through ABM Automated Device Enrolment.'
    Rationale = 'ADE-enrolled Macs are supervised and non-removable from management; manually enrolled corporate Macs can simply be unenrolled by the user.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune and Apple Business Manager'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'depOnboardingSettings'
        'managedDevices'
    )
    Remediation = 'Add corporate Macs to Apple Business Manager and enrol via Automated Device Enrolment.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/device-enrollment-program-enroll-macos'
    )
}
