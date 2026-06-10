@{
    CheckId = 'IOS-002'
    Domain = 'EndpointManagement'
    Title = 'Automated Device Enrolment token validity'
    Description = 'Verifies an Apple Business Manager ADE token is configured and not approaching expiry when corporate Apple devices are managed.'
    Rationale = 'Without a valid ADE token, corporate Apple devices cannot be supervised or zero-touch enrolled, weakening corporate control of Apple hardware.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune and Apple Business Manager'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'depOnboardingSettings'
        'managedDevices'
    )
    Remediation = 'Configure or renew the ADE token from Apple Business Manager and enrol corporate Apple hardware through it.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/device-enrollment-program-enroll-ios'
    )
}
