@{
    CheckId = 'AND-002'
    Domain = 'EndpointManagement'
    Title = 'No legacy Android device administrator enrolments'
    Description = 'Detects Android devices enrolled through the deprecated device administrator channel rather than Android Enterprise.'
    Rationale = 'Device administrator management is deprecated by Google and loses capability with each Android release; it cannot enforce modern work-profile separation.'
    DefaultSeverity = 'High'
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
    Remediation = 'Re-enrol device administrator Android devices into the appropriate Android Enterprise profile and block new DA enrolments.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/android-move-device-admin-work-profile'
    )
}
