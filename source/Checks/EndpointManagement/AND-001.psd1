@{
    CheckId = 'AND-001'
    Domain = 'EndpointManagement'
    Title = 'Android Enterprise binding'
    Description = 'Verifies the tenant is bound to Android Enterprise (managed Google Play) when Android devices are enrolled.'
    Rationale = 'Without the Android Enterprise binding, Android management falls back to deprecated device administrator techniques with materially weaker controls.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'androidEnterpriseSettings'
        'managedDevices'
    )
    Remediation = 'Bind the tenant to managed Google Play and migrate Android enrolment to Android Enterprise profiles.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/connect-intune-android-enterprise'
    )
}
