@{
    CheckId = 'AND-003'
    Domain = 'EndpointManagement'
    Title = 'Personal Android protected by app protection'
    Description = 'Verifies an Android app protection (MAM) policy exists when personally owned Android devices access corporate data.'
    Rationale = 'A personal work-profile device without MAM has no data-egress controls on corporate apps.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementApps.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'appProtectionPolicies'
        'managedDevices'
    )
    Remediation = 'Deploy an Android app protection policy covering corporate apps for all personally owned devices.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/apps/app-protection-policy'
    )
}
