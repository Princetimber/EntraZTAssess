@{
    CheckId = 'IOS-004'
    Domain = 'EndpointManagement'
    Title = 'Personal iOS protected by app protection'
    Description = 'Verifies an iOS app protection (MAM) policy exists when personally owned iOS devices access corporate data.'
    Rationale = 'BYOD iOS without MAM has no corporate data separation; the user profile and corporate data are indistinguishable.'
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
    Remediation = 'Deploy an iOS app protection policy covering corporate apps for all personally owned devices.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/apps/app-protection-policy'
    )
}
