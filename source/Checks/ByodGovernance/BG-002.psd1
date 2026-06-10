@{
    CheckId = 'BG-002'
    Domain = 'ByodGovernance'
    Title = 'App protection coverage of personal estate'
    Description = 'Measures app protection (MAM) policy presence per platform against the platforms where personally owned devices are actually enrolled.'
    Rationale = 'MAM is the BYOD control plane: selective wipe, copy/paste restrictions, and save-as controls only exist where a policy targets the platform.'
    DefaultSeverity = 'High'
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
    Remediation = 'Deploy app protection policies for every platform with personal devices and verify assignment to the user population.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/apps/app-protection-policies'
    )
}
