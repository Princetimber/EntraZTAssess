@{
    CheckId = 'BG-004'
    Domain = 'ByodGovernance'
    Title = 'BYOD and corporate devices treated differently'
    Description = 'Checks that BYOD and corporate devices receive differentiated policy treatment rather than identical (or absent) controls.'
    Rationale = 'Identical treatment means either BYOD is over-managed (privacy risk) or corporate is under-managed (control gap); differentiation is the sign of a deliberate ownership model.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementApps.Read.All'
        'DeviceManagementServiceConfig.Read.All'
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'appProtectionPolicies'
        'enrollmentConfigurations'
        'managedDevices'
    )
    Remediation = 'Define the ownership model: corporate devices receive full management and baselines; personal devices receive MAM and restricted enrolment.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/fundamentals/byod-technology-decisions'
    )
}
