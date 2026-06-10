@{
    CheckId = 'BG-001'
    Domain = 'ByodGovernance'
    Title = 'BYOD access has data controls'
    Description = 'Verifies that platforms permitting personal devices enforce app protection policies and/or compliant-device Conditional Access; flags platforms with neither.'
    Rationale = 'BYOD with neither MAM nor device-based Conditional Access is an unmanaged data egress path - corporate data flows to devices the organisation cannot see or wipe.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Intune and Entra ID P1'
    PermissionDependency = @(
        'DeviceManagementApps.Read.All'
        'DeviceManagementServiceConfig.Read.All'
        'Policy.Read.All'
    )
    DataSources = @(
        'appProtectionPolicies'
        'enrollmentConfigurations'
        'conditionalAccessPolicies'
        'managedDevices'
    )
    Remediation = 'For every platform where personal devices are permitted, deploy app protection policies and require them (or compliant devices) through Conditional Access.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/apps/app-protection-policy'
    )
}
