@{
    CheckId = 'EM-001'
    Domain = 'EndpointManagement'
    Title = 'Windows security baseline deployed'
    Description = 'Verifies a security baseline (or equivalent hardening profile set) is deployed to the corporate Windows estate.'
    Rationale = 'Baselines codify hundreds of hardening settings; without one, Windows configuration depends on defaults and ad hoc profiles.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementConfiguration.Read.All'
    )
    DataSources = @(
        'intents'
        'configurationPolicies'
        'managedDevices'
    )
    Remediation = 'Deploy the Intune security baseline for Windows to all corporate Windows devices and manage deviations deliberately.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/security-baselines'
    )
}
