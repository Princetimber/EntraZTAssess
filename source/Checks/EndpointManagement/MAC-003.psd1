@{
    CheckId = 'MAC-003'
    Domain = 'EndpointManagement'
    Title = 'macOS security configuration deployed'
    Description = 'Verifies macOS security configuration (firewall, Gatekeeper and related settings) is deployed via compliance or configuration policy.'
    Rationale = 'Default macOS security posture is user-controlled; managed firewall and Gatekeeper settings make it organisational policy.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementConfiguration.Read.All'
    )
    DataSources = @(
        'compliancePolicies'
        'deviceConfigurations'
        'managedDevices'
    )
    Remediation = 'Deploy macOS firewall and Gatekeeper settings via Intune configuration, and require the firewall in compliance policy.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-firewall-policy'
    )
}
