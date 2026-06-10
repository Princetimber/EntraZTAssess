@{
    CheckId = 'EM-004'
    Domain = 'EndpointManagement'
    Title = 'Endpoint security policy coverage'
    Description = 'Checks endpoint security policy presence across the core families: antivirus, firewall, attack surface reduction, and EDR.'
    Rationale = 'Each missing family is an unmanaged control plane on the endpoint; ASR rules in particular block the most common malware execution chains.'
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
    )
    Remediation = 'Deploy endpoint security policies for antivirus, firewall, attack surface reduction, and EDR onboarding.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/endpoint-security'
    )
}
