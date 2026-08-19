@{
    CheckId = 'DF-002'
    Domain = 'Defender'
    Title = 'Devices onboarded to Microsoft Defender for Endpoint'
    Description = 'Uses the tenant''s Microsoft Secure Score contribution for the device-onboarding control as a proxy signal for Defender for Endpoint device coverage, since Microsoft Graph exposes no direct onboarded-machine count.'
    Rationale = 'Unonboarded endpoints have no EDR telemetry or response capability, leaving an assume-breach blind spot.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Defender for Endpoint'
    PermissionDependency = @(
        'SecurityEvents.Read.All'
    )
    DataSources = @(
        'secureScoreLatest'
        'secureScoreControlProfiles'
    )
    Remediation = 'Onboard all eligible endpoints to Microsoft Defender for Endpoint via Intune, Configuration Manager, Group Policy, or a local script, then confirm the onboarding secure score control reaches its maximum score.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/defender-endpoint/onboard-configure'
    )
}
