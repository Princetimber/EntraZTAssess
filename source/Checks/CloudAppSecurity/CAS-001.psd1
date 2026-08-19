@{
    CheckId = 'CAS-001'
    Domain = 'CloudAppSecurity'
    Title = 'Defender for Cloud Apps setup is implemented (best-effort proxy)'
    Description = 'Uses the tenant''s Microsoft Secure Score contribution for the Cloud App Security / Defender for Cloud Apps setup control as a best-effort proxy for whether the service is provisioned, since Microsoft Graph exposes no direct Defender for Cloud Apps configuration API.'
    Rationale = 'Defender for Cloud Apps provides visibility and control over SaaS/cloud app usage; without setup, shadow IT and risky OAuth app grants go undetected.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Microsoft Defender for Cloud Apps'
    PermissionDependency = @(
        'SecurityEvents.Read.All'
    )
    DataSources = @(
        'secureScoreLatest'
    )
    Remediation = 'Provision Microsoft Defender for Cloud Apps and connect it to the tenant''s Microsoft 365 apps, then confirm the setup secure score control reaches its maximum score. This check is a best-effort proxy; verify actual configuration in the Defender for Cloud Apps portal.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/defender-cloud-apps/general-setup'
    )
}
