@{
    CheckId = 'DT-004'
    Domain = 'DeviceTrust'
    Title = 'Compliance policy quality per platform'
    Description = 'Reviews each platform compliance policy for core controls: minimum OS version, encryption, jailbreak/root blocking (mobile), and password requirements.'
    Rationale = 'A compliance policy that checks nothing meaningful grants the compliant-device signal without verifying device health.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementConfiguration.Read.All'
    )
    DataSources = @(
        'compliancePolicies'
    )
    Remediation = 'Strengthen compliance policies to require encryption, minimum OS versions, password/PIN, and jailbreak/root blocking per platform.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started'
    )
}
