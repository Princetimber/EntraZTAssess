@{
    CheckId = 'TP-003'
    Domain = 'ThreatProtection'
    Title = 'Anti-phishing impersonation protection is enabled'
    Description = 'Evaluates whether anti-phishing policies enable mailbox intelligence and spoof intelligence, and set a phishing confidence threshold at or above the consultancy-defined floor.'
    Rationale = 'Impersonation and spoof detection are the primary Defender for Office 365 controls against business email compromise and executive impersonation.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Defender for Office 365 Plan 1 or 2 (mailbox intelligence); Exchange Online Protection (spoof intelligence)'
    PermissionDependency = @()
    DataSources = @(
        'antiPhishPolicies'
    )
    Remediation = 'Enable every anti-phishing policy with mailbox intelligence, mailbox intelligence protection, and spoof intelligence turned on, and raise the phishing threshold level to at least the consultancy-defined floor.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about'
    )
}
