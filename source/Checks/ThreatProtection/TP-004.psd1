@{
    CheckId = 'TP-004'
    Domain = 'ThreatProtection'
    Title = 'Malware filtering blocks malicious attachments'
    Description = 'Evaluates whether malware filter policies enable the common attachment-type file filter and take a blocking action rather than a notify-only action.'
    Rationale = 'Malware filtering is the baseline attachment control present even without a Defender for Office 365 licence; a notify-only action still delivers the malicious file.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Exchange Online Protection (included with Exchange Online)'
    PermissionDependency = @()
    DataSources = @(
        'malwareFilterPolicies'
    )
    Remediation = 'Enable the common attachment-type file filter on every malware filter policy and set the action to delete or reject the message rather than notify-only.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/defender-office-365/anti-malware-policies-configure'
    )
}
