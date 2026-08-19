@{
    CheckId = 'TP-002'
    Domain = 'ThreatProtection'
    Title = 'Safe Attachments blocks malicious attachments'
    Description = 'Evaluates whether Safe Attachments policies are enabled and configured to block, replace, or dynamically deliver suspicious attachments rather than merely monitor them.'
    Rationale = 'A monitor-only or allow action detonates malware sandboxing without preventing delivery, leaving the payload in the mailbox regardless of the verdict.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Defender for Office 365 Plan 1 or 2'
    PermissionDependency = @()
    DataSources = @(
        'safeAttachmentPolicies'
    )
    Remediation = 'Enable every Safe Attachments policy and set its action to Block, Dynamic Delivery, or Replace so malicious attachments are not delivered.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/defender-office-365/safe-attachments-policies-configure'
    )
}
