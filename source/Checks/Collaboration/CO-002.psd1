@{
    CheckId = 'CO-002'
    Domain = 'Collaboration'
    Title = 'No mail-flow rule silently redirects or blind-copies messages'
    Description = 'Evaluates whether any enabled Exchange transport (mail-flow) rule automatically redirects or blind-copies messages to another recipient, a common data-exfiltration technique after mailbox compromise.'
    Rationale = 'A silent redirect or blind-copy rule lets an attacker who compromises a mailbox (or an insider) exfiltrate mail indefinitely without the mailbox owner noticing.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = ''
    PermissionDependency = @()
    DataSources = @(
        'transportRules'
    )
    Remediation = 'Review every transport rule that sets RedirectMessageTo or BlindCopyTo; remove any that are not a deliberate, documented business requirement, and alert on new rules of this shape going forward.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/defender-office-365/detect-and-remediate-outlook-rules-forms-attack'
    )
}
