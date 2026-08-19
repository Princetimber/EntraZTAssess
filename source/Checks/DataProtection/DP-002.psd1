@{
    CheckId = 'DP-002'
    Domain = 'DataProtection'
    Title = 'DLP rules block sensitive-information matches'
    Description = 'Evaluates whether at least one DLP compliance rule takes a blocking action (BlockAccess) when sensitive information is detected, rather than only notifying or logging.'
    Rationale = 'A rule that only notifies still allows the sensitive content to leave the organisation; a blocking action is required to prevent exfiltration rather than merely observe it.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Purview Data Loss Prevention (Microsoft 365 E3/E5 or standalone Compliance add-on)'
    PermissionDependency = @()
    DataSources = @(
        'dlpComplianceRules'
    )
    Remediation = 'Configure at least one DLP rule to block access when sensitive information is matched, rather than only notifying the user or generating an incident report.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/purview/dlp-create-deploy-policy'
    )
}
