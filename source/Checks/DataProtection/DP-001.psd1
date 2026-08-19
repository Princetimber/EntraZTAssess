@{
    CheckId = 'DP-001'
    Domain = 'DataProtection'
    Title = 'DLP policies enforce protection across core workloads'
    Description = 'Evaluates whether at least one Data Loss Prevention (DLP) policy is in enforcing mode (not test-only or disabled) and covers Exchange together with SharePoint or OneDrive.'
    Rationale = 'A DLP policy left in test mode logs matches without ever blocking or notifying, giving a false sense of protection against sensitive-data exfiltration.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Purview Data Loss Prevention (Microsoft 365 E3/E5 or standalone Compliance add-on)'
    PermissionDependency = @()
    DataSources = @(
        'dlpCompliancePolicies'
    )
    Remediation = 'Move at least one DLP policy covering Exchange together with SharePoint or OneDrive out of test mode into Enable (enforcing) mode, after validating against real traffic.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/purview/dlp-create-deploy-policy'
    )
}
