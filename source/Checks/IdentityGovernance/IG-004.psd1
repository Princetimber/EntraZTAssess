@{
    CheckId = 'IG-004'
    Domain = 'IdentityGovernance'
    Title = 'Lifecycle workflows and guest hygiene'
    Description = 'Checks lifecycle workflow adoption for joiner/leaver processes and measures stale guest accounts against the staleness window.'
    Rationale = 'Orphaned accounts are the residue of manual lifecycle processes; stale guests in particular are unsupervised external access.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'AssumeBreach'
    )
    LicenceDependency = 'Governance licence for workflows'
    PermissionDependency = @(
        'LifecycleWorkflows.Read.All'
        'Directory.Read.All'
    )
    DataSources = @(
        'lifecycleWorkflows'
        'users'
    )
    Remediation = 'Deploy leaver workflows that disable accounts and remove access automatically, and clean up stale guest accounts.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/what-are-lifecycle-workflows'
    )
}
