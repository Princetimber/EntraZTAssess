@{
    CheckId = 'TP-001'
    Domain = 'ThreatProtection'
    Title = 'Safe Links protection is hardened'
    Description = 'Evaluates whether Safe Links policies scan URLs in email, Teams, and Office apps at time-of-click and block click-through past a warning page.'
    Rationale = 'Safe Links defends against weaponised or delayed-detonation URLs; scanning without a click-through bypass is required for the control to be effective.'
    DefaultSeverity = 'High'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'AssumeBreach'
    )
    LicenceDependency = 'Microsoft Defender for Office 365 Plan 1 or 2'
    PermissionDependency = @()
    DataSources = @(
        'safeLinksPolicies'
    )
    Remediation = 'Enable Safe Links for email, Teams, and Office apps in every policy, enable URL scanning, and disable click-through past the warning page.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/defender-office-365/safe-links-policies-configure'
    )
}
