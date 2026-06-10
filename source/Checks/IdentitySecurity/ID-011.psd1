@{
    CheckId = 'ID-011'
    Domain = 'IdentitySecurity'
    Title = 'Password expiry policy aligned to guidance'
    Description = 'Reports whether forced periodic password expiry is disabled, in line with current Microsoft and NCSC guidance, where MFA coverage is strong.'
    Rationale = 'Forced rotation encourages weaker, patterned passwords; current guidance is to drop expiry once MFA and banned-password protections are in place.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Directory.Read.All'
    )
    DataSources = @(
        'organization'
    )
    Remediation = 'Set password validity to never expire once MFA coverage and banned password lists are in force.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/microsoft-365/admin/misc/password-policy-recommendations'
    )
}
