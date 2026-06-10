@{
    CheckId = 'ID-007'
    Domain = 'IdentitySecurity'
    Title = 'Windows Hello for Business configured'
    Description = 'Verifies Windows Hello for Business is configured for the Windows estate and reports adoption.'
    Rationale = 'WHfB provides phishing-resistant, passwordless sign-in bound to device hardware, advancing both identity and device trust pillars.'
    DefaultSeverity = 'Low'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune for policy distribution'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'enrollmentConfigurations'
    )
    Remediation = 'Configure Windows Hello for Business via the tenant enrolment configuration or an Intune account protection policy.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/'
    )
}
