@{
    CheckId = 'WIN-001'
    Domain = 'EndpointManagement'
    Title = 'Windows join-state strategy'
    Description = 'Reviews the Entra join-state distribution of Windows devices and flags a hybrid-only estate with no cloud-native (Entra joined) presence.'
    Rationale = 'Hybrid join keeps device identity anchored to on-premises AD; a cloud-native path is the strategic direction and removes line-of-sight dependencies.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Directory.Read.All'
    )
    DataSources = @(
        'entraDevices'
    )
    Remediation = 'Adopt Entra join for new Windows devices and plan migration of the hybrid estate.'
    RemediationEffort = 'High'
    References = @(
        'https://learn.microsoft.com/entra/identity/devices/concept-directory-join'
    )
}
