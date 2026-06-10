@{
    CheckId = 'AND-004'
    Domain = 'EndpointManagement'
    Title = 'Corporate Android uses corporate-owned profiles'
    Description = 'Verifies corporate-owned Android devices are enrolled as fully managed, dedicated, or corporate-owned work profile rather than personal profiles.'
    Rationale = 'Corporate Android in a personally owned profile leaves the organisation unable to enforce device-wide controls on hardware it owns.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementManagedDevices.Read.All'
    )
    DataSources = @(
        'managedDevices'
    )
    Remediation = 'Re-enrol corporate Android hardware using corporate-owned Android Enterprise enrolment profiles.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/android-fully-managed-enroll'
    )
}
