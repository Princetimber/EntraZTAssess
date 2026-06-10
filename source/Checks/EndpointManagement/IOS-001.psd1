@{
    CheckId = 'IOS-001'
    Domain = 'EndpointManagement'
    Title = 'Apple MDM push certificate validity'
    Description = 'Verifies the Apple MDM push certificate is present and not approaching expiry (warning at 30 days).'
    Rationale = 'If the APNs certificate expires, every iOS and macOS device silently stops receiving management commands and re-enrolment of the whole estate is required.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Intune'
    PermissionDependency = @(
        'DeviceManagementServiceConfig.Read.All'
    )
    DataSources = @(
        'applePushCertificate'
        'managedDevices'
    )
    Remediation = 'Renew the Apple MDM push certificate before expiry using the same Apple ID, and diarise renewal.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/intune/intune-service/enrollment/apple-mdm-push-certificate-get'
    )
}
