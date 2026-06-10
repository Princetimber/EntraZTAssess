#Requires -Version 7.0

# Device classification engine. Classifies every device into one of six
# classes - Corporate, BYOD, Shared, Kiosk, PAW, Unknown - with a
# confidence level, using the precedence defined in the toolkit
# specification:
#
#   1. Intune ownership (managedDeviceOwnerType company/personal)
#   2. Enrolment profile type refinement (dedicated -> Kiosk, shared modes
#      -> Shared, Entra-registered-only personal -> BYOD)
#   3. PAW candidacy via configured name patterns (flagged, never asserted)
#   4. Entra-registered with no Intune record -> BYOD (unmanaged, MAM-only
#      candidate)
#   5. Entra device with no Intune record and stale or no activity -> Unknown
#
# Returns one record per device: Id, DisplayName, Platform, Class,
# Confidence, OwnerType, EnrolmentType, Managed, Source.
function Get-ZTAssessDeviceClass {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$ManagedDevices,

        [Parameter()]
        [AllowNull()]
        [object[]]$EntraDevices,

        [Parameter()]
        [hashtable]$Settings
    )

    if (-not $Settings) {
        $Settings = Get-ZTAssessConfiguration -Name Settings
    }

    $pawPatterns = @($Settings.PawGroupPatterns)
    $staleCutoff = [datetime]::UtcNow.AddDays(-[int]$Settings.Thresholds.StaleDeviceDays)

    $normalisePlatform = {
        param($os)
        switch -Regex ([string]$os) {
            'Windows' { 'Windows'; break }
            'iOS|iPadOS' { 'iOS'; break }
            'macOS|Mac OS' { 'macOS'; break }
            'Android' { 'Android'; break }
            default { 'Other' }
        }
    }

    $isPawCandidate = {
        param($name)
        foreach ($pattern in $pawPatterns) {
            if ([string]$name -like $pattern) { return $true }
        }
        return $false
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $managedByEntraId = @{}

    foreach ($device in @($ManagedDevices)) {
        $platform = & $normalisePlatform $device.operatingSystem
        $enrolment = [string]$device.deviceEnrollmentType
        $owner = [string]$device.managedDeviceOwnerType

        $class = 'Unknown'
        $confidence = 'Low'

        if ($owner -eq 'company') {
            $class = 'Corporate'
            $confidence = 'High'
        }
        elseif ($owner -eq 'personal') {
            $class = 'BYOD'
            $confidence = 'High'
        }

        # Enrolment profile refinement.
        if ($enrolment -match 'DedicatedDevice') {
            $class = 'Kiosk'
            $confidence = 'High'
        }
        elseif ($enrolment -match 'sharedDevice|sharedPC' -or $device.deviceName -like '*shared*') {
            $class = 'Shared'
            $confidence = if ($enrolment -match 'shared') { 'High' } else { 'Low' }
        }

        # PAW candidacy (flag for consultant confirmation, never auto-assert).
        if ($class -eq 'Corporate' -and (& $isPawCandidate $device.deviceName)) {
            $class = 'PAW'
            $confidence = 'Medium'
        }

        $record = [pscustomobject]@{
            PSTypeName    = 'ZTAssess.DeviceClass'
            Id            = $device.id
            DisplayName   = $device.deviceName
            Platform      = $platform
            Class         = $class
            Confidence    = $confidence
            OwnerType     = $owner
            EnrolmentType = $enrolment
            Managed       = $true
            Source        = 'Intune'
        }
        $results.Add($record)

        if ($device.azureADDeviceId) {
            $managedByEntraId[$device.azureADDeviceId] = $record
        }
    }

    # Entra device objects without an Intune record.
    foreach ($device in @($EntraDevices)) {
        if ($device.deviceId -and $managedByEntraId.ContainsKey($device.deviceId)) { continue }
        if (-not $device.accountEnabled) { continue }

        $platform = & $normalisePlatform $device.operatingSystem
        $lastActivity = $null
        if ($device.approximateLastSignInDateTime) {
            $lastActivity = [datetime]$device.approximateLastSignInDateTime
        }

        $isActive = $lastActivity -and $lastActivity -ge $staleCutoff

        if ($device.profileType -eq 'RegisteredDevice' -and $isActive) {
            # Workplace-joined personal device, active, not Intune managed.
            $class = 'BYOD'
            $confidence = 'Medium'
        }
        elseif ($isActive) {
            $class = 'Unknown'
            $confidence = 'Medium'
        }
        else {
            $class = 'Unknown'
            $confidence = 'Low'
        }

        $results.Add([pscustomobject]@{
                PSTypeName    = 'ZTAssess.DeviceClass'
                Id            = $device.id
                DisplayName   = $device.displayName
                Platform      = $platform
                Class         = $class
                Confidence    = $confidence
                OwnerType     = ''
                EnrolmentType = [string]$device.profileType
                Managed       = $false
                Source        = 'Entra'
            })
    }

    return , $results.ToArray()
}
