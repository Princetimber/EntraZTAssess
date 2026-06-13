#Requires -Version 7.2
<#
.SYNOPSIS
    Ensures the build bootstrap modules from RequiredModules.psd1 are present.

.DESCRIPTION
    The standard Sampler build path uses ./build.ps1 -ResolveDependency to restore the
    modules listed in RequiredModules.psd1. That preferred path depends on ModuleFast
    being available and on its package index being able to resolve every required module.
    If ModuleFast cannot create a dependency plan, dependencies such as InvokeBuild and
    PSScriptAnalyzer may never be installed and the build can fail later with a less
    useful "Invoke-Build is not recognized" error.

    This helper is an idempotent pre-flight for developer machines and build agents. It:

      - Checks the machine for each module listed in RequiredModules.psd1.
      - Installs ModuleFast by using the official bootstrap script, with a PSGallery
        Install-Module fallback.
      - Installs missing RequiredModules.psd1 entries from PSGallery, including
        InvokeBuild and PSScriptAnalyzer, using the declared version ranges when they can
        be translated to Install-Module parameters.

    Run this script before ./build.ps1 -ResolveDependency -Tasks build when dependency
    bootstrap reports that a required module was not found through ModuleFast/pwsh.gallery
    or when InvokeBuild is not available on the machine.

.PARAMETER Scope
    Installation scope passed to Install-Module. Defaults to CurrentUser.

.PARAMETER Force
    Reinstall the required build modules even when they are already available.

.EXAMPLE
    ./Install-BuildDependency.ps1

.EXAMPLE
    ./Install-BuildDependency.ps1 -Scope AllUsers -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]
    $Scope = 'CurrentUser',

    [Parameter()]
    [switch]
    $Force
)

$ErrorActionPreference = 'Stop'

function Test-ModulePresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    $availableModule = Get-Module -Name $Name -ListAvailable -ErrorAction 'SilentlyContinue' | Select-Object -First 1
    if ($null -ne $availableModule) {
        return $true
    }

    return [bool] (Get-Module -Name $Name -ErrorAction 'SilentlyContinue')
}

function Initialize-PSGallery {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]
        $Scope
    )

    if ($PSCmdlet.ShouldProcess('PSGallery', 'Ensure NuGet provider and trusted repository')) {
        $null = Get-PackageProvider -Name 'NuGet' -ErrorAction 'SilentlyContinue'
        if ($null -eq (Get-PackageProvider -Name 'NuGet' -ErrorAction 'SilentlyContinue')) {
            Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Scope $Scope -Force | Out-Null
        }

        $repository = Get-PSRepository -Name 'PSGallery' -ErrorAction 'Stop'
        if ($repository.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
        }
    }
}

function Convert-VersionRangeToInstallModuleParameter {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $VersionRange
    )

    $versionParameter = @{}

    if ([string]::IsNullOrWhiteSpace($VersionRange)) {
        return $versionParameter
    }

    $normalizedRange = $VersionRange.Trim()
    if ($normalizedRange -notmatch '^[\[\(]\s*([^,\]\)]+)\s*,\s*([^\]\)]+)\s*[\]\)]$') {
        Write-Warning "Could not parse version range '$VersionRange'. Installing the module without an explicit version constraint."
        return $versionParameter
    }

    $minimumVersion = $Matches[1].Trim()
    $upperVersion = $Matches[2].Trim()

    if (-not [string]::IsNullOrWhiteSpace($minimumVersion)) {
        $versionParameter['MinimumVersion'] = $minimumVersion
    }

    $isExclusiveUpperBound = $normalizedRange.EndsWith(')')
    if (-not [string]::IsNullOrWhiteSpace($upperVersion)) {
        if ($isExclusiveUpperBound) {
            $upperVersionParts = $upperVersion -split '\.'
            $upperMajor = 0
            if ([int]::TryParse($upperVersionParts[0], [ref] $upperMajor) -and $upperMajor -gt 0) {
                $versionParameter['MaximumVersion'] = ('{0}.999.999' -f ($upperMajor - 1))
            } else {
                Write-Warning "Could not translate exclusive upper bound '$upperVersion'. Installing without MaximumVersion."
            }
        } else {
            $versionParameter['MaximumVersion'] = $upperVersion
        }
    }

    return $versionParameter
}

function Install-RequiredBuildModule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter()]
        [string]
        $VersionRange,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [string]
        $Scope,

        [Parameter()]
        [switch]
        $Force
    )

    if (-not $Force.IsPresent -and (Test-ModulePresent -Name $Name)) {
        Write-Information -MessageData "[bootstrap] $Name is already available." -InformationAction 'Continue'
        return
    }

    if ($PSCmdlet.ShouldProcess($Name, 'Install required build module from PSGallery')) {
        Initialize-PSGallery -Scope $Scope

        $installModuleParameters = @{
            Name        = $Name
            Scope       = $Scope
            Force       = $true
            AllowClobber = $true
        }

        $versionParameter = Convert-VersionRangeToInstallModuleParameter -VersionRange $VersionRange
        foreach ($parameterName in $versionParameter.Keys) {
            $installModuleParameters[$parameterName] = $versionParameter[$parameterName]
        }

        Install-Module @installModuleParameters
    }
}

$requiredModuleManifest = Join-Path -Path $PSScriptRoot -ChildPath 'RequiredModules.psd1'
if (-not (Test-Path -Path $requiredModuleManifest -PathType 'Leaf')) {
    throw "Required module manifest was not found at '$requiredModuleManifest'."
}

$requiredModules = Import-PowerShellDataFile -Path $requiredModuleManifest

if ($Force.IsPresent -or -not (Test-ModulePresent -Name 'ModuleFast')) {
    if ($PSCmdlet.ShouldProcess('ModuleFast', 'Install bootstrap module')) {
        try {
            Write-Information -MessageData '[bootstrap] Installing ModuleFast using the official bootstrap script.' -InformationAction 'Continue'
            $moduleFastInstaller = Invoke-WebRequest -Uri 'https://bit.ly/modulefast' -UseBasicParsing
            $moduleFastInstallerScript = [scriptblock]::Create($moduleFastInstaller.Content)
            & $moduleFastInstallerScript -Scope $Scope -Confirm:$false
        } catch {
            Write-Warning "ModuleFast bootstrap script failed. Falling back to PSGallery Install-Module. Error: $($_.Exception.Message)"
            Initialize-PSGallery -Scope $Scope
            Install-Module -Name 'ModuleFast' -Scope $Scope -Force -AllowClobber
        }
    }
} else {
    Write-Information -MessageData '[bootstrap] ModuleFast is already available.' -InformationAction 'Continue'
}

foreach ($moduleName in ($requiredModules.Keys | Sort-Object)) {
    if ($moduleName -eq 'ModuleFast') {
        continue
    }

    Install-RequiredBuildModule -Name $moduleName -VersionRange $requiredModules[$moduleName] -Scope $Scope -Force:$Force
}

Write-Information -MessageData "[bootstrap] Required build modules are ready. Run './build.ps1 -ResolveDependency -Tasks build' next." -InformationAction 'Continue'
