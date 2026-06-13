#Requires -Version 7.2
<#
    .SYNOPSIS
        Ensures the build bootstrap modules ModuleFast and Sampler are present.

    .DESCRIPTION
        Pre-flight guard for the Sampler build pipeline. The standard
        './build.ps1 -ResolveDependency' flow uses ModuleFast to restore the
        modules listed in RequiredModules.psd1 (Sampler, InvokeBuild, Pester,
        etc.). If ModuleFast itself is missing, or if ModuleFast cannot reach
        its 'pwsh.gallery' source to pull Sampler, dependency resolution aborts
        and InvokeBuild is never installed (the 'Invoke-Build is not recognized'
        error).

        This script checks the machine for ModuleFast and Sampler and installs
        each one only when it is not already available. ModuleFast is installed
        via its official bootstrap script, falling back to PSGallery. Sampler is
        installed from PSGallery using the version range declared in
        RequiredModules.psd1, which sidesteps the 'pwsh.gallery' source that
        failed in the build log.

        The script is idempotent: re-running it is a no-op once both modules are
        present. It only installs the two bootstrap modules; the remaining
        dependencies are still restored by './build.ps1 -ResolveDependency'.

    .PARAMETER Scope
        Installation scope passed to Install-Module ('CurrentUser' or
        'AllUsers'). 'AllUsers' requires elevation. The default value is
        'CurrentUser'.

    .PARAMETER Force
        Reinstall ModuleFast and Sampler even if they are already present.

    .EXAMPLE
        ./Install-BuildDependency.ps1

        Installs ModuleFast and Sampler for the current user only if missing,
        then you can run './build.ps1 -ResolveDependency -tasks build'.

    .EXAMPLE
        ./Install-BuildDependency.ps1 -Scope AllUsers -Verbose

        Installs the bootstrap modules machine-wide (run from an elevated
        session) with verbose progress output.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param
(
    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [System.String]
    $Scope = 'CurrentUser',

    [Parameter()]
    [System.Management.Automation.SwitchParameter]
    $Force
)

$ErrorActionPreference = 'Stop'

function Test-ModulePresent
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    return [System.Boolean]((Get-Module -Name $Name -ListAvailable -ErrorAction 'SilentlyContinue') -or
        (Get-Module -Name $Name -ErrorAction 'SilentlyContinue'))
}

function Initialize-PSGallery
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param ()

    # Ensure the NuGet package provider is available so Install-Module works unattended.
    $nuGetProvider = Get-PackageProvider -Name 'NuGet' -ListAvailable -ErrorAction 'SilentlyContinue'

    if (-not $nuGetProvider)
    {
        if ($PSCmdlet.ShouldProcess('NuGet', 'Install package provider'))
        {
            Write-Verbose -Message 'Installing the NuGet package provider.'

            $null = Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Scope $Scope -Force
        }
    }

    $gallery = Get-PSRepository -Name 'PSGallery' -ErrorAction 'SilentlyContinue'

    if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted')
    {
        if ($PSCmdlet.ShouldProcess('PSGallery', 'Temporarily trust repository'))
        {
            Write-Verbose -Message 'Temporarily trusting PSGallery for this bootstrap.'

            Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
        }
    }
}

# Read the Sampler version range from RequiredModules.psd1 so this stays in sync.
$requiredModulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'RequiredModules.psd1'

$samplerMinimumVersion = $null
$samplerMaximumVersion = $null

if (Test-Path -Path $requiredModulesPath)
{
    $requiredModules = Import-PowerShellDataFile -Path $requiredModulesPath

    $samplerSpecification = $requiredModules['Sampler']

    # Parse a NuGet-style range such as '[0.118,1.0)' into min/max versions.
    if ($samplerSpecification -is [System.String] -and $samplerSpecification -match '([\d\.]+)\s*,\s*(\d+)')
    {
        $samplerMinimumVersion = $Matches[1]

        # The upper bound is exclusive in NuGet syntax (e.g. '1.0)' means < 1.0).
        # Install-Module's MaximumVersion is inclusive, so target the highest
        # release below the next major boundary, e.g. '1.0)' -> '0.999.999'.
        $samplerMaximumVersion = '{0}.999.999' -f ([System.Int32] $Matches[2] - 1)
    }
}

if (-not $samplerMinimumVersion)
{
    # Fallback that matches the documented baseline if the manifest could not be parsed.
    $samplerMinimumVersion = '0.118.0'
    $samplerMaximumVersion = '0.999.999'
}

# --- ModuleFast -----------------------------------------------------------
if ($Force -or -not (Test-ModulePresent -Name 'ModuleFast'))
{
    if ($PSCmdlet.ShouldProcess('ModuleFast', 'Install module'))
    {
        Write-Verbose -Message 'ModuleFast is not present. Installing it.'

        try
        {
            # Preferred path: the official ModuleFast bootstrap script (same source build.ps1 uses).
            $moduleFastBootstrap = Invoke-WebRequest -Uri 'https://bit.ly/modulefast' -ErrorAction 'Stop' # cSpell: disable-line

            $moduleFastScriptBlock = [System.Management.Automation.ScriptBlock]::Create($moduleFastBootstrap.Content)

            & $moduleFastScriptBlock
        }
        catch
        {
            Write-Warning -Message ('ModuleFast bootstrap script failed ({0}). Falling back to PSGallery.' -f $_.Exception.Message)

            Initialize-PSGallery

            Install-Module -Name 'ModuleFast' -Scope $Scope -Force -AllowClobber
        }
    }
}
else
{
    Write-Verbose -Message 'ModuleFast is already present. Skipping.'
}

# --- Sampler --------------------------------------------------------------
if ($Force -or -not (Test-ModulePresent -Name 'Sampler'))
{
    if ($PSCmdlet.ShouldProcess('Sampler', 'Install module'))
    {
        Write-Verbose -Message ('Sampler is not present. Installing version range [{0},{1}].' -f $samplerMinimumVersion, $samplerMaximumVersion)

        Initialize-PSGallery

        $installSamplerParameters = @{
            Name            = 'Sampler'
            MinimumVersion  = $samplerMinimumVersion
            MaximumVersion  = $samplerMaximumVersion
            Scope           = $Scope
            Force           = $true
            AllowClobber    = $true
        }

        Install-Module @installSamplerParameters
    }
}
else
{
    Write-Verbose -Message 'Sampler is already present. Skipping.'
}

Write-Information -MessageData "[bootstrap] ModuleFast and Sampler are ready. Run './build.ps1 -ResolveDependency -tasks build' next." -InformationAction 'Continue'
