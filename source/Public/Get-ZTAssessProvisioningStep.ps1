#Requires -Version 7.0

function Get-ZTAssessProvisioningStep {
    <#
    .SYNOPSIS
    Lists the ordered steps to provision the EntraZTAssess app registration.

    .DESCRIPTION
    Emits the sequence of commands an administrator runs once to stand up the
    certificate and Entra ID app registration used for certificate-based,
    app-only assessment. Provisioning performs Microsoft Graph WRITE operations
    and therefore lives in the repository's scripts/EntraZTAssess.Provisioning
    module, NOT in this read-only assessment module; the guidance below is
    repo-relative because that module is not installed by Install-Module.

    This function makes no network calls and requires no connection.

    .PARAMETER Modules
    Optional assessment modules to scope the app registration to. When supplied,
    the emitted app-registration and connection commands are tailored to them.
    Use Get-ZTAssessModuleCatalog to list valid names; unknown names throw.

    .EXAMPLE
    Get-ZTAssessProvisioningStep

    Lists the default provisioning steps.

    .EXAMPLE
    Get-ZTAssessProvisioningStep -Modules Identity, Devices | Format-List

    Lists provisioning steps scoped to the Identity and Devices modules.

    .OUTPUTS
    PSCustomObject
    One object per step with Step, Title, Command, and Description.

    .NOTES
    Provisioning is an admin-run, one-time step performed from a clone of the
    EntraZTAssess repository. It is intentionally not part of the installed,
    read-only assessment module.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Modules
    )

    # Validate module names against the catalogue (reads local settings, no network).
    if ($Modules) {
        $null = Get-ZTAssessModuleCatalog -Name $Modules -ErrorAction Stop
    }

    $moduleSuffix = if ($Modules) { ' -Modules {0}' -f ($Modules -join ', ') } else { '' }

    $catalogueForExoCheck = if ($Modules) { Get-ZTAssessModuleCatalog -Name $Modules } else { Get-ZTAssessModuleCatalog }
    $needsExchangeOnline = [bool]($catalogueForExoCheck | Where-Object { $_.RequiresExchangeOnline })

    $orderedSteps = @(
        @{
            Title       = 'Import the provisioning module'
            Command     = 'Import-Module ./scripts/EntraZTAssess.Provisioning'
            Description = 'From a clone of the EntraZTAssess repository. These commands perform Graph writes and are not installed with the read-only assessment module.'
        }
        @{
            Title       = 'Create the certificate'
            Command     = 'New-ZTAssessCertificate'
            Description = 'Generates ~/.ztassess/EntraZTAssess.cer (public) and EntraZTAssess.pfx (private key). Run once; keep the .pfx and its password safe.'
        }
        @{
            Title       = 'Register the application'
            Command     = ('New-ZTAssessAppRegistration -TenantId <YourTenantId> -CertificatePath ~/.ztassess/EntraZTAssess.cer{0}' -f $moduleSuffix)
            Description = 'Creates the Entra ID app with least-privilege read-only Graph permissions, uploads the certificate, and writes ~/.ztassess/auth.json. Requires the Microsoft.Graph SDK and an account that can create app registrations.'
        }
        @{
            Title       = 'Approve admin consent'
            Command     = ('Get-ZTAssessRequiredPermission{0} | Format-Table' -f $moduleSuffix)
            Description = 'A Global Administrator approves the read-only permissions via the consent URL printed by the previous step. Share the required-permission list with the security team first.'
        }
    )

    if ($needsExchangeOnline) {
        $orderedSteps += @{
            Title       = 'Grant Exchange Online / Purview role groups'
            Command     = ('Get-ZTAssessExchangeOnlineRoleGuidance{0}' -f $moduleSuffix)
            Description = 'From a clone of the EntraZTAssess repository (scripts/EntraZTAssess.Provisioning). Lists the Exchange Online / Security & Compliance role groups the tenant''s own Exchange administrator must grant to the app''s service principal; this toolkit only reads Exchange Online/Purview configuration and cannot grant these roles itself.'
        }
    }

    $orderedSteps += @{
        Title       = 'Connect and assess'
        Command     = ('Connect-ZTAssessment{0}' -f $moduleSuffix)
        Description = 'Once consent (and, if applicable, Exchange Online role groups) is granted, connect with certificate-based app-only auth using the values recorded in ~/.ztassess/auth.json.'
    }

    $stepNumber = 0
    foreach ($step in $orderedSteps) {
        $stepNumber++
        [pscustomobject]@{
            PSTypeName  = 'ZTAssess.ProvisioningStep'
            Step        = $stepNumber
            Title       = $step.Title
            Command     = $step.Command
            Description = $step.Description
        }
    }
}
