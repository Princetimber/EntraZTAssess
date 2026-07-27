#Requires -Version 7.0

<#
    Repo-local provisioning module loader. Dot-sources the provisioning
    functions and exports them. This module is deliberately NOT part of the
    built/published Get-EntraZTAssess package; it performs Graph writes and is
    run once by an administrator from a clone of the repository.
#>

$publicFunctions = Get-ChildItem -Path $PSScriptRoot/Public/*.ps1 -ErrorAction SilentlyContinue
foreach ($function in $publicFunctions) {
    . $function.FullName
    Export-ModuleMember -Function $function.BaseName
}
