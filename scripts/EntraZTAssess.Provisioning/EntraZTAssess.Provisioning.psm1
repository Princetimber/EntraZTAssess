#Requires -Version 7.0

<#
    Provisioning module loader. Dot-sources the provisioning functions and
    exports them. Published as its own standalone PSGallery package
    (EntraZTAssess.Provisioning), separately from the read-only
    Get-EntraZTAssess package - it performs Graph and Exchange Online write
    operations and is run once by an administrator, from either
    `Install-Module EntraZTAssess.Provisioning` or a clone of this
    repository. It ships its own copy of the permission catalogue under
    Settings/ so it does not depend on a sibling `source/` folder existing.
#>

$privateFunctions = Get-ChildItem -Path $PSScriptRoot/Private/*.ps1 -ErrorAction SilentlyContinue
foreach ($function in $privateFunctions) {
    . $function.FullName
}

$publicFunctions = Get-ChildItem -Path $PSScriptRoot/Public/*.ps1 -ErrorAction SilentlyContinue
foreach ($function in $publicFunctions) {
    . $function.FullName
    Export-ModuleMember -Function $function.BaseName
}
