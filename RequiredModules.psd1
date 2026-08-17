@{
    <#
        This is only required if you need to use the method PowerShellGet & PSDepend
        It is not required for PSResourceGet or ModuleFast (and will be ignored).
        See Resolve-Dependency.psd1 on how to enable methods.
    #>
    #PSDependOptions             = @{
    #    AddToPath  = $true
    #    Target     = 'output\RequiredModules'
    #    Parameters = @{
    #        Repository = 'PSGallery'
    #    }
    #}

    # 5.10.5+ avoids the duplicate 'ProgressAction' parameter error on PowerShell 7.4+
    # (https://github.com/nightroman/Invoke-Build/issues/183).
    InvokeBuild                 = '[5.10.5,6.0)'
    # 1.24.0 has a flaky NullReferenceException in Invoke-ScriptAnalyzer when
    # enough custom Rules entries are active simultaneously (reproduced
    # locally, ~1 crash in 5 runs against Export-ZTAssessReport.ps1 under our
    # PSScriptAnalyzerSettings.psd1); fixed by 1.25.0. 1.22.0/1.23.0 were not
    # individually verified, so the lower bound is raised straight to the
    # confirmed-clean 1.25.0 rather than bisecting further.
    PSScriptAnalyzer            = '[1.25.0,2.0)'
    Pester                      = '[5.6,6.0)'
    ModuleBuilder               = '[3.0,4.0)'
    ChangelogManagement         = '[3.0,4.0)'
    Sampler                     = '[0.118,1.0)'
    # PSGallery's latest published Sampler.GitHubTasks is 0.4.1; an upper-only
    # 0.6 pin made Save-PSResource throw 'Package(s) ... could not be installed'.
    'Sampler.GitHubTasks'       = '[0.4.1,1.0)'
}
