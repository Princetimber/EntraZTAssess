@{
    # =========================================================================
    # PSScriptAnalyzerSettings.psd1
    #
    # Baseline ruleset for PowerShell modules and scripts following the
    # Jeffrey Snover design philosophy (objects not text, pipeline as the
    # unit of composition, discoverability, "if it can't be automated it's
    # broken") and OTBS ("One True Brace Style") formatting conventions.
    #
    # Target: zero violations at Error and Warning severity.
    #   Invoke-ScriptAnalyzer -Path .\source -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    #
    # See: ~/claude-work/about-me/tech-standards.md
    #      references/design-philosophy.md, references/conventions.md
    #      (powershell-sysadmin / powershell-security-engineer skills)
    # =========================================================================

    Severity            = @('Error', 'Warning', 'Information')

    # Run every default rule, then explicitly override/exclude below rather
    # than hand-picking a subset — new PSScriptAnalyzer rules should apply
    # by default unless there's a stated reason not to.
    IncludeDefaultRules = $true

    ExcludeRules        = @(
        # PSAvoidUsingWriteHost is kept as a HARD rule (see below) — not excluded.

        # Required baseline exclusion per powershell/coding-style.md: BOM
        # presence is decided by the editor/encoding config (VS Code's
        # [powershell] files.encoding = "utf8bom"), not by ScriptAnalyzer.
        # Authoring happens across macOS, Windows, and CI runners, and BOM
        # handling is inconsistent enough across those (particularly
        # macOS/Linux-originated files) that enforcing it here produces
        # noise rather than signal. Encoding correctness is verified by the
        # module's own encoding checks / CI step instead.
        'PSUseBOMForUnicodeEncodedFile'
    )

    Rules               = @{

        # ---------------------------------------------------------------
        # Objects, not text / Never format inside a function
        # ---------------------------------------------------------------

        PSAvoidUsingWriteHost                          = @{
            Enable = $true
            # Write-Host writes to the screen and returns nothing — invisible
            # to capture, redirection, and tests. Use Write-Verbose for
            # operator-facing progress, Write-Output (implicit return) for data.
        }

        PSUseOutputTypeCorrectly                       = @{
            Enable = $true
        }

        PSUseSingularNouns                             = @{
            Enable = $true
            # Get-ADUser, not Get-ADUsers.
        }

        PSUseApprovedVerbs                             = @{
            Enable = $true
            # Check Get-Verb before naming. Discoverability depends on a
            # closed, predictable verb vocabulary.
        }

        # ---------------------------------------------------------------
        # Aliases and terseness — script code is read later, so spell it out
        # ---------------------------------------------------------------

        PSAvoidUsingCmdletAliases                      = @{
            Enable = $true
            # Full cmdlet names only: Get-ChildItem, not gci or ls.
        }

        PSAvoidUsingPositionalParameters               = @{
            Enable = $true
            # Named parameters only in saved script code.
        }

        PSAvoidUsingDoubleQuotesForConstantString      = @{
            Enable = $true
            # Single-quote constant strings; reserve double quotes for
            # actual interpolation, per common style guide convention.
        }

        # ---------------------------------------------------------------
        # Security — never plaintext secrets, never unsafe expression eval
        # ---------------------------------------------------------------

        PSAvoidUsingPlainTextForPassword               = @{
            Enable = $true
        }

        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }

        PSAvoidUsingUsernameAndPasswordParams          = @{
            Enable = $true
            # Take a single [PSCredential] instead of two separate params.
        }

        PSAvoidUsingInvokeExpression                   = @{
            Enable = $true
            # Use the call operator '&' with an argument array, or a real cmdlet.
        }

        PSUsePSCredentialType                          = @{
            Enable = $true
        }

        PSAvoidUsingComputerNameHardcoded              = @{
            Enable = $true
        }

        # ---------------------------------------------------------------
        # State-changing functions — "if it cannot be automated, it is broken"
        # ---------------------------------------------------------------

        PSUseShouldProcessForStateChangingFunctions    = @{
            Enable = $true
            # Any New-/Set-/Remove-/Disable- function needs
            # [CmdletBinding(SupportsShouldProcess)]. No dry-run, no ship.
        }

        PSShouldProcess                                = @{
            Enable = $true
        }

        PSUseProcessBlockForPipelineCommand            = @{
            Enable = $true
            # Stream, don't accumulate: implement 'process' so each pipeline
            # item is emitted as it completes.
        }

        # ---------------------------------------------------------------
        # Hygiene / correctness
        # ---------------------------------------------------------------

        PSAvoidDefaultValueSwitchParameter             = @{
            Enable = $true
            # A [switch] already defaults to $false — never write
            # [switch]$Force = $false.
        }

        PSUseDeclaredVarsMoreThanAssignments           = @{
            Enable = $true
        }

        PSAvoidGlobalVars                              = @{
            Enable = $true
        }

        PSAvoidUsingEmptyCatchBlock                    = @{
            Enable = $true
            # Swallowing an error silently is worse than crashing. Add
            # context with Write-Error, then re-throw.
        }

        PSAvoidTrailingWhitespace                      = @{
            Enable = $true
        }

        PSReviewUnusedParameter                        = @{
            Enable = $true
        }

        PSMissingModuleManifestField                   = @{
            Enable = $true
        }

        PSAvoidMultipleTypeAttributes                  = @{
            Enable = $true
        }

        # ---------------------------------------------------------------
        # Discoverability — help is the interface, not documentation
        # ---------------------------------------------------------------

        PSProvideCommentHelp                           = @{
            Enable                  = $true
            ExportedOnly            = $true
            BlockComment            = $true
            VSCodeSnippetCorrection = $true
            Placement               = 'begin'
            # Every public function needs SYNOPSIS/DESCRIPTION/PARAMETER
            # (one per param)/EXAMPLE (two or more)/OUTPUTS/NOTES.
        }

        # ---------------------------------------------------------------
        # OTBS formatting — brace on its own line, 4-space indent,
        # whitespace around operators and pipes, aligned hashtables
        # ---------------------------------------------------------------

        PSPlaceOpenBrace                               = @{
            Enable             = $true
            OnSameLine         = $true   # OTBS: opening brace stays on the statement's line, e.g. 'if (x) {'
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }

        PSPlaceCloseBrace                              = @{
            Enable             = $true
            NewLineAfter       = $false
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $true
        }

        PSUseConsistentIndentation                     = @{
            Enable              = $true
            IndentationSize     = 4
            PipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
            Kind                = 'space'
        }

        PSUseConsistentWhitespace                      = @{
            Enable                          = $true
            CheckOpenBrace                  = $true
            CheckOpenParen                  = $true
            # CheckOperator is disabled: it enforces exactly one space around
            # '=', which directly conflicts with PSAlignAssignmentStatement's
            # padded alignment of hashtable/splat assignments (e.g.
            # 'Environment           = $x'). The two rules cannot both pass
            # on an aligned hashtable — this is a known PSScriptAnalyzer rule
            # conflict, not a formatter bug. Disabling CheckOperator here
            # forgoes single-space enforcement around ALL binary/assignment
            # operators project-wide (not just in hashtables) in favour of
            # keeping hashtable/splat alignment enforced and auto-fixable.
            CheckOperator                   = $false
            CheckSeparator                  = $true
            CheckPipe                       = $true
            CheckPipeForRedundantWhitespace = $false
            CheckInnerBrace                 = $true
            CheckParameter                  = $false
        }

        PSAlignAssignmentStatement                     = @{
            Enable         = $true
            CheckHashtable = $true
            # Aligns '=' in hashtables/splats — matches
            # codeFormatting.alignPropertyValuePairs in the VS Code extension.
            # Note: source/Checks/**/*.psd1, Get-EntraZTAssess.psd1,
            # settings.psd1, and permissions.psd1 are flat manifests with
            # widely varying key lengths, so a full 'source/ -Recurse' lint
            # will show noisy findings here for those .psd1 files.
            # PSScriptAnalyzer has no per-extension rule scoping within one
            # Settings file. This is expected and does not gate CI: the QA
            # suite (tests/QA/module.tests.ps1) only lints exported .ps1
            # function files, never .psd1.
        }

        PSUseCorrectCasing                             = @{
            Enable = $true
            # Cmdlet and parameter names cased as the command actually
            # declares them — matches codeFormatting.useCorrectCasing.
        }

        # ---------------------------------------------------------------
        # Compatibility — 99% of modules target PowerShell 7+, so pin to
        # 7.4 (current LTS). For the rare module that still has to run
        # under Windows PowerShell 5.1 (e.g. against the CA/CM estate),
        # override this in that project's own PSScriptAnalyzerSettings.psd1
        # rather than loosening the shared baseline.
        # ---------------------------------------------------------------

        PSUseCompatibleSyntax                          = @{
            Enable         = $true
            TargetVersions = @('7.4')
        }
    }
}
