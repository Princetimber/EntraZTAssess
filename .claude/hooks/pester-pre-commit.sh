#!/usr/bin/env bash
# PreToolUse hook (Bash, filtered to `git commit`): blocks the commit if the
# project Pester suite (tests/) has any failing test. Matches the documented
# Git & PR Workflow step "run all tests" before committing.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

pwsh -NoProfile -NonInteractive -Command "
  \$env:PSModulePath = '$ROOT/output/RequiredModules' + [IO.Path]::PathSeparator + \$env:PSModulePath
  Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
  \$cfg = New-PesterConfiguration
  \$cfg.Run.Path = '$ROOT/tests'
  \$cfg.Run.Exit = \$true
  \$cfg.Output.Verbosity = 'Normal'
  Invoke-Pester -Configuration \$cfg
"
exit_code=$?

if [ "$exit_code" -ne 0 ]; then
  reason="Pester suite failed ($exit_code failing test(s)). Run 'Invoke-Pester -Path tests' locally, fix the failures, then retry the commit."
  jq -n --arg reason "$reason" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
fi

exit 0
