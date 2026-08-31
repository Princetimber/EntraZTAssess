#!/usr/bin/env bash
# PostToolUse hook (Write|Edit): informational PSScriptAnalyzer check on the edited file.
# Never blocks - CLAUDE.md requires ScriptAnalyzer to be run and warnings fixed before
# committing, but per-edit files are often mid-refactor, so this only reports.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
file="$(jq -r '.tool_input.file_path // .tool_response.filePath // empty')"

case "$file" in
  *.ps1|*.psm1) ;;
  *) exit 0 ;;
esac

[ -f "$file" ] || exit 0

PSModulePath="$ROOT/output/RequiredModules${PSModulePath:+:${PSModulePath}}" \
  ZTASSESS_HOOK_FILE="$file" \
  pwsh -NoProfile -NonInteractive -Command '
  Import-Module PSScriptAnalyzer -ErrorAction Stop
  $path = $env:ZTASSESS_HOOK_FILE
  $name = Split-Path -Leaf $path
  $results = Invoke-ScriptAnalyzer -Path $path -Severity Error,Warning
  if ($results) {
    Write-Output "PSScriptAnalyzer: $name has $($results.Count) warning(s)"
    $results | Format-Table RuleName,Severity,Line,Message -AutoSize | Out-String -Width 200
  } else {
    Write-Output "PSScriptAnalyzer: no warnings for $name"
  }
' 2>&1

exit 0
