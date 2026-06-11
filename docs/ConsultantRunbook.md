# Consultant Runbook

This runbook is for consultant-led, read-only Microsoft Entra ID and Intune Zero Trust assessments with `Get-EntraZTAssess`. It assumes PowerShell 7+, restored project dependencies, and an operator account that can consent to the read-only Microsoft Graph scopes listed by the module.

## Pre-Engagement

1. Confirm the engagement reference, customer name, classification, and local output location.
2. Review required scopes with `Get-ZTAssessRequiredPermission` and agree the module set with the customer before connecting.
3. Confirm the customer understands that collection is read-only and that all report artifacts are written locally under the engagement folder.
4. Decide whether delivered report artifacts should use `Export-ZTAssessReport -RedactUserIdentifiers`. This option redacts user-identifying values in generated reports only; raw run artifacts remain unchanged for auditability.

## Collection Workflow

```powershell
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring
$engagement = New-ZTAssessEngagement -CustomerName 'Contoso Ltd' -Reference 'ENG-2026-042' -OutputPath ~/Assessments -Classification 'Confidential - Client'
$run = Invoke-ZTAssessment -EngagementPath $engagement.EngagementPath
Get-ZTAssessScore -RunPath $run.RunPath
Get-ZTAssessFinding -RunPath $run.RunPath -Status Fail | Sort-Object Severity, CheckId
Export-ZTAssessReport -RunPath $run.RunPath -RedactUserIdentifiers
Disconnect-ZTAssessment
```

Use `-RedactUserIdentifiers` for client-distribution copies when user names, UPNs, email addresses, or owner fields appear in finding evidence. Omit it for internal working copies when raw identifiers are required for remediation workshops.

## Delivery Artifacts

`Export-ZTAssessReport` writes these local-only files under `<RunPath>/Reports`:

- `ExecutiveReport.html`
- `TechnicalReport.html`
- `RiskRegister.json`
- `RiskRegister.csv`
- `RemediationRoadmap.json`

The risk register and remediation roadmap include only `Fail` and `Partial` findings. `NotAssessed` findings remain in the technical report so missing permissions, licences, or collection gaps are visible to the customer.

## Quality Checks

Before sharing results, verify:

- The run folder contains `Findings/findings.json` and `Scores/scores.json`.
- The exported reports reflect the intended redaction mode.
- Critical and High findings have clear evidence and remediation text.
- `NotAssessed` findings have actionable reasons, especially missing Microsoft Graph scopes.
- No generated reports are edited by hand; rerun `Export-ZTAssessReport` after any source run correction.

## Read-Only Boundaries

The module must not mutate tenant configuration. Collection should flow through the module Graph wrappers, reports must not connect to Graph, and generated artifacts should remain under the engagement output path. Do not run release or publish tasks during a customer assessment.
