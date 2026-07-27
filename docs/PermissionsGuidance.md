# Permissions Guidance

`Get-EntraZTAssess` uses read-only Microsoft Graph scopes to collect tenant configuration for assessment. Permission requirements are data-driven from `source/Settings/permissions.psd1` and should be reviewed with the customer before collection.

## How To Review Required Scopes

Use the public permission command rather than copying scopes from source files:

```powershell
Get-ZTAssessRequiredPermission -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, IdentityGovernance, Applications, HybridIdentity, Monitoring
```

Run a narrower query when the customer approves only selected modules:

```powershell
Get-ZTAssessRequiredPermission -Modules Identity, ConditionalAccess
```

## Consent Principles

- Request only the modules required for the engagement scope.
- Prefer delegated read-only Graph permissions for consultant-led interactive assessments. For repeatable and unattended (CI / headless) runs, certificate-based app-only authentication is preferred and is the default for `Connect-ZTAssessment` — see the subsection below and [`Authentication.md`](Authentication.md).
- Do not add Graph write scopes for assessment checks, reporting, or remediation roadmap generation.
- Record any missing scope as an engagement limitation. The module should mark dependent checks `NotAssessed` rather than failing the whole run.
- Treat beta endpoint requirements as collection dependencies that can degrade gracefully if Microsoft changes response shape or availability.

## Application Permissions (App-Only / CBA)

Certificate-based authentication is app-only, so the assessment app is granted **Application** permissions rather than delegated scopes. The identifiers are the **same** as the delegated scopes for each module, but as Application roles they require **Global Administrator consent**.

- The required app roles for the selected modules are resolved at runtime, so the granted set stays aligned with the module → scope map in `source/Settings/permissions.psd1`.
- Provision the app with the repo-local `EntraZTAssess.Provisioning` module under `scripts/` (`Import-Module ./scripts/EntraZTAssess.Provisioning`): `New-ZTAssessCertificate` creates the certificate and `New-ZTAssessAppRegistration` creates the read-only app, grants the Application permissions, and emits the admin-consent URL (or grants consent programmatically with `-GrantAdminConsent`). `Get-ZTAssessProvisioningStep` (in the installed module) lists these steps.
- The provisioning module itself needs elevated **one-time setup** permissions (`Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Directory.Read.All`). These are setup-only and are **not** assessment scopes; the assessment app holds only the read-only permissions.
- The full per-module Application-permissions table is in [`Authentication.md`](Authentication.md).

## Interpreting Missing Permissions

Missing permissions can affect collection completeness. When a collector cannot gather a required snapshot, dependent checks should return `NotAssessed` findings with a reason such as the missing scope or unavailable licence. These findings remain visible in `TechnicalReport.html` and should be reviewed with the customer.

## Delivery And Redaction

Permission guidance is separate from report redaction. `Export-ZTAssessReport -RedactUserIdentifiers` redacts user-identifying values in generated report artifacts only; it does not change required scopes, collection behavior, raw snapshots, findings, scores, or the run manifest.

## Source Of Truth

For implementation changes, update `source/Settings/permissions.psd1` and the relevant check metadata together. Keep `README.md`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, and `CHANGELOG.md` synchronized whenever permission behavior changes.
