# EntraZTAssess Provisioning Module

One-time, admin-run setup commands that create the Entra ID app registration and
certificate used by the EntraZTAssess assessment toolkit for unattended,
certificate-based (app-only) authentication. They are exposed as the advanced
functions `New-ZTAssessCertificate` and `New-ZTAssessAppRegistration` in the
repo-local `EntraZTAssess.Provisioning` module.

## Why these live outside the assessment module

The assessment module under `source/` carries a **read-only guarantee**: every
Graph call is funnelled through a wrapper that permits only `GET`, and
`tests/QA/ReadOnly.tests.ps1` statically forbids any write method, write scope,
or Graph write SDK cmdlet appearing anywhere under `source/`. Provisioning an
app registration is inherently a **write** operation (it creates directory
objects and grants permissions), so this module is kept here in `scripts/` to
preserve that guarantee. It is a deliberate, documented, one-time
administrative step.

**Distribution note:** `scripts/` is repository-based tooling. The
`EntraZTAssess.Provisioning` module is *not* shipped as part of the assessment
module when installed via `Install-Module`. Clone or download the repository to
import and run it. From inside the installed module, `Get-ZTAssessProvisioningStep`
lists these steps as discoverable guidance.

## Prerequisites

- PowerShell 7.0 or later (macOS, Linux, or Windows).
- For Step 2 only: the Microsoft Graph SDK
  (`Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser`)
  and an account that can create app registrations. Granting consent
  additionally requires a Global Administrator or Privileged Role Administrator.

## Step 1 — Create the certificate (any OS)

```powershell
Import-Module ./scripts/EntraZTAssess.Provisioning
New-ZTAssessCertificate
```

Prompts for a password and writes two files to `~/.ztassess`:

| File | Purpose |
| --- | --- |
| `EntraZTAssess.cer` | DER public certificate — uploaded to the app in Step 2. |
| `EntraZTAssess.pfx` | Password-protected private key — used by `Connect-ZTAssessment` for app-only auth. |

The script uses pure .NET cryptography, so it behaves identically on macOS,
Linux, and Windows and does **not** depend on the Windows-only
`New-SelfSignedCertificate`. The PFX password is never written to disk or logs.

## Step 2 — Register the application (admin)

```powershell
# The EntraZTAssess.Provisioning module imported in Step 1 exposes this function.
New-ZTAssessAppRegistration `
    -TenantId 'contoso.onmicrosoft.com' `
    -CertificatePath ~/.ztassess/EntraZTAssess.cer
```

This connects to Microsoft Graph with **elevated one-time setup scopes**
(`Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`,
`Directory.Read.All` — used only for provisioning, *not* by the assessment),
then:

1. Computes the read-only Graph permission union for the selected modules
   (default: all non-optional modules, plus the always-included Core).
2. Resolves each permission to its Microsoft Graph **application app role** GUID
   at runtime (nothing is hardcoded).
3. Creates the app registration and service principal, and uploads the public
   certificate as a verification credential.
4. Emits an **admin-consent URL** (it does not grant consent by default).
5. Writes a **non-secret** JSON config to `~/.ztassess/auth.json`:

   ```json
   {
     "TenantId": "contoso.onmicrosoft.com",
     "ClientId": "<appId>",
     "CertificateThumbprint": "<thumbprint>",
     "CertificatePath": "/Users/you/.ztassess/EntraZTAssess.pfx",
     "Environment": "Global"
   }
   ```

   No password or secret is ever written to this file.

Add `-GrantAdminConsent` to grant the permissions programmatically instead of
emitting the URL (requires a Global Administrator session).

## Step 3 — Approve admin consent (Global Administrator)

A Global Administrator opens the consent URL printed by Step 2 and approves the
requested read-only permissions. Until consent is granted, dependent checks are
reported as `NotAssessed`.

## Step 4 — Run assessments (normal users)

Once the app exists and consent is granted, run the assessment with
certificate-based authentication using the values recorded in
`~/.ztassess/auth.json`:

```powershell
Connect-ZTAssessment -Modules Identity, ConditionalAccess, Devices `
    -TenantId '<tenant>' -ClientId '<appId>' -CertificateThumbprint '<thumbprint>'
```

On macOS and Linux, load the certificate from the `.pfx` (the PFX password is
prompted for or supplied as a `SecureString`); no certificate store is required.
On Windows, the certificate may instead be referenced by thumbprint from the
`CurrentUser\My` store (run Step 1 with `-InstallToWindowsStore`).

## Required read-only application permissions

The default run (all non-optional modules) grants these 22 read-only Microsoft
Graph application permissions. **All require admin consent.**

| Permission |
| --- |
| `AccessReview.Read.All` |
| `Agreement.Read.All` |
| `Application.Read.All` |
| `AuditLog.Read.All` |
| `DeviceManagementApps.Read.All` |
| `DeviceManagementConfiguration.Read.All` |
| `DeviceManagementManagedDevices.Read.All` |
| `DeviceManagementServiceConfig.Read.All` |
| `Directory.Read.All` |
| `EntitlementManagement.Read.All` |
| `IdentityRiskEvent.Read.All` |
| `IdentityRiskyUser.Read.All` |
| `LifecycleWorkflows.Read.All` |
| `OnPremDirectorySynchronization.Read.All` |
| `Organization.Read.All` |
| `Policy.Read.All` |
| `Reports.Read.All` |
| `RoleAssignmentSchedule.Read.Directory` |
| `RoleEligibilitySchedule.Read.Directory` |
| `RoleManagement.Read.Directory` |
| `SecurityIdentitiesSensors.Read.All` |
| `UserAuthenticationMethod.Read.All` |

Narrow the set with `-Modules` (e.g. `-Modules Identity, Devices`) to grant only
what a specific engagement needs.

## macOS / Linux vs Windows certificate notes

- **macOS / Linux** have no reliable certificate store; use the `.pfx` with its
  password for certificate-based authentication.
- **Windows** can use the `.pfx` as well, or reference the certificate by
  thumbprint after importing it into `CurrentUser\My`
  (`New-ZTAssessCertificate -InstallToWindowsStore`).
