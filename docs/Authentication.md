# Authentication

`Get-EntraZTAssess` connects to Microsoft Graph through `Connect-ZTAssessment`. As of this release, **certificate-based authentication (CBA)** — an app-only sign-in using a certificate rather than a client secret — is the **default** method. When no CBA configuration is found, `Connect-ZTAssessment` automatically falls back to interactive delegated sign-in, so the [Quick Start](../README.md#quick-start) keeps working with zero authentication arguments.

Certificate-based, app-only authentication is the preferred method for repeatable and unattended (CI / headless) runs: it needs no interactive prompt, uses a certificate instead of a shared secret, and holds only the read-only Application permissions listed below.

## Authentication Methods And Precedence

`Connect-ZTAssessment` resolves how to authenticate in this order:

1. **Certificate-based (app-only, default).** Used whenever a CBA configuration can be resolved (see [CBA Configuration Resolution](#cba-configuration-resolution)).
2. **Interactive delegated (fallback).** Used automatically when no CBA configuration is found. Pass `-NoInteractiveFallback` to turn this fallback off and fail hard instead (see [CI And Headless Usage](#ci-and-headless-usage)).

Important behaviours:

- If a CBA configuration **is** present but the connection fails, the error surfaces — there is **no silent fallback** to interactive sign-in. This prevents an unattended run from quietly downgrading to a prompt.
- Fallback to interactive sign-in happens **only** when no CBA configuration can be resolved at all.

### CBA Configuration Resolution

CBA settings are resolved from the first source that supplies them, in this order:

1. **Explicit parameters** on `Connect-ZTAssessment` (`-TenantId`, `-ClientId`, `-CertificateThumbprint`, `-CertificatePath`, `-CertificatePassword`, `-Environment`).
2. **Environment variables:**
   - `ZTASSESS_TENANTID`
   - `ZTASSESS_CLIENTID`
   - `ZTASSESS_CERT_THUMBPRINT`
   - `ZTASSESS_CERT_PATH`
   - `ZTASSESS_ENVIRONMENT`
3. **Non-secret configuration file** at `~/.ztassess/auth.json`.

### Parameters

`Connect-ZTAssessment` uses these parameter sets: `Auto` (default), `AppOnlyThumbprint`, `AppOnlyCertificate`, and `Delegated`.

| Parameter | Purpose |
|---|---|
| `-TenantId` | Target tenant (GUID or verified domain). |
| `-ClientId` | Application (client) ID of the assessment app registration. |
| `-CertificateThumbprint` | Thumbprint of a certificate in the OS certificate store (**Windows-only** path). |
| `-CertificatePath` | Path to a password-protected PFX (cross-platform; macOS/Linux and Windows). |
| `-CertificatePassword` | `SecureString` protecting the PFX. Never persisted. |
| `-Environment` | Graph national cloud environment (for example `Global`, `USGov`). |
| `-Organization` | The verified domain Exchange Online / Security & Compliance (IPPS) requires, for modules that need that surface (see [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection)). |
| `-NoInteractiveFallback` | Forces a hard failure when no CBA configuration is found instead of falling back to interactive sign-in. Intended for headless / CI. |

The existing `-ClientId` / `-CertificateThumbprint` combination continues to work for the Windows certificate-store path.

## Exchange Online / Security & Compliance Connection

Some modules (`ThreatProtection`, `SecurityCompliance`, `DataProtection`, `Collaboration`) read data that does not exist in Microsoft Graph — Purview DLP/retention/label policies, Exchange sharing and transport rules, and Defender for Office 365 policies (Safe Links, Safe Attachments, anti-phishing) are only available through Exchange Online / Security & Compliance (IPPS) PowerShell cmdlets. `Connect-ZTAssessment` establishes this as a **second, independent, read-only connection**, alongside Microsoft Graph, only when a selected module requires it. All four modules are fully implemented (4 checks each). `Collaboration`'s v1 scope covers Exchange sharing policies and transport rules only — SharePoint tenant sharing settings (`Get-SPOTenant`) are out of scope, since they require a third connection surface (`Connect-SPOService`) this module does not establish.

Key behaviours:

- **Lazy.** The connection is attempted only when `Get-ZTAssessModuleCatalog` reports `RequiresExchangeOnline` for a selected module. Engagements that only use Graph-only modules never touch this surface.
- **App-only only.** This surface reuses the same certificate as the Microsoft Graph app-only connection. It is **not available** for delegated/device-code sign-in; affected checks are reported as `NotAssessed` in that case.
- **Never fails the overall connection.** If Exchange Online / IPPS fails to connect (or was skipped because no `-Organization` could be resolved), `Connect-ZTAssessment` still succeeds for Graph-only modules. `ExchangeOnlineConnected` and `ExchangeOnlineWarning` on the returned connection summary report the outcome.
- **Read-only, allow-listed.** All Exchange Online / IPPS calls flow through `Invoke-ZTAssessExoRequestWrapper`, which only permits the `Get-*` cmdlets returned by `Get-ZTAssessExoAllowedCmdletName`. The session itself is also scoped to that allow-list via `-CommandName`, so write cmdlets are never imported into the session. `tests/QA/ReadOnly.tests.ps1` statically enforces both.
- **`-Organization` resolution order**: explicit `-Organization` parameter → `ZTASSESS_ORGANIZATION` environment variable → `Organization` in `~/.ztassess/auth.json` → a domain-looking `-TenantId` used as-is → derived from the connected Graph tenant's initial verified domain. This last fallback means Graph must connect successfully before Exchange Online / IPPS is attempted, which is always the case since Graph connects first.
- **Granting the role groups is a separate, optional provisioning step.** The assessment module itself (`source/`) never grants Exchange Online / Security & Compliance role groups — it only ever calls the read-only, allow-listed `Get-*` cmdlet surface described above. `Get-ZTAssessExchangeOnlineRoleGuidance` (in the `EntraZTAssess.Provisioning` module) lists the role groups each module needs; `Grant-ZTAssessExchangeOnlineRole` (also in `EntraZTAssess.Provisioning`) can optionally grant them, but only when explicitly run by an administrator with sufficient Exchange Online / Security & Compliance rights — see [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection).

```powershell
Connect-ZTAssessment -Modules ThreatProtection -Organization 'contoso.onmicrosoft.com'
```

## CBA Setup — Four Steps

Setup is a one-time, administrator-run activity. The provisioning commands live in the repository as the `EntraZTAssess.Provisioning` module under `scripts/` and are **not** shipped with the assessment module (they are not installed by `Install-Module`). Import it first, then run the functions. From inside the installed module, `Get-ZTAssessProvisioningStep` lists these steps.

### 1. Generate a certificate

```powershell
Import-Module ./scripts/EntraZTAssess.Provisioning
New-ZTAssessCertificate
```

`New-ZTAssessCertificate` creates a platform-agnostic self-signed certificate using the .NET `CertificateRequest` API and produces two files:

- `EntraZTAssess.cer` — the public certificate, uploaded to the app registration.
- `EntraZTAssess.pfx` — the password-protected private key, used at connection time on macOS/Linux.

### 2. Register the application

```powershell
New-ZTAssessAppRegistration -TenantId '<tenant>' -CertificatePath ~/.ztassess/EntraZTAssess.cer
```

`New-ZTAssessAppRegistration` creates the enterprise application and grants the **read-only Application permissions** listed below (the required app roles are resolved at runtime). By default it emits the admin-consent URL. It writes the non-secret connection details to `~/.ztassess/auth.json`.

### 3. Grant admin consent

Open the admin-consent URL emitted in step 2 signed in as a **Privileged Role Administrator** (or Global Administrator), or grant consent programmatically:

```powershell
New-ZTAssessAppRegistration -TenantId '<tenant>' -CertificatePath ~/.ztassess/EntraZTAssess.cer -GrantAdminConsent
```

All Application permissions used by the assessment are on Microsoft Graph, so admin consent requires **Privileged Role Administrator** or Global Administrator. Application Administrator and Cloud Application Administrator can register the app and add the requested app roles in step 2, but Microsoft explicitly excludes Microsoft Graph application permissions from what those two roles can consent to — see [Cloud Application Administrator](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#cloud-application-administrator). If the organization won't grant Global Administrator, request a time-bound Privileged Role Administrator assignment (ideally via PIM) for this one consent step, or have an existing Privileged Role Administrator run it.

### 3a. Grant Exchange Online / Purview role groups (only for SecurityCompliance, Collaboration, DataProtection, ThreatProtection)

If the engagement scope includes any of these four modules, the app's service principal needs the Exchange Online / Security & Compliance role groups listed by:

```powershell
Get-ZTAssessExchangeOnlineRoleGuidance -Modules ThreatProtection
```

The assessment module itself only reads Exchange Online / Purview configuration through a read-only, allow-listed cmdlet surface (see [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection)) — it never grants these roles itself. Granting the roles is a separate, one-time administrative action that can be done either:

- **Manually**, by the tenant's own Exchange administrator, via the Microsoft Purview / Exchange admin center or `Add-RoleGroupMember`; or
- **With `Grant-ZTAssessExchangeOnlineRole`**, run by an account that holds sufficient Exchange Online / Security & Compliance administrative rights (for example Organization Management or a delegated Exchange Administrator):

  ```powershell
  Grant-ZTAssessExchangeOnlineRole -AppId '<clientId>' -ServicePrincipalObjectId '<spObjectId>' `
      -Organization 'contoso.onmicrosoft.com' -UserPrincipalName 'admin@contoso.onmicrosoft.com' `
      -Modules ThreatProtection
  ```

  `Grant-ZTAssessExchangeOnlineRole` connects to Exchange Online / IPPS as the **calling administrator** (interactive delegated sign-in — `-UserPrincipalName` just skips the account picker), never as the app being granted roles: that app may not yet be authorized to connect at all, which is exactly the gap this function closes, so authenticating as the app would be circular. Run it signed in as an account that already holds sufficient Exchange Online / Security & Compliance administrative rights.

  `-ServicePrincipalObjectId` (the app's Entra ID service principal object ID, from `New-ZTAssessAppRegistration`'s output or the Entra admin center) is only required the first time — it is used to create the app's Exchange Online-side service principal with `New-ServicePrincipal`, which does **not** happen automatically just from consenting to `Exchange.ManageAsApp` or from Graph admin consent. Re-running the function afterward skips creating a duplicate service principal and skips entries the app is already granted.

  Not every entry in the table below is actually a role group. Verified against a live tenant: `Security Reader` is a genuine role group; `View-Only Configuration` and `View-Only Recipients` are **management roles** visible in the Exchange Online session; `View-Only Retention Management` and `View-Only DLP Compliance Management` are management roles visible only in the Security & Compliance / IPPS session. Management roles require `New-ManagementRoleAssignment -App` instead of `Add-RoleGroupMember`. `Grant-ZTAssessExchangeOnlineRole` tries the role-group path first, falls back to the management-role path against the same connection, and as a last resort retries against a separately-established IPPS connection — which is what resolves the two Purview retention/DLP roles, since they exist only in that RBAC namespace. Each entry is granted with whichever mechanism actually matches what it is. A grant that still fails after every mechanism is recorded in the function's `FailedGrants` output rather than aborting the rest of the run.

  This function performs Exchange Online RBAC **write** operations and therefore lives in `EntraZTAssess.Provisioning`, alongside `New-ZTAssessAppRegistration` — never in the read-only assessment module under `source/`.

### 4. Connect

```powershell
# CBA settings auto-resolve from ~/.ztassess/auth.json (or env vars / explicit params)
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, `
    IdentityGovernance, Applications, HybridIdentity, Monitoring, Defender
```

## Cross-Platform Certificate Guidance

The certificate store / thumbprint path is **Windows-only**. On macOS and Linux, use a password-protected PFX.

| Platform | Method |
|---|---|
| macOS / Linux | Load `EntraZTAssess.pfx` into an `X509Certificate2` (using `-CertificatePath` and `-CertificatePassword`) and pass it to `Connect-MgGraph -Certificate`. |
| Windows | Either the OS certificate store (`-CertificateThumbprint`) **or** the PFX (`-CertificatePath` / `-CertificatePassword`). |

## Read-Only Application Permissions

The CBA app registration holds only the read-only permissions below. They use the **same identifiers as the delegated scopes** but are granted as **Application** roles. Because they are all Microsoft Graph application permissions, consent requires **Privileged Role Administrator** or Global Administrator (see [step 3](#3-grant-admin-consent)). Request only the permissions for the modules in the engagement scope.

| Module | Application permissions (read-only) |
|---|---|
| Core (always) | `Organization.Read.All`, `Directory.Read.All` |
| Identity | `UserAuthenticationMethod.Read.All`, `Reports.Read.All`, `Policy.Read.All`, `AuditLog.Read.All` |
| ConditionalAccess | `Policy.Read.All`, `Agreement.Read.All` |
| PrivilegedAccess | `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory` |
| IdentityGovernance | `AccessReview.Read.All`, `EntitlementManagement.Read.All`, `LifecycleWorkflows.Read.All`, `Policy.Read.All` |
| Applications | `Application.Read.All`, `Policy.Read.All` |
| HybridIdentity | `OnPremDirectorySynchronization.Read.All`, `Directory.Read.All` |
| Devices | `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementApps.Read.All` |
| Monitoring | `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`, `AuditLog.Read.All`, `SecurityIdentitiesSensors.Read.All` |
| Defender | `SecurityEvents.Read.All`, `SecurityAlert.Read.All` |
| CloudAppSecurity | `SecurityEvents.Read.All` |

CloudAppSecurity shares its collected data with Defender (no separate collector) and is a Graph-only, best-effort Secure Score proxy — see the note under [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection) for why Microsoft Graph cannot provide a genuine Defender for Cloud Apps assessment. The Sentinel module uses Azure Reader via ARM and requires no Graph permissions.

### Exchange Online / Security & Compliance Role Groups

The four modules below hold no Graph scopes; instead they need Exchange Online / Security & Compliance (IPPS) role groups and management roles granted to the app's service principal (see [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection)). **The read-only assessment module (`source/`) cannot and does not grant these roles itself** — treat this table as pre-engagement guidance, not an enforced or verified permission set. Despite the naming, only one entry is actually a role group: verified against a live tenant, `Security Reader` is a genuine role group; `View-Only Configuration` and `View-Only Recipients` are management roles visible in the Exchange Online session; `View-Only Retention Management` and `View-Only DLP Compliance Management` are management roles visible only in the Security & Compliance / IPPS session. Management roles are granted with a different cmdlet (`New-ManagementRoleAssignment -App` rather than `Add-RoleGroupMember`) — `Grant-ZTAssessExchangeOnlineRole` handles this automatically, including the IPPS fallback for the two Purview-only roles (see [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection)), but a manual grant needs the right cmdlet and the right session for the right entry. Exact names may still vary by tenant license and national cloud; confirm with `Get-RoleGroup` / `Get-ManagementRole` in the tenant's Purview / Exchange admin center before assigning them. Granting them is a separate, optional step performed either manually by the tenant's own Exchange administrator, or with `Grant-ZTAssessExchangeOnlineRole` in the `EntraZTAssess.Provisioning` module.

| Module | Exchange Online / IPPS role groups (read-only guidance) |
|---|---|
| SecurityCompliance | `View-Only Retention Management`, `View-Only Configuration` |
| Collaboration | `View-Only Recipients`, `View-Only Configuration` |
| DataProtection | `View-Only DLP Compliance Management`, `View-Only Configuration` |
| ThreatProtection | `Security Reader`, `View-Only Configuration` |

### One-Time Setup Permissions (Elevated — Not Assessment Scopes)

`New-ZTAssessAppRegistration` itself needs elevated permissions to create the app and, optionally, grant app roles. These are requested least-privilege, only as needed:

- `Application.ReadWrite.All` — always requested; creates the application and service principal.
- `AppRoleAssignment.ReadWrite.All` — requested **only** when `-GrantAdminConsent` is supplied, since it is only exercised when creating app role assignments directly.

These are **setup-only** and are used by the operator running the provisioning module. They are **not** assessment scopes and are **not** held by the assessment app. The assessment app holds only the read-only permissions in the table above.

Re-running `New-ZTAssessAppRegistration` against a tenant that already has an application registered under the same `-DisplayName` does not silently create a duplicate: it stops with an actionable error naming the existing application's `AppId` unless `-Force` is supplied.

## Configuration File Schema

`~/.ztassess/auth.json` holds **non-secret** connection details only. It never stores the certificate password.

```json
{
  "TenantId": "00000000-0000-0000-0000-000000000000",
  "ClientId": "11111111-1111-1111-1111-111111111111",
  "CertificateThumbprint": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
  "CertificatePath": "~/.ztassess/EntraZTAssess.pfx",
  "Environment": "Global",
  "Organization": "contoso.onmicrosoft.com"
}
```

Provide the certificate password (for a PFX) at connection time via `-CertificatePassword` or an equivalent secure mechanism — it is never written to `auth.json`. `Organization` is optional and only used when a selected module requires Exchange Online / Security & Compliance (IPPS); omit it to rely on the other resolution fallbacks (see [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection)).

## CI And Headless Usage

For unattended runs, supply CBA configuration via environment variables (or explicit parameters) and disable the interactive fallback so a misconfiguration fails fast instead of blocking on a prompt:

```powershell
$env:ZTASSESS_TENANTID        = '00000000-0000-0000-0000-000000000000'
$env:ZTASSESS_CLIENTID        = '11111111-1111-1111-1111-111111111111'
$env:ZTASSESS_CERT_PATH       = '/secure/EntraZTAssess.pfx'
$env:ZTASSESS_ENVIRONMENT     = 'Global'
$env:ZTASSESS_ORGANIZATION    = 'contoso.onmicrosoft.com'   # only needed for SecurityCompliance/Collaboration/DataProtection/ThreatProtection
# Certificate password supplied securely at connection time.

Connect-ZTAssessment -Modules Identity, ConditionalAccess -NoInteractiveFallback
```

With `-NoInteractiveFallback`, a missing configuration is a hard error rather than a silent downgrade to interactive sign-in.

## Security Notes

- Authentication uses a **certificate, not a client secret** — there is no shared secret to leak or rotate on a short cycle.
- The **certificate password is never persisted**. `~/.ztassess/auth.json` contains non-secret connection details only.
- Provisioning writes (app registration, role grants, config file) live **only** in the repository `scripts/` folder, run as a one-time administrator setup. The module under `source/` remains **read-only** — it performs no directory writes and requests no write scopes.
- Grant only the Application permissions required for the modules in scope, and record any deferred scope as an engagement limitation (see [`PermissionsGuidance.md`](PermissionsGuidance.md)).
- The Exchange Online / Security & Compliance (IPPS) surface used by the **assessment module** is equally read-only: all calls flow through an allow-listed `Get-*` cmdlet wrapper, and the session itself is scoped to that allow-list so write cmdlets are never imported. Granting the Exchange Online role groups the app needs is a separate, optional provisioning action — either performed manually by the tenant's own Exchange administrator, or with `Grant-ZTAssessExchangeOnlineRole` in `EntraZTAssess.Provisioning`, run by an account with sufficient Exchange Online / Security & Compliance rights. That function, like `New-ZTAssessAppRegistration`, lives outside `source/` precisely because it performs writes.
