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
- **App-only or device-code.** In app-only mode this surface reuses the same certificate as the Microsoft Graph app-only connection. In device-code mode (`Connect-ZTAssessment -UseDeviceCode`), the Security & Compliance session-establishing cmdlet has no device-code switch of its own (unlike its Exchange Online counterpart), so a separate Exchange Online device-code sign-in is performed and the resulting access token is used for both surfaces. The default client ID used for that sign-in (`Settings/settings.psd1` → `ExchangeOnline.DeviceCodeClientId`) is the well-known Microsoft first-party "Microsoft Exchange REST API Based PowerShell" public client that the ExchangeOnlineManagement module's own device-code switch already uses internally — no new app registration, public-client-flow toggle, or `Exchange.ManageAsApp` grant is required. A tenant whose Conditional Access policy blocks sign-in by well-known native client IDs can override `ExchangeOnline.DeviceCodeClientId` (and `DeviceCodeScope`) with their own registered public-client app. It remains **not available** for plain interactive delegated sign-in (no `-UseDeviceCode`); affected checks are reported as `NotAssessed` in that case.
- **Never fails the overall connection.** If Exchange Online / IPPS fails to connect (or was skipped because no `-Organization` could be resolved), `Connect-ZTAssessment` still succeeds for Graph-only modules. `ExchangeOnlineConnected` and `ExchangeOnlineWarning` on the returned connection summary report the outcome.
- **Read-only, allow-listed.** All Exchange Online / IPPS calls flow through `Invoke-ZTAssessExoRequestWrapper`, which only permits the `Get-*` cmdlets returned by `Get-ZTAssessExoAllowedCmdletName`. The session itself is also scoped to that allow-list via `-CommandName`, so write cmdlets are never imported into the session. `tests/QA/ReadOnly.tests.ps1` statically enforces both.
- **`-Organization` resolution order**: explicit `-Organization` parameter → `ZTASSESS_ORGANIZATION` environment variable → `Organization` in `~/.ztassess/auth.json` → a domain-looking `-TenantId` used as-is → derived from the connected Graph tenant's initial verified domain. This last fallback means Graph must connect successfully before Exchange Online / IPPS is attempted, which is always the case since Graph connects first.
- **Granting the role groups is a separate, optional provisioning step — app-only mode only.** The assessment module itself (`source/`) never grants Exchange Online / Security & Compliance role groups — it only ever calls the read-only, allow-listed `Get-*` cmdlet surface described above. `Get-ZTAssessExchangeOnlineRoleGuidance` (in the `EntraZTAssess.Provisioning` module) lists the role groups each module needs; `Grant-ZTAssessExchangeOnlineRole` (also in `EntraZTAssess.Provisioning`) can optionally grant them, but only when explicitly run by an administrator with sufficient Exchange Online / Security & Compliance rights — see [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection). **This step only applies to the app-only (CBA) connection**: it authorizes the app registration's own service principal, which app-only mode connects as. **Device-code mode never connects as an app** — both the Graph and Exchange Online / IPPS sign-ins authenticate as the signed-in consultant, so `Grant-ZTAssessExchangeOnlineRole` is not part of that workflow at all. What matters instead is whether the consultant's own account already holds the equivalent Exchange Online / Security & Compliance permissions (see [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection) for the note on device-code mode) — if it doesn't, those checks degrade to `NotAssessed` rather than failing the connection.

```powershell
Connect-ZTAssessment -Modules ThreatProtection -Organization 'contoso.onmicrosoft.com'
```

## CBA Setup — Four Steps

Setup is a one-time, administrator-run activity. The provisioning commands live in the repository as the `EntraZTAssess.Provisioning` module under `scripts/` and are **not** shipped with the assessment module (they are not installed by `Install-Module`). Import it first, then run the functions. From inside the installed module, `Get-ZTAssessProvisioningStep` lists these steps.

**This entire section applies only when the engagement uses app-only (CBA) authentication.** An engagement running `Connect-ZTAssessment -UseDeviceCode` skips all four steps below — there is no app registration, no certificate, no admin consent, and no `Grant-ZTAssessExchangeOnlineRole` step, because device-code mode never connects as an app at all (see [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection)).

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

This step's own sign-in is interactive and delegated (it is a one-time, admin-run setup action, separate from the app-only connection the assessment itself uses). If the tenant's Conditional Access policy blocks interactive browser sign-in, add `-UseDeviceCode` to use the OAuth device-code flow instead:

```powershell
New-ZTAssessAppRegistration -TenantId '<tenant>' -CertificatePath ~/.ztassess/EntraZTAssess.cer -UseDeviceCode
```

### 3. Grant admin consent

Open the admin-consent URL emitted in step 2 signed in as a **Privileged Role Administrator** (or Global Administrator), or grant consent programmatically:

```powershell
New-ZTAssessAppRegistration -TenantId '<tenant>' -CertificatePath ~/.ztassess/EntraZTAssess.cer -GrantAdminConsent
```

All Application permissions used by the assessment are on Microsoft Graph, so admin consent requires **Privileged Role Administrator** or Global Administrator. Application Administrator and Cloud Application Administrator can register the app and add the requested app roles in step 2, but Microsoft explicitly excludes Microsoft Graph application permissions from what those two roles can consent to — see [Cloud Application Administrator](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#cloud-application-administrator). If the organization won't grant Global Administrator, request a time-bound Privileged Role Administrator assignment (ideally via PIM) for this one consent step, or have an existing Privileged Role Administrator run it.

### 3a. Grant Exchange Online / Purview role groups (only for SecurityCompliance, Collaboration, DataProtection, ThreatProtection)

**Not required for device-code mode.** This entire step exists to authorize the *app's* service principal for the app-only (CBA) connection — `Grant-ZTAssessExchangeOnlineRole` connects as the calling administrator specifically to grant roles to that app. Device-code mode (`Connect-ZTAssessment -UseDeviceCode`) never connects as an app; both its Graph and Exchange Online / IPPS sign-ins authenticate as whichever consultant account completes the device-code prompts. There is no service principal for this step to grant roles to, so skip it entirely for a device-code engagement.

For device-code engagements, what matters instead is whether the **consultant's own signed-in account** already holds Exchange Online / Security & Compliance permissions equivalent to the role groups/management roles listed below (`Security Reader`, `View-Only Configuration`, `View-Only Recipients`, `View-Only Retention Management`, `View-Only DLP Compliance Management`) — typically already true for a Global Administrator, and otherwise something the tenant's own Exchange/Purview administrator assigns to that consultant's account directly (via role group membership, ahead of the engagement) rather than anything this toolkit runs. If the account lacks a given permission, the dependent checks degrade to `NotAssessed` rather than the connection failing.

If the engagement scope includes any of these four modules **and is using app-only (CBA) authentication**, the app's service principal needs the Exchange Online / Security & Compliance role groups listed by:

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

  Not every entry in the table below is actually a role group, and not every management role supports direct application assignment. Verified against a live tenant: `Security Reader` is a genuine role group; `View-Only Configuration` and `View-Only Recipients` are management roles that accept direct `New-ManagementRoleAssignment -App` assignment; `View-Only Retention Management` and `View-Only DLP Compliance Management` are management roles visible only in the Security & Compliance / IPPS session, and `New-ManagementRoleAssignment -App` fails for both with `"<role>" management role can't be found` against **both** the Exchange Online and the IPPS connection — direct application assignment is simply not supported for them. `Grant-ZTAssessExchangeOnlineRole` tries, in order: the role-group path; direct management-role assignment against Exchange Online; the same direct assignment again against a lazily-established IPPS connection; and, only if every prior mechanism fails, the Microsoft-documented workaround of creating a dedicated role group scoped to exactly that one management role (`New-RoleGroup -Name 'EntraZTAssess - <role>' -DisplayName 'EntraZTAssess - <role>' -Roles '<role>'`, deliberately without `-Members` — confirmed live that parameter does not reliably accept a service principal identity, and `-DisplayName` is passed explicitly because `New-RoleGroup` has been observed to leave it empty otherwise, which fails the next step's validation) and then adding the app to it with a separate `Add-RoleGroupMember` call — which is what actually resolves the two Purview retention/DLP roles. It stops at the first mechanism that succeeds and reuses (rather than recreates) a dedicated role group on later runs. A grant that still fails after every mechanism is recorded in the function's `FailedGrants` output rather than aborting the rest of the run.

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

The four modules below hold no Graph scopes; instead they need Exchange Online / Security & Compliance (IPPS) role groups and management roles granted to the app's service principal (see [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection)). **The read-only assessment module (`source/`) cannot and does not grant these roles itself** — treat this table as pre-engagement guidance, not an enforced or verified permission set. Despite the naming, only one entry is actually a role group: verified against a live tenant, `Security Reader` is a genuine role group; `View-Only Configuration` and `View-Only Recipients` are management roles that accept direct `New-ManagementRoleAssignment -App` assignment; `View-Only Retention Management` and `View-Only DLP Compliance Management` are management roles visible only in the Security & Compliance / IPPS session, and direct `-App` assignment fails for both (`"<role>" management role can't be found`) against both the Exchange Online and the IPPS connection — they instead require the Microsoft-documented workaround of a dedicated role group scoped to just that role. `Grant-ZTAssessExchangeOnlineRole` handles all of this automatically, trying the role-group, direct-assignment, IPPS-retry, and dedicated-role-group mechanisms in order (see [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection)), but a manual grant needs the right cmdlet, the right session, and possibly a dedicated role group for the right entry. Exact names may still vary by tenant license and national cloud; confirm with `Get-RoleGroup` / `Get-ManagementRole` in the tenant's Purview / Exchange admin center before assigning them. Granting them is a separate, optional step performed either manually by the tenant's own Exchange administrator, or with `Grant-ZTAssessExchangeOnlineRole` in the `EntraZTAssess.Provisioning` module.

| Module | Exchange Online / IPPS role groups (read-only guidance) |
|---|---|
| SecurityCompliance | `View-Only Retention Management`, `View-Only Configuration` |
| Collaboration | `View-Only Recipients`, `View-Only Configuration` |
| DataProtection | `View-Only DLP Compliance Management`, `View-Only Configuration` |
| ThreatProtection | `Security Reader`, `View-Only Configuration` |

**Where to assign these manually — the four roles don't all live in the same admin surface:**

- **`View-Only Configuration` and `View-Only Recipients`** are classic Exchange management roles, assigned in the **Exchange admin center**: `admin.exchange.microsoft.com` (or the classic EAC) → **Roles** → **Admin roles** → create or edit a role group (the built-in **View-Only Organization Management** role group already has both) → add the role on the **Roles** tab → add the user on the **Assigned**/**Members** tab. PowerShell equivalent: `New-RoleGroup`/`Add-RoleGroupMember`, or `New-ManagementRoleAssignment -Role 'View-Only Configuration' -User <upn>`, against a plain Exchange Online session.
- **`View-Only Retention Management` and `View-Only DLP Compliance Management`** do **not exist in the EAC at all**. They're Microsoft Purview/Defender compliance roles, assigned in the **Microsoft Purview compliance portal**: `purview.microsoft.com` (or `compliance.microsoft.com`; some tenants still show this as the classic **Security & Compliance Center**) → **Roles and scopes** → **Permissions** → create/edit a role group → add the role on the **Roles** tab → add the user on the **Members** tab. PowerShell equivalent: the same `Add-RoleGroupMember`, but run against a **Security & Compliance (IPPS)** session (`Connect-IPPSSession`) — this is exactly why direct `-App`/`-User` assignment for these two fails against a plain Exchange Online connection but can work against IPPS, and why both still need the dedicated-role-group workaround for an app service principal (see the note above).

A consultant who is already a Global Administrator holds all four implicitly. A more scoped admin account needs `View-Only Configuration`/`View-Only Recipients` granted via the EAC and, separately, `View-Only Retention Management`/`View-Only DLP Compliance Management` granted via the Purview compliance portal — two different admin surfaces, not one. This applies whether the role is being granted to a human account (device-code engagements — see [Exchange Online / Security & Compliance Connection](#exchange-online--security--compliance-connection)) or to an app's service principal (CBA engagements, via [step 3a](#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection)).

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
