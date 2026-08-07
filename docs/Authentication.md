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
| `-NoInteractiveFallback` | Forces a hard failure when no CBA configuration is found instead of falling back to interactive sign-in. Intended for headless / CI. |

The existing `-ClientId` / `-CertificateThumbprint` combination continues to work for the Windows certificate-store path.

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

Open the admin-consent URL emitted in step 2 as a Global Administrator, or grant consent programmatically:

```powershell
New-ZTAssessAppRegistration -TenantId '<tenant>' -CertificatePath ~/.ztassess/EntraZTAssess.cer -GrantAdminConsent
```

All Application permissions used by the assessment require Global Administrator consent.

### 4. Connect

```powershell
# CBA settings auto-resolve from ~/.ztassess/auth.json (or env vars / explicit params)
Connect-ZTAssessment -Modules Identity, ConditionalAccess, PrivilegedAccess, Devices, `
    IdentityGovernance, Applications, HybridIdentity, Monitoring
```

## Cross-Platform Certificate Guidance

The certificate store / thumbprint path is **Windows-only**. On macOS and Linux, use a password-protected PFX.

| Platform | Method |
|---|---|
| macOS / Linux | Load `EntraZTAssess.pfx` into an `X509Certificate2` (using `-CertificatePath` and `-CertificatePassword`) and pass it to `Connect-MgGraph -Certificate`. |
| Windows | Either the OS certificate store (`-CertificateThumbprint`) **or** the PFX (`-CertificatePath` / `-CertificatePassword`). |

## Read-Only Application Permissions

The CBA app registration holds only the read-only permissions below. They use the **same identifiers as the delegated scopes** but are granted as **Application** roles. All require Global Administrator consent. Request only the permissions for the modules in the engagement scope.

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

The Sentinel module uses Azure Reader via ARM and requires no Graph permissions.

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
  "Environment": "Global"
}
```

Provide the certificate password (for a PFX) at connection time via `-CertificatePassword` or an equivalent secure mechanism — it is never written to `auth.json`.

## CI And Headless Usage

For unattended runs, supply CBA configuration via environment variables (or explicit parameters) and disable the interactive fallback so a misconfiguration fails fast instead of blocking on a prompt:

```powershell
$env:ZTASSESS_TENANTID        = '00000000-0000-0000-0000-000000000000'
$env:ZTASSESS_CLIENTID        = '11111111-1111-1111-1111-111111111111'
$env:ZTASSESS_CERT_PATH       = '/secure/EntraZTAssess.pfx'
$env:ZTASSESS_ENVIRONMENT     = 'Global'
# Certificate password supplied securely at connection time.

Connect-ZTAssessment -Modules Identity, ConditionalAccess -NoInteractiveFallback
```

With `-NoInteractiveFallback`, a missing configuration is a hard error rather than a silent downgrade to interactive sign-in.

## Security Notes

- Authentication uses a **certificate, not a client secret** — there is no shared secret to leak or rotate on a short cycle.
- The **certificate password is never persisted**. `~/.ztassess/auth.json` contains non-secret connection details only.
- Provisioning writes (app registration, role grants, config file) live **only** in the repository `scripts/` folder, run as a one-time administrator setup. The module under `source/` remains **read-only** — it performs no directory writes and requests no write scopes.
- Grant only the Application permissions required for the modules in scope, and record any deferred scope as an engagement limitation (see [`PermissionsGuidance.md`](PermissionsGuidance.md)).
