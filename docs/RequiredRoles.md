# Required Roles

This document lists the **Entra ID directory roles** and **Purview / Exchange
Online RBAC roles** used across the lifecycle of an `EntraZTAssess`
engagement. It complements [`PermissionsGuidance.md`](PermissionsGuidance.md)
(Graph scope catalogue) and [`Authentication.md`](Authentication.md)
(connection setup); this file focuses on *who needs to hold what role, and
when*. As with those documents, treat exact role/role-group names as
guidance — verify availability in the tenant's own Entra admin center /
Microsoft Purview compliance portal before assigning them, since names can
vary slightly by licence and national cloud.

Two lifecycle stages need roles, and they are held by **different**
identities:

1. **One-time provisioning** (app registration, admin consent, Exchange
   Online role grants) — performed by a human **administrator**, using the
   separately published `EntraZTAssess.Provisioning` module. Not part of the
   read-only `Get-EntraZTAssess` module.
2. **Assessment runs** — performed by whichever identity `Connect-ZTAssessment`
   authenticates as: the app's service principal (app-only / CBA, the
   default) or the signed-in consultant (`-UseDeviceCode`).

## 1. Entra ID Directory Roles

| Role | Used for | Who holds it | When |
|---|---|---|---|
| **Privileged Role Administrator** (or **Global Administrator**) | Granting admin consent to the assessment app's Microsoft Graph **Application** permissions | The consenting administrator | Once, during provisioning step 3 ([`Authentication.md` § 3](Authentication.md#3-grant-admin-consent)) |
| **Application Administrator** or **Cloud Application Administrator** | Creating the app registration and adding the requested app roles (`New-ZTAssessAppRegistration`) | The provisioning operator | Once, during provisioning steps 1–2 — **cannot** complete step 3 (consent to Graph application permissions is explicitly excluded from both roles per Microsoft's [least-privileged roles by task](https://learn.microsoft.com/entra/identity/role-based-access-control/delegate-by-task#enterprise-applications-least-privileged-roles)) |
| **Global Administrator** (device-code mode only) | Implicitly satisfies every Graph delegated scope and Exchange Online / Purview permission the assessment needs | The consultant running an interactive, device-code engagement | For the duration of the engagement; a lower-privileged delegated account works too if it separately holds the equivalent Entra + Exchange Online/Purview permissions listed below |
| No standing Entra role | Running `Connect-ZTAssessment` in app-only (CBA) mode day-to-day | The app's service principal | Every assessment run — the service principal itself holds only the read-only Graph **Application** permissions granted in step 3, no directory role |

Notes:

- The assessment app's Microsoft Graph permissions are all **Application**
  permissions (not Entra directory roles) — see
  [`Authentication.md` § "Application Permissions"](Authentication.md#application-permissions-app-only--cba)
  and [`PermissionsGuidance.md`](PermissionsGuidance.md) for the full
  per-module scope table. They are listed separately because Graph app roles
  and Entra directory roles are different authorization mechanisms, even
  though both are configured in Entra ID.
- `New-ZTAssessAppRegistration` (provisioning-time only) additionally needs
  `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, and
  `Directory.Read.All` — these are its own one-time setup permissions, held
  by the operator's account or granted to a bootstrap app, and are distinct
  from the read-only assessment scopes the target app ends up with.
- Request a **time-bound** Privileged Role Administrator assignment (ideally
  via PIM) for the one-time consent step if the organization won't grant
  standing Global Administrator.

## 2. Purview / Exchange Online RBAC Roles

Four modules — `SecurityCompliance`, `Collaboration`, `DataProtection`,
`ThreatProtection` — read configuration that does not exist in Microsoft
Graph and is collected exclusively through the read-only Exchange Online /
Security & Compliance (IPPS) connection surface. That surface needs these
roles/management roles granted to whichever identity is connecting:

| Module | Required roles |
|---|---|
| `SecurityCompliance` | `View-Only Retention Management`, `View-Only Configuration` |
| `Collaboration` | `View-Only Recipients`, `View-Only Configuration` |
| `DataProtection` | `View-Only DLP Compliance Management`, `View-Only Configuration` |
| `ThreatProtection` | `Security Reader`, `View-Only Configuration` |

Get the current list for the modules in scope, rather than copying from this
table, with:

```powershell
Get-ZTAssessExchangeOnlineRoleGuidance -Modules SecurityCompliance, Collaboration, DataProtection, ThreatProtection
```

### These are not all the same kind of thing

Despite the shared naming convention, only one of the four is a genuine role
group; verified against a live tenant:

- **`Security Reader`** — a genuine Entra/Exchange role group.
- **`View-Only Configuration`**, **`View-Only Recipients`** — classic
  Exchange management roles; accept direct `New-ManagementRoleAssignment -App`
  (or `-User`) assignment.
- **`View-Only Retention Management`**, **`View-Only DLP Compliance
  Management`** — Purview/Defender compliance management roles, visible only
  in a Security & Compliance (IPPS) session. Direct `-App`/`-User` assignment
  fails against both Exchange Online and IPPS with `"<role>" management role
  can't be found`; they require the Microsoft-documented workaround of a
  dedicated role group scoped to just that one role
  (`New-RoleGroup -Roles '<role>'` + `Add-RoleGroupMember`).

### Where to assign each role

The four roles don't live in one admin surface:

- **`View-Only Configuration`** and **`View-Only Recipients`** — assign in
  the **Exchange admin center** (`admin.exchange.microsoft.com`, or the
  classic EAC): **Roles → Admin roles** → create/edit a role group (the
  built-in **View-Only Organization Management** role group already has
  both) → add the role on **Roles** → add the user/app on
  **Assigned/Members**. PowerShell: `New-RoleGroup`/`Add-RoleGroupMember`, or
  `New-ManagementRoleAssignment -Role 'View-Only Configuration' -User <upn>`,
  against a plain Exchange Online session.
- **`View-Only Retention Management`** and **`View-Only DLP Compliance
  Management`** — do **not** exist in the EAC. Assign in the **Microsoft
  Purview compliance portal** (`purview.microsoft.com`, or
  `compliance.microsoft.com` / classic Security & Compliance Center):
  **Roles and scopes → Permissions** → create/edit a role group → add the
  role on **Roles** → add the user/app on **Members**. PowerShell:
  `Add-RoleGroupMember` against a **Security & Compliance (IPPS)** session
  (`Connect-IPPSSession`).
- **`Security Reader`** — a standard Entra/Microsoft 365 admin role group,
  assignable from the Entra admin center (**Roles and administrators**) or
  the Exchange/Purview admin surfaces.

A consultant who is already a **Global Administrator** holds all four
implicitly. A more scoped account needs `View-Only Configuration` /
`View-Only Recipients` granted via the EAC and, separately, `View-Only
Retention Management` / `View-Only DLP Compliance Management` granted via
the Purview compliance portal.

### Who these roles are granted to

- **App-only (CBA) engagements** — the roles are granted to the **assessment
  app's service principal**, either manually by the tenant's Exchange
  administrator, or with `Grant-ZTAssessExchangeOnlineRole` (in
  `EntraZTAssess.Provisioning`), run by an account with sufficient Exchange
  Online / Security & Compliance rights (for example Organization Management
  or a delegated Exchange Administrator). See
  [`Authentication.md` § 3a](Authentication.md#3a-grant-exchange-online--purview-role-groups-only-for-securitycompliance-collaboration-dataprotection-threatprotection).
- **Device-code engagements** (`-UseDeviceCode`) — there is no service
  principal to grant roles to; both the Graph and Exchange Online/IPPS
  sign-ins authenticate as the signed-in consultant. The tenant's own
  Exchange/Purview administrator instead grants these roles directly to that
  **consultant's own account**, ahead of the engagement. If the account
  lacks a role, the dependent checks degrade to `NotAssessed` rather than
  the connection failing.

### What the read-only module does and does not do

`Get-EntraZTAssess` (`source/`) never grants these roles — it only ever
calls a read-only, allow-listed `Get-*` cmdlet surface
(`Invoke-ZTAssessExoRequestWrapper`), scoped by
`Get-ZTAssessExoAllowedCmdletName`, over a session that itself only imports
that allow-listed command set. Granting is exclusively a provisioning-time
action, performed either manually or with `Grant-ZTAssessExchangeOnlineRole`
in the separately published `EntraZTAssess.Provisioning` package — outside
`source/`, because it performs writes.

## 3. Optional: Azure Role (Sentinel Module)

The optional `Sentinel` module assesses Microsoft Sentinel data connectors
via Azure Resource Manager, not Microsoft Graph or Exchange Online. It
requires the `Az.Accounts` module and an **Azure Reader** role (or
equivalent) on the subscription/resource group containing the Sentinel
workspace. No Entra directory role or Purview/Exchange RBAC role is needed
for this module.

## Summary Table

| Stage | Identity | Role(s) |
|---|---|---|
| Provisioning: create app registration | Provisioning operator | Application Administrator or Cloud Application Administrator |
| Provisioning: admin consent | Consenting administrator | Privileged Role Administrator or Global Administrator |
| Provisioning: grant Exchange Online/Purview roles (app-only) | Grant operator | Account with Exchange Online / Security & Compliance rights (e.g. Organization Management) |
| Assessment run: app-only (CBA), Graph | App service principal | Read-only Graph **Application** permissions only (no directory role) |
| Assessment run: app-only (CBA), Exchange Online/Purview modules | App service principal | `Security Reader`, `View-Only Configuration`, `View-Only Recipients`, `View-Only Retention Management`, `View-Only DLP Compliance Management` (as applicable per module) |
| Assessment run: device-code, all modules | Signed-in consultant | Same Graph delegated scopes + same Exchange Online/Purview roles as above, held directly on the consultant's account |
