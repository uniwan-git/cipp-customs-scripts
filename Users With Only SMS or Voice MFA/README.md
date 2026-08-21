# Users with only SMS or Voice MFA — CIPP Custom Script

A CIPP custom test that lists every user whose **only** registered MFA method is phone-based (SMS or voice), and attaches a per-account recommended action derived from Microsoft's SMS/Voice retirement guidance.

## Why this matters

Microsoft is retiring Microsoft-provided SMS and voice authentication in Microsoft Entra ID.

- **01-09-2026** — Passkeys become the default sign-in experience. Users enabled for SMS or voice are auto-enabled for passkeys, and the registration campaign is set to Microsoft Managed targeting them.
- **01-02-2027** — Microsoft-provided SMS and voice telecom delivery is fully retired. Any user whose **only** available MFA method is SMS or voice gets a **blocking** passkey-registration prompt at sign-in and cannot continue until they register one. There is **no opt-out** from this enforcement.

Phone-based MFA is also vulnerable to SIM-swapping and phishing, so these accounts are worth migrating regardless of the deadline.

Reference: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement

## Timeline

| Date | Milestone |
|---|---|
| 01-09-2026 | Passkeys become the default sign-in experience. Users enabled for SMS/voice are auto-enabled for passkeys; the registration campaign is set to Microsoft Managed targeting them and nudges them at MFA sign-in. |
| 18-09-2026 | Information on customer-managed telecom providers becomes available. |
| 30-10-2026 | Customers who need to keep SMS/voice can select and configure a telecom provider from the Microsoft Security Store. |
| 01-02-2027 | Microsoft-provided SMS/voice delivery is fully retired. Users whose only method is SMS/voice get a blocking passkey-registration prompt. No opt-out. |

A temporary opt-out (`passkeyDynamicMigration = true` on the authentication methods policy) can delay the 01-09-2026 through 01-02-2027 automatic enablement, but it does **not** exempt a tenant from the 01-02-2027 enforcement.

## What the script does

1. Pulls user registration details via `Get-CIPPTestData -Type 'UserRegistrationDetails'`.
2. Filters to non-guest users whose only real MFA methods are phone-based. Email and security questions are treated as SSPR-only and never count as MFA, so a user with `email, mobilePhone` is still flagged as phone-only.
3. Flags admin accounts as `CRITICAL` priority (privileged accounts on phone-only MFA are the biggest exposure) and sorts them to the top.
4. Builds a per-account recommended action, plus tenant-level next steps and a migration-methods guide.
5. Returns `Failed` when one or more users are affected, `Passed` when none are.

## Output columns

| Column | Meaning |
|---|---|
| User | User principal name |
| Admin | Whether the account holds an admin role |
| Priority | `CRITICAL` for admins, `High` otherwise |
| MFA Methods | Real MFA methods only (email / security questions excluded) |
| Recommended Action | Per-account migration guidance |

The full result set (`CIPPResults`) also includes `DisplayName` and `AllMethods` (the raw, unfiltered method list) for downstream use.

## Migration methods

**Pushable via the registration campaign** (proposed to the user at sign-in):

- **Passkey (FIDO2)** — default phishing-resistant credential; device-bound or synced.
- **Microsoft Authenticator** — push / passwordless; phishing-resistant in passwordless mode.

**Valid alternatives, but not pushed by the campaign** (register via self-service, Temporary Access Pass, or admin provisioning):

- **Windows Hello for Business** — phishing-resistant, best on managed Windows devices.
- **FIDO2 hardware security key** — device-bound passkey on a physical key.
- **Certificate-based authentication (X.509)** — for environments with a PKI.
- **Hardware / Software OATH token** — TOTP; exits SMS but weaker than phishing-resistant methods.

The 01-02-2027 enforcement removes Microsoft-provided SMS/Voice delivery — it does **not** force passkeys specifically. Any account holding one of the methods above continues to sign in normally; the blocking prompt only hits accounts whose sole method is SMS or voice.

## Result status

| Condition | CIPPStatus |
|---|---|
| One or more phone-only MFA users found | `Failed` |
| No phone-only MFA users | `Passed` |

## Script

```powershell
# Users whose only registered MFA methods are phone-based (SMS/voice), with per-account
# recommended actions derived from Microsoft's SMS/Voice retirement guidance.
# Ref: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement
$RegDetails = Get-CIPPTestData -Type 'UserRegistrationDetails'

# Phone methods = SMS/voice; email + security questions are SSPR-only and never satisfy MFA
$phoneMethods  = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
$nonMfaMethods = @('email', 'securityQuestion')

# Users who have at least one real MFA method AND whose only real MFA method(s) are phone-based
$phoneOnly = $RegDetails | Where-Object {
    $_.userType -ne 'guest' -and
    @($_.methodsRegistered | Where-Object { $_ -notin $nonMfaMethods }).Count -gt 0 -and
    @($_.methodsRegistered | Where-Object { $_ -notin $nonMfaMethods -and $_ -notin $phoneMethods }).Count -eq 0
} | Select-Object `
    @{Name='UserPrincipalName'; Expression={ $_.userPrincipalName }},
    @{Name='DisplayName'; Expression={ $_.userDisplayName }},
    @{Name='IsAdmin'; Expression={ $_.isAdmin }},
    @{Name='MfaMethods'; Expression={ (@($_.methodsRegistered | Where-Object { $_ -notin $nonMfaMethods }) -join ', ') }},
    @{Name='AllMethods'; Expression={ (@($_.methodsRegistered) -join ', ') }},
    @{Name='Priority'; Expression={ if ($_.isAdmin) { 'CRITICAL' } else { 'High' } }},
    @{Name='RecommendedAction'; Expression={
        if ($_.isAdmin) {
            'Admin on phone-only MFA - migrate before 01-02-2027 (privileged account, SIM-swap/phishing exposure). Push-eligible via campaign: Passkey (FIDO2) OR Microsoft Authenticator. Also valid (register separately): Windows Hello for Business, FIDO2 security key, certificate-based auth.'
        } else {
            'Phone-only MFA - migrate before 01-02-2027 or sign-in shows a blocking passkey prompt. Push-eligible via campaign: Passkey (FIDO2) OR Microsoft Authenticator. Also valid (register separately): Windows Hello, FIDO2 key, certificate, OATH token.'
        }
    }}

$count = @($phoneOnly).Count

if ($count -gt 0) {
    $adminCount = @($phoneOnly | Where-Object { $_.IsAdmin }).Count

    $headerLines = @(
        "### Users with only SMS/Voice MFA: $count"
        ""
        "These accounts' only MFA methods are phone-based (SIM-swap and phishing exposure). Microsoft-provided SMS/Voice is retired on 01-02-2027; after that date any user whose only method is SMS/Voice gets a **blocking** passkey-registration prompt at sign-in. There is no opt-out from the February 1 enforcement."
        ""
        "**Admins affected: $adminCount** - treat these as top priority."
        ""
        "| User | Admin | Priority | MFA Methods | Recommended Action |"
        "|---|---|---|---|---|"
    )

    $tableRows = $phoneOnly | Sort-Object @{Expression={ if ($_.IsAdmin) { 0 } else { 1 } }}, UserPrincipalName | ForEach-Object {
        "| $($_.UserPrincipalName) | $($_.IsAdmin) | $($_.Priority) | $($_.MfaMethods) | $($_.RecommendedAction) |"
    }

    $methodGuide = @(
        ""
        "### Migration methods that resolve the SMS/Voice risk"
        ""
        "**Pushable via the registration campaign** (proposed to the user at sign-in):"
        "- Passkey (FIDO2) - default phishing-resistant credential; device-bound or synced."
        "- Microsoft Authenticator - push / passwordless; phishing-resistant in passwordless mode."
        ""
        "**Valid alternatives, but NOT pushed by the campaign** (register via self-service, TAP, or admin provisioning):"
        "- Windows Hello for Business - phishing-resistant, best on managed Windows devices."
        "- FIDO2 hardware security key - device-bound passkey on a physical key."
        "- Certificate-based authentication (X.509) - for environments with a PKI."
        "- Hardware / Software OATH token - TOTP; exits SMS but weaker than phishing-resistant methods."
        ""
        "Note: the 01-02-2027 enforcement removes Microsoft-provided SMS/Voice delivery - it does not force passkeys specifically. Any account holding one of the methods above continues to sign in normally; the blocking prompt only hits accounts whose sole method is SMS or Voice."
    )

    $globalSteps = @(
        ""
        "### Tenant-level actions (Microsoft guidance)"
        ""
        "1. Ensure Passkey (FIDO2) and/or Microsoft Authenticator is enabled in the Authentication Methods Policy."
        "2. Create a security group of these SMS/Voice users and set the Registration Campaign state to Microsoft Managed, targeting that group."
        "3. Communicate the change (Awareness / Action / Reminder) using the Microsoft MFA templates."
        "4. Only if a genuine regulatory or operational need exists, evaluate a customer-managed telecom provider via the Microsoft Security Store (config available from 30-10-2026)."
        "5. Confirm every listed user holds a phishing-resistant (or at least non-phone) method before 01-02-2027."
    )

    $md = (@($headerLines) + @($tableRows) + @($methodGuide) + @($globalSteps)) -join "`n"

    @{
        CIPPStatus         = 'Failed'
        CIPPResults        = $phoneOnly
        CIPPResultMarkdown = $md
    }
} else {
    $md = @(
        "### Users with only SMS or Voice MFA: 0"
        ""
        "No users rely solely on SMS or voice call for MFA. No action needed for the 01-02-2027 SMS/Voice retirement on this axis."
    ) -join "`n"

    @{
        CIPPStatus         = 'Passed'
        CIPPResults        = @()
        CIPPResultMarkdown = $md
    }
}
```

## Requirements & constraints

- Runs in CIPP's custom-test sandbox (PowerShell ConstrainedLanguage). It avoids `+=`, custom functions, and `[pscustomobject]` casts, and uses only the allowed cmdlets (`Where-Object`, `Select-Object`, `Sort-Object`, `ForEach-Object`, `Get-CIPPTestData`, etc.).
- Markdown output uses real newlines (backtick-n), which the CIPP result renderer requires for tables to display correctly.
- The exact strings returned in `methodsRegistered` can vary by Microsoft Graph version. The phone-only filter is robust because it works by excluding phone methods rather than enumerating strong ones, but verify method labels on a tenant that has passkeys/Authenticator if you extend the logic.

## Notes

- This script covers the per-user axis (who is affected). Pair it with a tenant-policy readiness check (whether SMS/Voice are still enabled, whether FIDO2 is enabled, campaign state) for the full picture.
- The registration-campaign targetable methods listed here reflect guidance as of early 2026; confirm against current Microsoft documentation, since Microsoft updates these capabilities over time.
