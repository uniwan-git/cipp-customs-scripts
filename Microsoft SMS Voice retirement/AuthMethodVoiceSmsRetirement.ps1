# Assess tenant readiness for the SMS/Voice retirement and Passkeys-by-default change
# This script is intended to be copy pasted in CIPP Custom tests
# Ref: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement
$Policy = Get-CIPPTestData -Type 'AuthenticationMethodsPolicy'

$FriendlyNames = @{
    'Fido2'                        = 'FIDO2 / Passkey'
    'MicrosoftAuthenticator'       = 'Microsoft Authenticator'
    'Sms'                          = 'SMS'
    'TemporaryAccessPass'          = 'Temporary Access Pass (TAP)'
    'HardwareOath'                 = 'Hardware OATH Token'
    'SoftwareOath'                 = 'Software OATH Token'
    'Voice'                        = 'Voice Call'
    'Email'                        = 'Email OTP'
    'X509Certificate'              = 'Certificate-Based Auth (X.509)'
    'VerifiableCredentials'        = 'Verifiable Credentials'
    'QRCodePin'                    = 'QR Code + PIN'
    'FederatedIdentityCredential'  = 'Federated Identity Credential'
}

$Configs = $Policy.authenticationMethodConfigurations

# --- Retirement-relevant signals - inline lookups (no custom functions) ---
$SmsState   = ($Configs | Where-Object { $_.id -eq 'Sms' }).state
$VoiceState = ($Configs | Where-Object { $_.id -eq 'Voice' }).state
$Fido2State = ($Configs | Where-Object { $_.id -eq 'Fido2' }).state

$SmsEnabled   = $SmsState -eq 'enabled'
$VoiceEnabled = $VoiceState -eq 'enabled'
$Fido2Enabled = $Fido2State -eq 'enabled'

# Registration campaign state + whether it targets passkeys (FIDO2)
$Campaign        = $Policy.registrationEnforcement.authenticationMethodsRegistrationCampaign
$CampaignState   = if ($Campaign) { $Campaign.state } else { 'notConfigured' }
$CampaignTargetsPasskey = [bool]($Campaign.includeTargets | Where-Object { $_.targetedAuthenticationMethod -eq 'FIDO2' })

# Temporary opt-out flag (passkeyDynamicMigration)
$OptOut          = [bool]$Policy.optOutSettings.passkeyDynamicMigration

# --- Readiness evaluation - build actions via array expansion (no +=) ---
$Actions = @(
    if ($SmsEnabled)   { 'SMS still enabled - migrate users to passkeys before 2027-02-01' }
    if ($VoiceEnabled) { 'Voice still enabled - migrate users to passkeys before 2027-02-01' }
    if (-not $Fido2Enabled) { 'FIDO2/Passkey NOT enabled - enable before launching a campaign' }
    if (($SmsEnabled -or $VoiceEnabled) -and $CampaignState -ne 'enabled') {
        'Registration campaign not enabled while SMS/Voice users exist'
    }
    if ($CampaignState -eq 'enabled' -and -not $CampaignTargetsPasskey) {
        'Registration campaign enabled but not targeting FIDO2/Passkey'
    }
    if ($OptOut) { 'Temporary opt-out active (passkeyDynamicMigration=true) - expires 2027-02-01' }
)

# Overall readiness: "Ready" if no telecom methods remain enabled and passkeys are enabled
$IsReady = (-not $SmsEnabled) -and (-not $VoiceEnabled) -and $Fido2Enabled

# Summary object built via Select-Object (no [pscustomobject])
$Summary = '' | Select-Object `
    @{Name='SmsEnabled'; Expression={ $SmsEnabled }},
    @{Name='VoiceEnabled'; Expression={ $VoiceEnabled }},
    @{Name='Fido2Enabled'; Expression={ $Fido2Enabled }},
    @{Name='RegistrationCampaign'; Expression={ $CampaignState }},
    @{Name='CampaignTargetsPasskey'; Expression={ $CampaignTargetsPasskey }},
    @{Name='TemporaryOptOut'; Expression={ $OptOut }},
    @{Name='RetirementReady'; Expression={ $IsReady }},
    @{Name='Actions'; Expression={ ($Actions -join '; ') }}

# --- Full method table for reference ---
$MethodTable = $Configs | Select-Object `
    @{Name='Method'; Expression={ $n = $FriendlyNames[$_.id]; if ($n) { $n } else { $_.id } }},
    @{Name='State'; Expression={ $_.state }},
    @{Name='Enabled'; Expression={ $_.state -eq 'enabled' }},
    @{Name='ExcludeTargets'; Expression={ if (@($_.excludeTargets).Count -gt 0) { (@($_.excludeTargets | ForEach-Object { $_.id }) -join ', ') } else { '-' } }}

# --- Markdown output - build all lines via array expansion (no +=) ---
$readyIcon = if ($IsReady) { '✅ Ready' } else { '⚠️ Action required' }

$actionLines = @(
    if ($Actions.Count -gt 0) {
        "**Actions required:**"
        $Actions | ForEach-Object { "- $_" }
        ""
    }
)

$methodLines = @(
    $MethodTable | ForEach-Object {
        $icon = if ($_.Enabled) { '✅' } else { '❌' }
        "| $($_.Method) | $icon $($_.State) | $($_.ExcludeTargets) |"
    }
)

$mdParts = @(
    "### SMS/Voice Retirement Readiness: $readyIcon"
    ""
    "**Key dates:** Passkeys default 2026-09-01 - Microsoft SMS/Voice retired 2027-02-01 (blocking, no opt-out)"
    ""
    "| Signal | Status |"
    "|---|---|"
    "| SMS enabled | $(if ($SmsEnabled) { '❌ Yes' } else { '✅ No' }) |"
    "| Voice enabled | $(if ($VoiceEnabled) { '❌ Yes' } else { '✅ No' }) |"
    "| FIDO2 / Passkey enabled | $(if ($Fido2Enabled) { '✅ Yes' } else { '❌ No' }) |"
    "| Registration campaign | $CampaignState |"
    "| Campaign targets passkey | $(if ($CampaignTargetsPasskey) { '✅ Yes' } else { '❌ No' }) |"
    "| Temporary opt-out active | $(if ($OptOut) { '⚠️ Yes' } else { 'No' }) |"
    ""
    $actionLines
    "### All authentication methods"
    "| Method | State | Exclude Targets |"
    "|---|---|---|"
    $methodLines
)

$md = $mdParts -join "`n"

# --- Return - status reflects readiness ---
@{
    CIPPStatus         = if ($IsReady) { 'Passed' } else { 'Failed' }
    CIPPResults        = @{ Summary = $Summary; Methods = $MethodTable }
    CIPPResultMarkdown = $md
}
