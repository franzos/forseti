# Kratos flow messages keyed by stable numeric ID.
# Passthrough (NOT in this catalog): 4000001 (generic validation - text IS the payload).
# En text matches Ory Kratos OSS English where Fluent allows it; expired-flow messages
# use simplified text because Fluent cannot compute %.2f minutes from a unix timestamp.

# --- Login (1010xxx) ---
kratos-1010001 = Sign in
kratos-1010002 = Sign in with { $provider }
kratos-1010003 = Please confirm this action by verifying that it is you.
kratos-1010004 = Please complete the second authentication challenge.
kratos-1010005 = Verify
kratos-1010006 = Authentication code
kratos-1010007 = Backup recovery code
kratos-1010008 = Sign in with a hardware key
kratos-1010009 = Use Authenticator
kratos-1010010 = Use backup recovery code
kratos-1010011 = Sign in with a hardware key
kratos-1010012 = Prepare your WebAuthn device (e.g. security key, biometrics scanner, ...) and press continue.
kratos-1010013 = Continue
kratos-1010014 = A code was sent to the address you provided. If you didn't receive it, please check the spelling of the address and try again.
kratos-1010015 = Send sign in code
kratos-1010021 = Sign in with passkey
kratos-1010022 = Sign in with password

# --- Registration (1040xxx) ---
kratos-1040001 = Sign up
kratos-1040002 = Sign up with { $provider }
kratos-1040003 = Continue
kratos-1040004 = Sign up with security key
kratos-1040005 = A code has been sent to the address(es) you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.
kratos-1040006 = Send sign up code
kratos-1040007 = Sign up with passkey
kratos-1040008 = Back

# --- Settings (1050xxx) ---
kratos-1050001 = Your changes have been saved!
kratos-1050002 = Link { $provider }
kratos-1050003 = Unlink { $provider }
kratos-1050004 = Unlink TOTP Authenticator App
kratos-1050007 = Reveal backup recovery codes
kratos-1050008 = Generate new backup recovery codes
kratos-1050010 = These are your back up recovery codes. Please keep them in a safe place!
kratos-1050011 = Confirm backup recovery codes
kratos-1050012 = Add security key
kratos-1050013 = Name of the security key
kratos-1050016 = Disable this method
kratos-1050017 = This is your authenticator app secret. Use it if you can not scan the QR code.
kratos-1050018 = Remove security key "{ $display_name }"
kratos-1050019 = Add passkey
kratos-1050020 = Remove passkey "{ $display_name }"
kratos-1050023 = Your account is managed by your organization. To change these settings, contact your organization administrator.

# --- Recovery (1060xxx) ---
# 1060001: Ory text has "within the next %.2f minutes" but context carries a
# timestamp, not minutes. Simplified here; fallback gives Ory's exact English.
kratos-1060001 = You successfully recovered your account. Please change your password or set up an alternative login method (e.g. social sign in) soon.
kratos-1060002 = An email containing a recovery link has been sent to the email address you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.
kratos-1060003 = An email containing a recovery code has been sent to the email address you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.
kratos-1060004 = A recovery code has been sent to { $masked_address }. If you have not received it, check the spelling of the address and make sure to use the address you registered with.

# --- Node labels (1070xxx) ---
kratos-1070001 = Password
kratos-1070003 = Save
kratos-1070004 = ID
kratos-1070005 = Submit
kratos-1070006 = Verify code
kratos-1070007 = Email
kratos-1070008 = Resend code
kratos-1070009 = Continue
kratos-1070010 = Recovery code
kratos-1070011 = Verification code
kratos-1070012 = Registration code
kratos-1070013 = Login code
kratos-1070016 = Recovery address

# --- Verification (1080xxx) ---
kratos-1080001 = An email containing a verification link has been sent to the email address you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.
kratos-1080002 = You successfully verified your email address.
kratos-1080003 = An email containing a verification code has been sent to the email address you provided. If you have not received an email, check the spelling of the address and make sure to use the address you registered with.

# --- Validation errors (4000xxx) ---
# 4000001 is passthrough: text IS the dynamic validation reason.
kratos-4000002 = Property { $property } is missing.
kratos-4000003 = length must be >= { $min_length }, but got { $actual_length }
# 4000005: $reason comes from Kratos policy config; it will be in English within a translated sentence.
kratos-4000005 = The password can not be used because { $reason }.
kratos-4000006 = The provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number.
kratos-4000007 = An account with the same identifier (email, phone, username, ...) exists already.
kratos-4000008 = The provided authentication code is invalid, please try again.
kratos-4000032 = The password must be at least { $min_length } characters long, but got { $actual_length }.
kratos-4000035 = This account does not exist or has not setup sign in with code.

# --- Login flow errors (4010xxx) ---
# Simplified: Ory computes "X.XX minutes ago" from a timestamp we cannot format in Fluent.
kratos-4010001 = The login flow has expired, please try again.
kratos-4010008 = The login code is invalid or has already been used. Please try again.

# --- Registration flow errors (4040xxx) ---
kratos-4040001 = The registration flow has expired, please try again.
kratos-4040003 = The registration code is invalid or has already been used. Please try again.

# --- Settings flow errors (4050xxx) ---
kratos-4050001 = The settings flow has expired, please try again.

# --- Recovery flow errors (4060xxx) ---
kratos-4060004 = The recovery token is invalid or has already been used. Please retry the flow.
kratos-4060006 = The recovery code is invalid or has already been used. Please try again.

# --- Verification flow errors (4070xxx) ---
kratos-4070001 = The verification token is invalid or has already been used. Please retry the flow.
kratos-4070005 = The verification flow has expired, please try again.
kratos-4070006 = The verification code is invalid or has already been used. Please try again.
