# Device authorization (RFC 8628) verify and done screens

device-verify-page-title = Approve Linux login
device-verify-card-title = Approve a Linux login
device-verify-prompt = Did you just start this login?
device-verify-host = Linux login as { $user } on host { $host } (host { $hostid }).
device-verify-warning = Only approve if you started this on that machine. If you didn't, close this page - approving lets whoever started it sign in as { $user }.
device-verify-approve = Yes, this was me - continue
device-verify-cancel = No, cancel
device-verify-code-prompt = Enter the code shown on your terminal to continue.
device-verify-code-submit = Continue

device-done-title-error = Login not approved
device-done-title-ok = Login approved
device-done-card-title-error = We couldn't approve that login
device-done-card-title-ok = Approved
device-done-body-error = That code may have expired or already been used. Start the login again on your terminal to get a fresh code.
device-done-body-ok = You can return to your terminal, the login will continue there.
device-done-body-safe = It's safe to close this page.
