# Onboarding-Oberfläche (claim_email- und invite-Vorlagen)

# E-Mail beanspruchen (claim_email.html)
claim-page-title = E-Mail beanspruchen
claim-card-title = E-Mail-Adresse beanspruchen
claim-subtitle = Wenn jemand Ihre E-Mail-Adresse registriert, aber nie bestätigt hat, können Sie sie übernehmen, indem Sie bestätigen, dass Sie an dieser Adresse Nachrichten empfangen.
claim-email-label = E-Mail
claim-send-code = Code senden
claim-changed-mind = Anders überlegt?
claim-back-to-signup = Zurück zur Registrierung

# Code bestätigen (claim_email_confirm.html)
claim-confirm-page-title = Anspruch bestätigen
claim-confirm-card-title = Bestätigen Sie Ihren Code
claim-confirm-subtitle = Geben Sie den 6-stelligen Code ein, den wir soeben gesendet haben. Codes laufen nach 15 Minuten ab.
claim-confirm-code-label = Code
claim-confirm-button = Bestätigen
claim-confirm-no-code = Keinen Code erhalten?
claim-confirm-start-over = Neu beginnen

# Einladung annehmen (invite/accept.html)
invite-accept-page-title = Einladung annehmen
invite-accept-heading = { $org } beitreten
invite-accept-body = Sie wurden eingeladen, { $org } als { $role } beizutreten. Die Einladung wurde an { $email } gesendet.

# Einladung nicht verfügbar (invite/invalid.html)
invite-invalid-page-title = Einladung nicht verfügbar
invite-invalid-heading = Einladung nicht verfügbar
invite-invalid-contact = Wenden Sie sich an die Person, die Sie eingeladen hat, um einen neuen Link anzufordern.
invite-invalid-back = Zurück zum Dashboard

# Claim-email-Fehler (in Rust gesetzt)
claim-error-invalid-email = Geben Sie eine gültige E-Mail-Adresse ein.
claim-error-code-expired = Der Code ist abgelaufen. Beginnen Sie von vorne.
claim-error-invalid-token = Ungültiges Token. Beginnen Sie von vorne.
claim-error-service-unavailable = Dienst vorübergehend nicht verfügbar. Versuchen Sie es in einem Moment erneut.
claim-error-too-many-attempts = Zu viele falsche Codes. Beginnen Sie von vorne.
claim-error-code-mismatch = Der Code stimmte nicht überein. Versuchen Sie es erneut.
claim-error-no-longer-claimable = Diese E-Mail-Adresse kann nicht mehr beansprucht werden.
claim-error-release-failed = Wir konnten die E-Mail-Adresse nicht freigeben. Wenden Sie sich an den Support.

# Einladung abschließen (in Rust gesetzt)
invite-error-corrupt = Die Einladung ist beschädigt. Wenden Sie sich an Ihren Administrator.
