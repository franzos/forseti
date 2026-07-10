# Anmeldeseite
auth-login-page-title = Anmelden
auth-login-card-title = Bei Ihrem Konto anmelden
auth-login-card-subtitle = Willkommen zurück bei { $brand }.
auth-login-aal2-body = Dieser Bereich erfordert die Zwei-Faktor-Authentifizierung, für Ihr Konto ist jedoch noch kein zweiter Faktor eingerichtet.
auth-login-aal2-hint = Richten Sie eine Authentifizierungs-App, einen Sicherheitsschlüssel oder Wiederherstellungscodes in den Einstellungen ein und kehren Sie dann zurück.
auth-login-aal2-setup-link = Zwei-Faktor-Authentifizierung einrichten
auth-login-forgot-password = Passwort vergessen?
auth-login-no-account = Noch kein Konto?
auth-login-create-account = Konto erstellen

# Geteilter Trenner (Anmeldung + Registrierung)
auth-or-continue-with = Oder weiter mit
auth-oidc-signin = Mit { $provider } anmelden

# Registrierungsseite
auth-registration-page-title = Konto erstellen
auth-registration-card-title = Ein Konto erstellen
auth-registration-card-subtitle = Registrieren Sie sich, um Ihre Identität sicher zu verwalten.
auth-registration-have-account = Bereits ein Konto vorhanden?
auth-registration-sign-in-link = Anmelden
auth-registration-claim-body = Wenn dies Ihre E-Mail-Adresse ist und Sie die Registrierung nie abgeschlossen haben,
auth-registration-claim-link = hier beanspruchen

# Wiederherstellungsseite
auth-recovery-page-title = Konto wiederherstellen
auth-recovery-card-title-sent = Prüfen Sie Ihren Posteingang
auth-recovery-card-title-default = Passwort vergessen?
auth-recovery-card-subtitle-sent = Wir haben einen Wiederherstellungscode an Ihren Posteingang gesendet. Geben Sie ihn unten ein, um fortzufahren.
auth-recovery-card-subtitle-default = Geben Sie Ihre E-Mail-Adresse ein und wir senden Ihnen einen Link zum Zurücksetzen.
auth-recovery-back-to-sign-in = Zurück zur Anmeldung

# Bestätigungsseite
auth-verification-page-title = E-Mail-Adresse bestätigen
auth-verification-card-title-passed = E-Mail-Adresse bestätigt
auth-verification-card-title-sent = Prüfen Sie Ihren Posteingang
auth-verification-card-title-default = E-Mail-Adresse bestätigen
auth-verification-card-subtitle-passed = Ihre E-Mail-Adresse wurde bestätigt. Sie können diesen Tab schließen oder fortfahren.
auth-verification-card-subtitle-sent = Wir haben einen Bestätigungscode an Ihren Posteingang gesendet. Geben Sie ihn unten ein, um zu bestätigen.
auth-verification-card-subtitle-default = Geben Sie Ihre E-Mail-Adresse ein, um einen Bestätigungscode zu erhalten.
auth-verification-sent-email-hint = Verwenden Sie den Code aus der neuesten Bestätigungs-E-Mail oder öffnen Sie den Link in dieser E-Mail, anstatt den Code manuell einzugeben.
auth-verification-back-to-dashboard = Zurück zum Dashboard
auth-verification-back-to-sign-in = Zurück zur Anmeldung

# WebAuthn / Passkey Browser-seitige Texte (eingebettet über Daten-Attribute in webauthn_helper.html)
auth-webauthn-no-support = Ihr Browser unterstützt WebAuthn / Passkeys nicht.
auth-passkey-needs-platform = Die Passkey-Anmeldung benötigt einen auf diesem Gerät gespeicherten Plattform-Passkey (Touch ID, Windows Hello, ein Android-Gerät oder ein synchronisierter Passkey). In Ihrem Browser ist keiner eingerichtet.
auth-webauthn-err-not-allowed = Die Anfrage wurde abgebrochen, hat das Zeitlimit überschritten oder es waren keine passenden Anmeldedaten verfügbar.
auth-webauthn-err-security = Ihr Browser hat den Sicherheitsvorgang abgelehnt. Stellen Sie sicher, dass die Seite über einen vertrauenswürdigen Ursprung geladen wird und der registrierte Bezeichner übereinstimmt.
auth-webauthn-err-invalid-state = Auf diesem Gerät sind bereits Anmeldedaten registriert. Versuchen Sie sich stattdessen anzumelden oder verwenden Sie ein anderes Gerät.
auth-webauthn-err-not-supported = Ihr Browser unterstützt die angeforderten Anmeldedaten-Parameter nicht.
auth-webauthn-err-abort = Die Anfrage wurde vor dem Abschluss abgebrochen.
auth-webauthn-err-generic-prefix = Authentifizierungsfehler:

# Formularfeld-Beschriftungen. Kratos liefert Trait-Felder mit dem Schema-`title`
# unter der generischen Passthrough-Label-ID 1070002; flow_view.rs ersetzt diese nach Name.
auth-field-email = E-Mail
auth-field-first-name = Vorname
auth-field-last-name = Nachname
