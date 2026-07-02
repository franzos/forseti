# Fehlerseite
error-reference-id = Referenz-ID:
error-cta-back-to-sign-in = Zurück zur Anmeldung

# OAuth-Abmeldebestätigung
logout-card-title = Von allen Apps abmelden?
logout-card-subtitle = Dadurch wird Ihre Sitzung bei { $brand } beendet und alle Apps, bei denen Sie angemeldet sind, werden benachrichtigt.
logout-body-text = Die App, die Ihre Abmeldung angefordert hat, wird über den abgeschlossenen Vorgang informiert. Einige Apps behalten möglicherweise kurzzeitig Daten im Cache; die Abmeldung hier beendet die Sitzung bei { $brand }.
logout-action-sign-out = Abmelden
logout-action-cancel = Abbrechen

# Admin-Dialog-Titel und -Texte für render_admin_error an Aufrufstellen mit Locale.
# Aufrufstellen ohne Locale (Hilfsfunktionen, Fehlergrenzen) behalten ihre englischen Literale.
dialog-identity-unavailable-title = Identität nicht verfügbar
dialog-identity-unavailable-body = Diese Identität konnte nicht geladen werden. Möglicherweise wurde sie gelöscht.
dialog-recovery-code-failed-title = Wiederherstellungscode fehlgeschlagen
dialog-recovery-code-failed-body = Der Wiederherstellungscode wurde erstellt, konnte aber nicht für die einmalige Anzeige gespeichert werden. Generieren Sie einen neuen Code und versuchen Sie es erneut.
dialog-disable-failed-title = Deaktivierung fehlgeschlagen
dialog-enable-failed-title = Aktivierung fehlgeschlagen
dialog-delete-failed-title = Löschen fehlgeschlagen
dialog-revoke-failed-title = Widerruf fehlgeschlagen

# Fehlergrenze (error_boundary.html), Titel/Text/CTA in Rust-Handlern gesetzt.
error-boundary-auth-unavailable-title = Authentifizierung nicht verfügbar
error-boundary-auth-unavailable-body = Wir konnten den Authentifizierungsdienst nicht erreichen. Bitte versuchen Sie es in einem Moment erneut.
error-boundary-cta-try-again = Erneut versuchen
error-boundary-cta-sign-in = Anmelden
error-boundary-cta-back-to-settings = Zurück zu den Einstellungen
error-boundary-cta-back-to-dashboard = Zurück zum Dashboard
error-boundary-cta-back-to-account = Zurück zum Konto
error-boundary-signin-title = Anmeldung nicht verfügbar
error-boundary-signup-title = Registrierung nicht verfügbar
error-boundary-recovery-title = Wiederherstellung nicht verfügbar
error-boundary-verification-title = Verifizierung nicht verfügbar
error-boundary-settings-title = Einstellungen nicht verfügbar
error-boundary-logout-title = Abmeldung nicht verfügbar
error-boundary-logout-body = Wir konnten Ihre Abmeldung nicht abschließen, da der Authentifizierungsdienst nicht erreichbar ist. Ihre Sitzung ist noch aktiv, bitte versuchen Sie es in einem Moment erneut.
error-boundary-sessions-title = Sitzungen nicht verfügbar
error-boundary-sessions-body = Wir konnten Ihre aktiven Sitzungen nicht auflisten. Bitte versuchen Sie es in einem Moment erneut.
error-boundary-authorized-apps-title = Autorisierte Apps nicht verfügbar
error-boundary-authorized-apps-no-session-body = Wir konnten Ihre Sitzung nicht lesen. Bitte melden Sie sich erneut an.
error-boundary-authorized-apps-service-body = Wir konnten den OAuth-Dienst nicht erreichen. Bitte versuchen Sie es in einem Moment erneut.
error-boundary-account-deletion-title = Kontolöschung fehlgeschlagen
error-boundary-account-delete-bad-session = Ihre Sitzung befindet sich in einem unerwarteten Zustand. Bitte melden Sie sich erneut an und versuchen Sie es noch einmal.
error-boundary-account-delete-sole-owner = Sie sind der einzige Eigentümer von { $names }. Übertragen Sie die Eigentümerschaft an ein anderes Mitglied, bevor Sie Ihr Konto löschen.
error-boundary-account-delete-ownership-check-failed = Wir konnten Ihre Organisationseigentümerschaft nicht überprüfen. Es wurde nichts geändert; bitte versuchen Sie es in einem Moment erneut.
error-boundary-account-delete-consent-unreachable = Wir konnten den Zustimmungsdienst nicht erreichen, um Ihre verbundenen Apps zu benachrichtigen. Es wurde nichts geändert; bitte versuchen Sie es in einem Moment erneut.
error-boundary-account-delete-notifications-failed = Wir konnten die Löschbenachrichtigungen nicht vorbereiten. Es wurde nichts geändert; bitte versuchen Sie es erneut.
error-boundary-account-delete-failed = Wir konnten Ihr Konto nicht löschen. Bitte versuchen Sie es in einem Moment erneut.

# SAML-Fehlerseite (wird mit der Standardsprache gerendert; der ACS-Callback trägt keine Anfragesprache).
error-boundary-sso-unavailable-title = Single Sign-on nicht verfügbar
error-boundary-sso-unavailable-body = Single Sign-on ist für diese Adresse nicht verfügbar. Prüfen Sie den Link, den Ihr Administrator Ihnen gegeben hat, oder melden Sie sich mit Ihrer üblichen Methode an.
error-boundary-sso-failed-title = Single Sign-on fehlgeschlagen
error-boundary-sso-validation-failed-body = Dieser Anmeldeversuch konnte nicht validiert werden. Beginnen Sie erneut über den SSO-Link Ihrer Organisation.
error-boundary-sso-upstream-failed-body = Der Anmeldedienst ist vorübergehend nicht verfügbar. Bitte versuchen Sie es erneut.
error-boundary-sso-no-email-body = Der Identitätsanbieter hat keine E-Mail-Adresse übermittelt. Bitten Sie Ihren Administrator, das E-Mail-Attribut der SAML-Verbindung zuzuordnen.

# Kratos-Fehlerseite (error.html), Fallbacks in Rust gesetzt.
error-page-generic-title = Etwas ist schiefgelaufen
error-page-generic-body = Wir konnten die angeforderte Seite nicht laden. Der Link ist möglicherweise abgelaufen oder wurde bereits verwendet.
error-page-link-expired-title = Link abgelaufen
error-page-link-expired-body = Dieser Link ist nicht mehr gültig. Bitte beginnen Sie erneut bei der Anmeldung.
error-page-security-title = Sicherheitsprüfung fehlgeschlagen
error-page-already-signed-in-title = Bereits angemeldet
error-page-default-message = Wir konnten diese Anfrage nicht abschließen.

# Admin-Sperrseite (admin/forbidden.html), in Rust gesetzt.
error-admin-access-denied-title = Zugriff verweigert
error-admin-access-denied-body = Ihr Konto ist nicht berechtigt, die Admin-Werkzeuge zu verwenden.
error-admin-access-denied-forseti-body = Ihr Konto ist nicht berechtigt, die Forseti-weiten Admin-Werkzeuge zu verwenden.
error-admin-access-denied-org-body = Sie haben keinen Admin-Zugriff auf diese Organisation.

# SAML blocked
error-saml-blocked-page-title = Anmeldung blockiert
error-saml-blocked-card-title = Anmeldung nicht möglich
error-saml-unverified-prefix = Ein Konto für
error-saml-unverified-suffix = ist bereits vorhanden, aber die E-Mail-Adresse wurde noch nicht bestätigt, sodass Single Sign-On nicht sicher verknüpft werden kann. Bestätigen Sie die Adresse über Ihre ursprüngliche Registrierungs-E-Mail oder wenden Sie sich an Ihren Administrator.
error-saml-cross-org-not-member = Ihr Konto ist noch kein Mitglied dieser Organisation. Bitten Sie Ihren Administrator, Sie hinzuzufügen, und versuchen Sie es dann erneut.
error-saml-conflict = Anmeldung nicht möglich. Bitte wenden Sie sich an Ihren Administrator.
error-saml-blocked-cta = Zur Anmeldung
