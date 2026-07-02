settings-hub-title = Einstellungen
settings-hub-subtitle = Verwalten Sie Ihre Kontoeinstellungen, Sicherheitsoptionen und aktiven Sitzungen.
settings-hub-profile-title = Profil
settings-hub-profile-desc = Aktualisieren Sie Ihre E-Mail-Adresse und Ihren Anzeigenamen.
settings-hub-profile-link = Profil verwalten
settings-hub-password-title = Passwort
settings-hub-password-desc = Ändern Sie Ihr Kontopasswort.
settings-hub-password-link = Passwort ändern
settings-hub-2fa-title = Zwei-Faktor-Authentifizierung
settings-hub-2fa-desc = Richten Sie TOTP, Wiederherstellungscodes und Sicherheitsschlüssel ein.
settings-hub-2fa-link = 2FA verwalten
settings-hub-sessions-title = Aktive Sitzungen
settings-hub-sessions-desc = Überprüfen Sie die an Ihrem Konto angemeldeten Geräte.
settings-hub-sessions-link = Sitzungen anzeigen
settings-hub-apps-title = Autorisierte Apps
settings-hub-apps-desc = Überprüfen und widerrufen Sie OAuth-Apps, denen Sie Zugriff gewährt haben.
settings-hub-apps-link = Apps verwalten
settings-hub-providers-title = Verknüpfte Anbieter
settings-hub-providers-desc = Verbinden oder entfernen Sie Drittanbieter-Anmeldedienste.
settings-hub-providers-link = Anbieter verwalten
settings-hub-account-title = Konto
settings-hub-account-desc = Dauerhafte Änderungen: Löschen Sie Ihr Konto.
settings-hub-account-link = Gefahrenbereich
settings-nav-general = Allgemein
settings-nav-security = Sicherheit
settings-nav-connections = Verbindungen
settings-nav-overview = Übersicht
settings-nav-profile = Profil
settings-nav-organization = Organisation
settings-nav-password = Passwort
settings-nav-2fa = 2FA
settings-nav-sessions = Sitzungen
settings-nav-offline = Offline-Anmeldung
settings-nav-authorized-apps = Autorisierte Apps
settings-nav-linked-providers = Verknüpfte Anbieter
settings-nav-account = Konto

# Profil-Unterseite
settings-profile-heading = Profil
settings-profile-subtitle = Aktualisieren Sie Ihre E-Mail-Adresse und Ihren Anzeigenamen.
settings-profile-email-not-verified = Nicht bestätigt
settings-profile-email-send-verification = Bestätigungs-E-Mail senden
settings-profile-public-heading = Öffentliches Profil
settings-profile-public-saved = Profil gespeichert.
settings-profile-public-label-bio = Bio
settings-profile-public-label-location = Standort
settings-profile-public-label-pronouns = Pronomen
settings-profile-public-label-website = Website
settings-profile-public-label-avatar = Avatar-URL
settings-profile-public-avatar-hint = Optional. Leer lassen, um das automatisch generierte Identicon zu verwenden.
settings-profile-public-label-links = Links
settings-profile-public-save = Profil speichern
settings-profile-back = Zurück zu den Einstellungen
settings-profile-language-label = Bevorzugte Sprache
settings-profile-language-help = Gilt auf allen Ihren Geräten.

# Passwort-Unterseite
settings-password-heading = Passwort
settings-password-subtitle = Ändern Sie das Passwort für die Anmeldung.
settings-password-back = Zurück zu den Einstellungen

# Konto-Unterseite
settings-account-heading = Konto
settings-account-subtitle = Dauerhafte Änderungen an Ihrem Konto.
settings-account-delete-section-heading = Konto löschen
settings-account-delete-body = Löschen Sie Ihr Konto dauerhaft, jede aktive Sitzung und alle 2FA-/Wiederherstellungsdaten. Apps, die Kopien Ihrer Daten besitzen, werden benachrichtigt, damit sie ihre Seite bereinigen können. Dies kann nicht rückgängig gemacht werden.
settings-account-delete-action = Mein Konto löschen

# Konto-Löschbestätigungsseite
settings-account-delete-page-title = Löschung bestätigen
settings-account-delete-confirm-heading = Möchten Sie Ihr Konto löschen?
settings-account-delete-confirm-subtitle-prefix = Dies entfernt dauerhaft
settings-account-delete-confirm-subtitle-suffix = sowie alle zugehörigen Sitzungen, Wiederherstellungscodes und Anmeldedaten.
settings-account-delete-apps-heading = Diese Apps werden über die Löschung Ihres Kontos informiert
settings-account-delete-apps-note = Apps kopieren die Daten, die sie benötigen (Profil, Einstellungen) und verknüpfen sie mit Ihrer Konto-ID. Wir benachrichtigen sie über den von ihnen registrierten Lösch-Webhook, damit sie ihre Kopie bereinigen können.
settings-account-delete-no-apps = Aktuell haben keine Drittanbieter-Apps Kopien Ihrer Daten. Es gibt niemanden zu benachrichtigen.
settings-account-delete-confirm-label = Zur Bestätigung geben Sie Ihre E-Mail-Adresse ein:
settings-account-delete-confirm-placeholder = E-Mail-Adresse zur Bestätigung eingeben
settings-account-delete-confirm-submit = Ja, mein Konto löschen
settings-account-delete-confirm-cancel = Abbrechen

# Offline-Zugang-Unterseite
settings-offline-heading = Offline-Host-Anmeldung
settings-offline-subtitle = Legen Sie eine dedizierte Passphrase fest, mit der Sie sich am Terminal eines eingebundenen Linux-Hosts anmelden können, wenn dieser den Server nicht erreichen kann. Sie ist von Ihrem Kontopasswort getrennt. Verwenden Sie etwas, das Sie sich merken können, aber nicht wiederverwenden würden.
settings-offline-status-set-prefix = Eine Offline-Passphrase ist
settings-offline-status-set-word = festgelegt
settings-offline-status-set-suffix = . Geben Sie unten eine neue ein, um sie zu ändern, oder entfernen Sie sie vollständig.
settings-offline-status-unset = Es ist noch keine Offline-Passphrase festgelegt. Ohne eine können Sie sich nicht an einem eingebundenen Host anmelden, während dieser offline ist.
settings-offline-label-new-passphrase = Neue Offline-Passphrase
settings-offline-label-passphrase = Offline-Passphrase
settings-offline-passphrase-hint = Mindestens { $min_len } Zeichen. Verwenden Sie nicht Ihr Kontopasswort erneut.
settings-offline-action-change = Passphrase ändern
settings-offline-action-set = Passphrase festlegen
settings-offline-remove-heading = Offline-Zugang entfernen
settings-offline-remove-body = Löschen Sie Ihre Offline-Passphrase. Eingebundene Hosts entfernen sie bei der nächsten Synchronisierung, und Sie können sich nicht mehr bei ihnen anmelden, während sie offline sind.
settings-offline-action-remove = Passphrase entfernen
settings-offline-back = Zurück zu den Einstellungen

# Passwort-Übergabe (Wiederherstellung → neues Passwort)
settings-handoff-heading = Neues Passwort festlegen
settings-handoff-subtitle = Sie sind über den Wiederherstellungscode angemeldet. Legen Sie ein neues Passwort fest, um den Vorgang abzuschließen.
settings-handoff-countdown-label = Verbleibende Zeit zum Festlegen Ihres neuen Passworts:
settings-handoff-sign-out = Ohne Änderung abmelden

# 2FA-Unterseite
settings-2fa-heading = Zwei-Faktor-Authentifizierung
settings-2fa-subtitle = Stärken Sie Ihr Konto mit einem zweiten Faktor.
settings-2fa-no-recovery-warning-heading = Keine Wiederherstellungscodes: Sie riskieren eine Kontosperrung
settings-2fa-no-recovery-warning-body = Die Zwei-Faktor-Authentifizierung ist aktiv, aber Sie haben keine Wiederherstellungscodes. Wenn Sie Ihren Authenticator oder Sicherheitsschlüssel verlieren, sind Wiederherstellungscodes der einzige Weg zurück in Ihr Konto. Generieren Sie diese jetzt.
settings-2fa-no-recovery-warning-action = Codes generieren
settings-2fa-totp-heading = Authenticator-App (TOTP)
settings-2fa-totp-desc = Verwenden Sie eine App wie 1Password, Bitwarden, Aegis oder Authy, um 6-stellige Codes zu generieren.
settings-2fa-totp-enabled = Aktiviert
settings-2fa-totp-scan-hint = Scannen Sie diesen QR-Code mit Ihrer Authenticator-App oder geben Sie den geheimen Schlüssel manuell ein:
settings-2fa-totp-not-offered = Die Authenticator-App-Einrichtung wird von Ihrem Server derzeit nicht angeboten.
settings-2fa-recovery-heading = Wiederherstellungscodes
settings-2fa-recovery-desc = Einmalcodes, mit denen Sie sich anmelden können, wenn Sie den Zugriff auf Ihren Authenticator verlieren.
settings-2fa-recovery-active = Aktiv
settings-2fa-recovery-save-strong = Speichern Sie diese jetzt.
settings-2fa-recovery-save-suffix = Sie werden nicht erneut angezeigt. Bewahren Sie sie an einem sicheren Ort auf. Ein Passwort-Manager eignet sich gut.
settings-2fa-recovery-not-offered = Wiederherstellungscodes werden von Ihrem Server derzeit nicht angeboten.
settings-2fa-webauthn-heading = Sicherheitsschlüssel & Passkeys
settings-2fa-webauthn-desc = Verwenden Sie einen Hardware-Schlüssel (YubiKey, Titan) oder einen Plattform-Passkey (Touch ID, Windows Hello) als zweiten Faktor.
settings-2fa-webauthn-remove-fallback = Sicherheitsschlüssel entfernen
settings-2fa-webauthn-not-enabled = Passkey-Unterstützung ist von Ihrem Administrator nicht aktiviert.
settings-2fa-back = Zurück zu den Einstellungen

# Sitzungen-Unterseite
settings-sessions-heading = Aktive Sitzungen
settings-sessions-subtitle = Geräte, die derzeit bei Ihrem Konto angemeldet sind. Widerrufen Sie alle, die Sie nicht kennen.
settings-sessions-revoke-action = Abmelden
settings-sessions-revoke-others-heading = Auf allen anderen Geräten abmelden
settings-sessions-revoke-others-desc = Behält diese Sitzung aktiv und widerruft alle anderen.
settings-sessions-revoke-others-action = Andere abmelden
settings-sessions-back = Zurück zu den Einstellungen

# Autorisierte-Apps-Unterseite
settings-apps-heading = Autorisierte Apps
settings-apps-subtitle = Apps, denen Sie Zugriff auf Ihr Konto gewährt haben. Widerrufen Sie alle, die Sie nicht mehr verwenden. Diese müssen beim nächsten Anmelden erneut um Erlaubnis bitten.
settings-apps-empty = Noch keine Apps haben Zugriff auf Ihr Konto erhalten.
settings-apps-verified-label = Bestätigt
settings-apps-access-granted-prefix = Zugriff gewährt
settings-apps-revoke-action = Zugriff widerrufen
settings-apps-back = Zurück zu den Einstellungen
settings-apps-reviewed-title = Von Ihrem Administrator überprüft

# 2FA-Reste
settings-2fa-qr-alt = TOTP-QR-Code

# Passwort-Übergabe: Ablauf des Countdowns (in JS gerendert)
settings-handoff-expired-lead = Ihr Wiederherstellungsfenster ist abgelaufen.
settings-handoff-expired-link = Erneut starten

# Verknüpfte-Anbieter-Unterseite
settings-providers-heading = Verknüpfte Anbieter
settings-providers-subtitle = Melden Sie sich über einen externen Identitätsanbieter bei Ihrem Konto an.
settings-providers-empty-heading = Keine Upstream-Anbieter von Ihrem Administrator konfiguriert.
settings-providers-empty-desc = Wenden Sie sich an Ihren Administrator, um Google, GitHub oder andere Anmeldeanbieter zu aktivieren.
settings-providers-back = Zurück zu den Einstellungen

# Inline-Code-Aufteilungen (Punkt 8: 2+ Code-Elemente pro Zeichenkette)

# settings_profile.html - Öffentliches-Profil Beschreibung (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Für Organisationsmitglieder auf Ihrer
settings-profile-public-desc-part2 = Seite und für Apps sichtbar, denen Sie den
settings-profile-public-desc-part3 = oder
settings-profile-public-desc-part4 = OAuth-Scope gewähren. Felder leer lassen, um sie auszublenden.

# settings_profile.html - Links-Hinweis (code: Label|https://url)
settings-profile-links-hint-part1 = Eine pro Zeile, im Format
settings-profile-links-hint-part2 = .

# Flash-Nachrichten und Inline-Fehlertexte, in Rust-Handlern gesetzt.
flash-session-signed-out = Sitzung abgemeldet.
flash-session-signout-failed = Diese Sitzung konnte nicht abgemeldet werden.
flash-sessions-signed-out-others =
    { $count ->
        [one] { $count } andere Sitzung abgemeldet.
       *[other] { $count } andere Sitzungen abgemeldet.
    }
flash-sessions-signout-others-failed = Andere Sitzungen konnten nicht abgemeldet werden.
flash-app-access-revoked = Zugriff widerrufen.
flash-app-access-revoke-failed = Der Zugriff für diese Anwendung konnte nicht widerrufen werden.
flash-offline-passphrase-saved = Offline-Passphrase gespeichert. Registrierte Hosts übernehmen sie bei der nächsten Synchronisierung.
flash-offline-passphrase-save-failed = Ihre Offline-Passphrase konnte nicht gespeichert werden. Bitte versuchen Sie es erneut.
flash-offline-passphrase-too-short = Ihre Offline-Passphrase muss mindestens { $min_len } Zeichen lang sein.
flash-offline-passphrase-removed = Offline-Passphrase entfernt. Hosts verwerfen sie bei der nächsten Synchronisierung.
flash-offline-passphrase-none = Sie haben keine Offline-Passphrase festgelegt.
flash-offline-passphrase-remove-failed = Ihre Offline-Passphrase konnte nicht entfernt werden. Bitte versuchen Sie es erneut.
settings-profile-url-invalid = Website und Avatar-URL müssen gültige http:// oder https:// URLs sein.
settings-profile-link-url-invalid = Jede Link-URL muss eine gültige http:// oder https:// URL sein.
settings-save-failed = Wir konnten Ihre Änderungen nicht speichern. Bitte versuchen Sie es erneut.
