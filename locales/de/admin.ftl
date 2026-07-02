# Admin-Banner (admin_shell.html)
admin-banner-label = ADMINISTRATION
admin-banner-body = Sie befinden sich auf einer privilegierten Oberfläche. Alle Aktionen werden protokolliert.

# Admin-Navigation Sidebar-Kopfzeile (admin_nav.html)
admin-nav-heading = Administration
admin-nav-subtitle = Operator-Werkzeuge

# Admin-Navigation Abschnittsüberschriften
admin-nav-section-system = System
admin-nav-section-access = Zugriff
admin-nav-section-linux = Linux

# Admin-Navigation Einträge
admin-nav-status = Status
admin-nav-configuration = Konfiguration
admin-nav-audit = Audit
admin-nav-webhooks = Webhooks
admin-nav-license = Lizenz
admin-nav-identities = Identitäten
admin-nav-sessions = Sitzungen
admin-nav-clients = OAuth2-Clients
admin-nav-dcr-tokens = DCR-Tokens
admin-nav-saml = SAML SSO
admin-nav-hosts = Hosts
admin-nav-accounts = Konten

# Identitätenliste (identities_list.html)
admin-identities-page-title = Identitäten
admin-identities-subtitle = Kratos-verwaltete Identitäten und ihr Status.
admin-identities-search-placeholder = Nach ID oder E-Mail suchen
admin-identities-search-button = Suchen
admin-identities-col-email = E-Mail
admin-identities-col-state = Status
admin-identities-col-created = Erstellt
admin-identities-empty = Keine Identitäten gefunden.
admin-identities-prev = Zurück zum Anfang
admin-identities-next = Nächste Seite

# Identitätsdetail (identity_show.html)
admin-identity-status-active = aktiv
admin-identity-recovery-code-heading = Wiederherstellungscode (einmalig angezeigt)
admin-identity-recovery-link-heading = Wiederherstellungslink
admin-identity-recovery-note = Bitte geben Sie diesen Code über einen vertrauenswürdigen Kanal an den Nutzer weiter. Er wird nicht erneut angezeigt.
admin-identity-section-actions = Aktionen
admin-identity-action-generate-recovery = Wiederherstellungscode generieren
admin-identity-action-disable = Deaktivieren
admin-identity-action-enable = Aktivieren
admin-identity-action-delete = Löschen
admin-identity-section-traits = Traits
admin-identity-section-addresses = Verifizierbare Adressen
admin-identity-addresses-empty = Keine verifizierbaren Adressen für diese Identität.
admin-identity-status-verified = bestätigt
admin-identity-status-pending = ausstehend
admin-identity-section-credentials = Anmeldedaten
admin-identity-credentials-empty = Keine Anmeldedaten konfiguriert.
admin-identity-section-sessions = Letzte Sitzungen
admin-identity-sessions-empty = Kein Sitzungsverlauf.
admin-identity-action-revoke-session = Sitzung widerrufen

# Identitätsauswahl (identity_picker.html)
admin-identity-picker-page-title = Nutzer auswählen
admin-identity-picker-subtitle = Bitte wählen Sie eine Identität aus, um fortzufahren.
admin-identity-picker-invalid-return = Ungültiges Weiterleitungsziel.
admin-identity-picker-search-placeholder = Nach ID oder E-Mail suchen
admin-identity-picker-search-button = Suchen
admin-identity-picker-col-email = E-Mail
admin-identity-picker-col-state = Status
admin-identity-picker-col-created = Erstellt
admin-identity-picker-empty = Keine Identitäten gefunden.
admin-identity-picker-action-select = Auswählen
admin-identity-picker-prev = Zurück zum Anfang
admin-identity-picker-next = Nächste Seite

# Sitzungsliste (sessions_list.html)
admin-sessions-page-title = Sitzungen
admin-sessions-subtitle = Alle von Kratos verwalteten Sitzungen, über alle Identitäten hinweg.
admin-sessions-filter-active-only = Nur aktive Sitzungen
admin-sessions-col-identity = Identität
admin-sessions-col-authenticated = Authentifiziert
admin-sessions-col-expires = Läuft ab
admin-sessions-col-device = Gerät
admin-sessions-empty = Keine Sitzungen vorhanden.
admin-sessions-action-revoke = Widerrufen
admin-sessions-prev = Zurück zum Anfang
admin-sessions-next = Nächste Seite

# Bestätigungsdialog (confirm.html)
admin-confirm-cancel = Abbrechen

# Zugriffsverboten-Seite (forbidden.html)
admin-forbidden-back = Zurück zum Dashboard

# Admin-Fehlerseite (error.html)
admin-error-back = Zurück zum Admin-Status

# Clients-Liste (clients_list.html)
admin-clients-page-title = OAuth2-Clients
admin-clients-subtitle = Über Hydra registrierte Relying Parties.
admin-clients-action-new = Neuer Client
admin-clients-search-placeholder = Nach Client-Name oder ID suchen
admin-clients-filter-all-types = Alle Typen
admin-clients-filter-all-verifications = Alle Verifikationsstatus
admin-clients-filter-verified = Verifiziert
admin-clients-filter-unverified = Nicht verifiziert
admin-clients-search-button = Suchen
admin-clients-col-name = Name
admin-clients-col-type = Typ
admin-clients-col-grants = Grants
admin-clients-col-created = Erstellt
admin-clients-badge-unverified-title = Wurde von keinem Administrator geprüft
admin-clients-badge-self-registered = Selbst registriert
admin-clients-badge-self-registered-title = Über /oauth2/register registriert (RFC 7591)
admin-clients-empty = Keine Clients registriert.
admin-clients-prev = Zurück zum Anfang
admin-clients-next = Nächste Seite

# Client gemeinsame Badges (clients_list.html, client_show.html)
admin-client-badge-verified = Verifiziert
admin-client-badge-unverified = Nicht verifiziert
admin-client-badge-unverified-title = Dieser Client wurde von keinem Administrator geprüft. Die Zustimmungsseite warnt Nutzer.

# Client-Formular Seitenüberschriften (client_form.html)
admin-client-form-title-new = Neuer Client
admin-client-form-title-edit = Client bearbeiten
admin-client-form-heading-new = Neuer OAuth2-Client
admin-client-form-heading-edit = Client bearbeiten
admin-client-form-preset-note = Die Voreinstellungen für diesen Typ sind bereits ausgefüllt.
admin-client-form-preset-change = Typ ändern

# Gemeinsame Formularfelder (client_form.html, client_show.html Bearbeitungsformular)
admin-client-field-name = Client-Name
admin-client-field-grant-types = Grant-Typen
admin-client-grant-auth-code-hint = (benutzergesteuerter Login)
admin-client-grant-refresh-hint = (langlebige Sitzungen)
admin-client-grant-client-creds-hint = (Service-zu-Service)
admin-client-field-response-types = Antworttypen
admin-client-field-scope = Scope
admin-client-field-scope-hint = Leerzeichen-getrennte OAuth2-Scopes.
admin-client-field-redirect-uris = Redirect-URIs
admin-client-field-redirect-uris-hint = Eine pro Zeile (oder kommagetrennt).
admin-client-field-post-logout-uris = Post-Logout-Redirect-URIs
admin-client-section-logout-fanout = OIDC-Logout-Fan-out
admin-client-section-logout-fanout-desc = Wenn der Nutzer seine Sitzung über Forseti beendet, benachrichtigt Hydra die Clients über diese URIs, damit jede App ihre lokale Sitzung beenden kann. Leer lassen, um diesen Client vom Fan-out auszuschließen.
admin-client-field-backchannel-uri = Back-Channel-Logout-URI
admin-client-field-backchannel-uri-hint = Hydra sendet einen signierten Logout-Token per POST hierher (Server-zu-Server). Nur für server-gerenderte Webanwendungen und BFFs sinnvoll.
admin-client-field-backchannel-sid-prefix = { "" }
admin-client-field-backchannel-sid-suffix = claim im Back-Channel-Logout-Token erforderlich
admin-client-field-backchannel-sid-short = claim erforderlich
admin-client-field-frontchannel-uri = Front-Channel-Logout-URI
admin-client-field-frontchannel-uri-hint = Hydra lädt diese URL in einem iFrame beim Logout, damit jede App ihre Sitzungs-Cookies im Browser löschen kann.
admin-client-field-frontchannel-sid-prefix = { "" }
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = Query-Parameter beim Front-Channel-Logout erforderlich
admin-client-field-frontchannel-sid-short = Query-Parameter erforderlich
admin-client-field-token-auth = Token-Endpoint-Authentifizierungsmethode
admin-client-token-auth-post-hint = (Secret im POST-Body)
admin-client-token-auth-basic-hint = (Secret im Authorization-Header)
admin-client-token-auth-none-hint = (öffentlicher Client, PKCE)
admin-client-token-auth-none-short = none (öffentlich + PKCE)
admin-client-field-audience = Audience-Allowlist
admin-client-field-audience-hint-short = Eine pro Zeile. Hydra verlangt, dass Audience-Werte hier vorregistriert werden.
admin-client-field-require-pkce = PKCE erforderlich (informell)
admin-client-field-skip-consent = Vertrauenswürdiger Client (Zustimmungsseite überspringen)
admin-client-field-webhook-url = Konto-Löschungs-Webhook-URL
admin-client-action-cancel = Abbrechen

# Client-Detailseite (client_show.html)
admin-client-action-revoke-verification = Verifikation widerrufen
admin-client-action-mark-verified = Als verifiziert markieren
admin-client-action-rotate-secret = Secret rotieren
admin-client-action-delete = Löschen
admin-client-credentials-heading = Anmeldedaten: einmalig angezeigt
admin-client-credentials-note = Bitte jetzt kopieren. Sie werden nicht erneut angezeigt; Seite neu laden zum Schließen. Client-ID und Endpunkte oben sind nicht geheim und bleiben sichtbar.
admin-client-credentials-secret-label = Client-Secret
admin-client-credentials-rat-label = Registrierungs-Zugriffstoken
admin-client-credentials-rat-note = Gemäß RFC 7592: ermöglicht dem Client, seine eigene Registrierung zu verwalten (lesen/aktualisieren/löschen) über Hydras Dynamic-Client-Registration-API. Kann nicht neu ausgestellt werden, daher im Zweifelsfall aufbewahren.
admin-client-undoc-scopes-heading = Undokumentierte Scopes
admin-client-section-connection = Verbindungsdetails
admin-client-connection-intro = Diese Werte in die OIDC/OAuth-Client-Konfiguration der App eintragen.
admin-client-conn-client-id = Client-ID
admin-client-conn-issuer = Aussteller
admin-client-conn-discovery-url = Discovery-URL
admin-client-conn-auth-endpoint = Autorisierungsendpunkt
admin-client-conn-token-endpoint = Token-Endpunkt
admin-client-conn-userinfo-endpoint = Userinfo-Endpunkt
admin-client-conn-jwks-uri = JWKS-URI
admin-client-conn-end-session-endpoint = End-Session-Endpunkt
admin-client-section-config = Konfiguration
admin-client-config-sid-required = (sid erforderlich)
admin-client-config-iss-sid-required = (iss+sid erforderlich)
admin-client-not-configured = nicht konfiguriert
admin-client-audience-none = keine
admin-client-config-token-auth = Token-Endpoint-Auth
admin-client-config-require-pkce = PKCE erforderlich
admin-client-bool-yes = ja
admin-client-bool-no = nein
admin-client-config-trusted = Vertrauenswürdig (Zustimmung überspringen)
admin-client-config-created = Erstellt
admin-client-config-provenance-audience = Audience
admin-client-config-provenance-audience-note = (DCR-Aufrufer-deklariert)
admin-client-config-provenance-url = Verwendet bei
admin-client-config-provenance-url-note = (erstmals bei Zustimmung beobachtet)
admin-client-config-webhook = Konto-Löschungs-Webhook
admin-client-section-edit = Bearbeiten
admin-client-action-save = Änderungen speichern
admin-client-action-back = Zurück zur Liste

# Client-Typ-Auswahl (client_type_picker.html)
admin-client-type-page-title = Neuer Client
admin-client-type-heading = Neuer OAuth2-Client
admin-client-type-subtitle = Bitte den Anwendungstyp auswählen. Die nächste Seite ist dasselbe Formular, mit den richtigen Standardwerten bereits ausgefüllt, sodass Sie nicht versehentlich eine ungültige Kombination wählen.
admin-client-type-popular-heading = Bekannte Apps
admin-client-type-action-cancel = Abbrechen

# DCR-Token-Liste (dcr_tokens_list.html)
admin-dcr-page-title = DCR-Initial-Access-Tokens
admin-dcr-action-issue = Token ausstellen
admin-dcr-token-revealed-heading = Initial-Access-Token (einmalig angezeigt)
admin-dcr-col-status = Status
admin-dcr-col-note = Notiz
admin-dcr-col-created-by = Erstellt von
admin-dcr-col-created = Erstellt
admin-dcr-col-expires = Läuft ab
admin-dcr-col-uses-left = Verbleibende Nutzungen
admin-dcr-status-active = Aktiv
admin-dcr-status-revoked = Widerrufen
admin-dcr-status-expired = Abgelaufen
admin-dcr-status-exhausted = Erschöpft
admin-dcr-empty-prefix = Keine Tokens ausgestellt.
admin-dcr-empty-link = Jetzt ausstellen
admin-dcr-empty-suffix = um die Selbstregistrierung zu ermöglichen.
admin-dcr-action-revoke = Widerrufen

# Neues DCR-Token (dcr_token_new.html)
admin-dcr-new-page-title = DCR-Token ausstellen
admin-dcr-new-heading = DCR-Initial-Access-Token ausstellen
admin-dcr-new-field-note = Notiz
admin-dcr-new-field-note-placeholder = Wofür ist dieses Token? (z. B. 'Claude Desktop für formshive')
admin-dcr-new-field-note-hint = Optional, nur für Ihre Unterlagen. Der Client-Autor sieht dies nicht.
admin-dcr-new-field-ttl = TTL (Stunden)
admin-dcr-new-field-ttl-hint = Leer lassen für kein Ablaufdatum.
admin-dcr-new-field-max-uses = Maximale Nutzungen
admin-dcr-new-action-cancel = Abbrechen

# Statusseite (status.html)
admin-status-page-title = Status
admin-status-heading = Systemstatus
admin-status-subtitle = Echtzeitstatus der IdP-Komponenten, der Courier-Warteschlange und der Build-Versionen.
admin-status-issuer-label = Aussteller
admin-status-issuer-config-link = Konfiguration anzeigen →
admin-status-warning-db-label = Datenbank
admin-status-warning-db-body = SQLite mit produktionsähnlicher Bereitstellung. Multi-Instanz-Setups korrumpieren die Datenbank. Für HA zu Postgres wechseln.
admin-status-warning-webhook-label = Webhook-Fan-out
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } fehlgeschlagene Konto-Löschungs-Webhook-Zeile
       *[other] { $count } fehlgeschlagene Konto-Löschungs-Webhook-Zeilen
    }
admin-status-dead-webhook-middle = (Empfänger werden nicht benachrichtigt).
admin-status-dead-webhook-open = /admin/webhooks öffnen
admin-status-dead-webhook-action = um sie erneut zu senden oder zu verwerfen.
admin-status-section-services = Dienste
admin-status-col-service = Dienst
admin-status-col-state = Status
admin-status-col-detail = Detail
admin-status-state-up = aktiv
admin-status-state-down = inaktiv
admin-status-section-courier = Courier-Warteschlange
admin-status-courier-pending = Ausstehend (in Warteschlange)
admin-status-courier-failed = Fehlgeschlagen (aufgegeben)
admin-status-courier-last-webhook = Letzter Audit-Webhook
admin-status-courier-never = nie
admin-status-section-audit = Audit
admin-status-audit-write-failures = Audit-Schreibfehler (seit Start)
admin-status-audit-write-failures-note-prefix = Zeilen können aus den strukturierten
admin-status-audit-write-failures-note-suffix = stderr-Zeilen wiederhergestellt werden, die Forseti zum Zeitpunkt des Fehlers ausgegeben hat.
admin-status-audit-webhook-rejected = Abgelehnte Audit-Webhooks (seit Start)
admin-status-audit-webhook-rejected-note-prefix = Fehlerhafte Payloads oder unbekannte Aktionen, wahrscheinlich ein Kratos-Hook/Konfigurations-Konflikt. Überprüfen Sie die
admin-status-audit-webhook-rejected-note-suffix = warn-Logs.
admin-status-audit-freshness = Audit-Webhook-Frische-Anomalien (seit Start)
admin-status-audit-freshness-note = Payloads mit veralteten oder zukünftigen Zeitstempeln, meist durch langsame Abläufe oder Uhrabweichungen. Zeilen werden weiterhin aufgezeichnet und markiert.
admin-status-section-license = Lizenz
admin-status-license-oss-prefix = OSS-Bereitstellung.
admin-status-license-oss-link = Lizenz aktivieren
admin-status-license-oss-suffix = um Premium-Funktionen freizuschalten.
admin-status-section-build = Build-Versionen
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = Datenbank

# Konfigurationsseite (configuration.html)
admin-config-page-title = Konfiguration
admin-config-subtitle = Konfiguration dieses Identity Providers: OIDC-Endpunkte und Fähigkeiten, Signaturschlüssel und Kratos-Identitätsschemata.
admin-config-discovery-warning-label = OIDC-Discovery
admin-config-discovery-warning-body = Das Hydra-Discovery-Dokument ist nicht erreichbar. Endpunkte und Fähigkeiten werden ausgeblendet, bis es wieder verfügbar ist.
admin-config-section-oidc = OIDC-Endpunkte
admin-config-field-issuer = Aussteller
admin-config-field-discovery-url = Discovery-URL
admin-config-field-authorization = Autorisierung
admin-config-field-token = Token
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = Sitzung beenden
admin-config-field-registration = Registrierung (DCR)
admin-config-field-revocation = Widerruf
admin-config-section-capabilities = Fähigkeiten
admin-config-cap-scopes = Scopes
admin-config-cap-grant-types = Grant-Typen
admin-config-cap-response-types = Antworttypen
admin-config-cap-token-auth-methods = Token-Endpoint-Authentifizierungsmethoden
admin-config-cap-pkce-methods = PKCE-Methoden
admin-config-cap-id-token-signing-algs = ID-Token-Signaturalgorithmen
admin-config-cap-subject-types = Subjekttypen
admin-config-cap-backchannel-logout = Back-Channel-Logout
admin-config-cap-frontchannel-logout = Front-Channel-Logout
admin-config-cap-yes = Ja
admin-config-cap-no = Nein
admin-config-section-signing-keys = Signaturschlüssel (JWKS)
admin-config-signing-keys-unavailable = Nicht verfügbar: öffentliche Schlüssel von Hydra konnten nicht abgerufen werden.
admin-config-signing-keys-empty = Hydra hat keine Signaturschlüssel angekündigt.
admin-config-col-key-id = Schlüssel-ID
admin-config-col-alg = Alg
admin-config-col-type = Typ
admin-config-col-use = Verwendung
admin-config-section-schemas = Kratos-Identitätsschemata
admin-config-schemas-unavailable = Nicht verfügbar: Identitätsschemata konnten nicht von Kratos abgerufen werden.
admin-config-schemas-empty = Keine Identitätsschemata registriert.

# Audit-Liste (audit.html)
admin-audit-page-title = Audit
admin-audit-subtitle = Unveränderliches Ereignisprotokoll. Erfasst Forseti-seitige Admin-Aktionen, OAuth-Grants, Sitzungsänderungen und via Webhook übermittelte Kratos-Flow-Abschlüsse. Aufbewahrung ist operator-konfiguriert (`[audit].audit_retention_days`); Bereinigung ist ein CLI-Unterbefehl, nicht automatisch.
admin-audit-filter-email = E-Mail enthält
admin-audit-filter-action = Aktionspräfix
admin-audit-filter-severity = Schweregrad
admin-audit-filter-since = Seit
admin-audit-severity-any = Alle
admin-audit-severity-info = Info
admin-audit-severity-warning = Warnung
admin-audit-severity-error = Fehler
admin-audit-severity-critical = Kritisch
admin-audit-filter-button = Filtern
admin-audit-col-target = Ziel
admin-audit-col-severity = Schweregrad
admin-audit-col-when = Zeitpunkt
admin-audit-col-actor = Akteur
admin-audit-col-action = Aktion
admin-audit-col-actions = Aktionen
admin-audit-empty = Keine Ereignisse entsprechen den aktuellen Filtern.
admin-audit-badge-critical = kritisch
admin-audit-badge-error = Fehler
admin-audit-badge-warning = Warnung
admin-audit-action-view = Anzeigen
admin-audit-prev = ‹ Zurück
admin-audit-next = Weiter ›

# Audit-Detail (audit_show.html)
admin-audit-back = ← Zurück zur Audit-Übersicht
admin-audit-show-section-event = Ereignis
admin-audit-show-outcome = Ergebnis
admin-audit-show-success = Erfolg
admin-audit-show-failure = Fehler
admin-audit-show-section-actor = Akteur
admin-audit-show-field-kind = Typ
admin-audit-show-field-email = E-Mail
admin-audit-show-none = keine
admin-audit-show-field-identity-id = Identitäts-ID
admin-audit-show-section-target = Ziel
admin-audit-show-field-label = Bezeichnung
admin-audit-show-deleted = (gelöscht)
admin-audit-show-field-target-id = Ziel-ID
admin-audit-show-section-metadata = Metadaten
admin-audit-show-section-request-context = Anforderungskontext
admin-audit-show-field-ip-hash = IP-Hash
admin-audit-show-field-user-agent = User Agent
admin-audit-show-field-request-id = Anforderungs-ID
admin-audit-show-field-org-id = Organisations-ID

# Webhooks-Liste (webhooks.html)
admin-webhooks-page-title = Webhooks
admin-webhooks-heading = Fehlgeschlagene Webhooks
admin-webhooks-subtitle = Konto-Löschungsbenachrichtigungen, die alle Wiederholungsversuche (12 Versuche oder 72 Stunden, je nachdem, was zuerst eintritt) ausgeschöpft haben. Klicken Sie auf eine Zeile für den vollständigen Payload und den letzten Fehler, oder stellen Sie die Sendung aus der Übersicht erneut in die Warteschlange, wenn Sie wissen, dass der Empfänger wieder erreichbar ist.
admin-webhooks-empty = Keine fehlgeschlagenen Zeilen. Alle Nachrichten werden zugestellt.
admin-webhooks-col-client = Client
admin-webhooks-col-event = Ereignis
admin-webhooks-col-attempts = Versuche
admin-webhooks-col-age = Alter
admin-webhooks-col-actions = Aktionen
admin-webhooks-deleted = (gelöscht)
admin-webhooks-action-view = Anzeigen
admin-webhooks-action-requeue = Erneut einreihen

# Webhook-Detail (webhook_show.html)
admin-webhook-back = ← Zurück zu Webhooks
admin-webhook-heading = Fehlgeschlagener Webhook
admin-webhook-action-requeue = Erneut einreihen
admin-webhook-action-discard = Verwerfen
admin-webhook-section-delivery = Zustellung
admin-webhook-field-client = Client
admin-webhook-deleted = (gelöscht)
admin-webhook-field-state = Status
admin-webhook-field-url = URL
admin-webhook-field-attempts = Versuche
admin-webhook-field-created = Erstellt
admin-webhook-field-next-attempt = Nächster Versuch
admin-webhook-section-last-error = Letzter Fehler
admin-webhook-section-payload = Signierter Payload

# POSIX-Kontenliste (posix_list.html)
admin-posix-page-title = POSIX-Konten
admin-posix-subtitle = Kratos-Identitäten, materialisiert als Linux-Konten (uid/gid + SSH-Schlüssel) für den NSS-Resolver.
admin-posix-seats-label = Belegte Plätze:
admin-posix-license-note = Eine kommerzielle Linux-Authentifizierungslizenz erhöht das Limit.
admin-posix-action-provision = Konto bereitstellen
admin-posix-col-username = Benutzername
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Status
admin-posix-col-created = Erstellt
admin-posix-empty-prefix = Keine aktiven POSIX-Konten.
admin-posix-empty-link = Jetzt bereitstellen
admin-posix-empty-suffix = aus einer Kratos-Identität.
admin-posix-status-enabled = aktiviert
admin-posix-status-disabled = deaktiviert
admin-posix-action-manage = Verwalten

# POSIX-Kontodetail (posix_account.html)
admin-posix-action-disable = Deaktivieren
admin-posix-action-enable = Aktivieren
admin-posix-action-delete = Löschen
admin-posix-ssh-keys-heading = SSH-Schlüssel
admin-posix-ssh-empty = Noch keine SSH-Schlüssel.
admin-posix-ssh-key-added-prefix = hinzugefügt
admin-posix-ssh-action-remove = Entfernen
admin-posix-ssh-field-public-key = Öffentlicher Schlüssel
admin-posix-ssh-field-comment = Kommentar (optional)
admin-posix-ssh-action-add = Schlüssel hinzufügen
admin-posix-teams-heading = Teams
admin-posix-hosts-heading = Erreichbare Hosts
admin-posix-back = ← Alle POSIX-Konten

# Neues POSIX-Konto (posix_new.html)
admin-posix-new-page-title = POSIX-Konto bereitstellen
admin-posix-new-heading = POSIX-Konto bereitstellen
admin-posix-new-choose-identity = Identität auswählen, die bereitgestellt werden soll.
admin-posix-new-action-select-user = Nutzer auswählen
admin-posix-new-or-enter-directly = Oder direkt eingeben
admin-posix-new-placeholder-id = UUID oder E-Mail
admin-posix-new-action-continue = Weiter
admin-posix-new-provision-intro = Kratos-Identität als Linux-Konto materialisieren. Eine uid/gid wird automatisch vergeben und eine primäre Gruppe erstellt.
admin-posix-new-selected-prefix = Ausgewählt:
admin-posix-new-action-change = Ändern
admin-posix-new-field-username = Benutzername
admin-posix-new-username-hint = Aus der E-Mail-Adresse vorgeschlagen; Sie können ihn bearbeiten. 1–32 Zeichen, Kleinbuchstaben, beginnt mit einem Buchstaben oder Unterstrich. Dies wird der POSIX-Anmeldename.
admin-posix-new-field-shell = Anmelde-Shell
admin-posix-new-action-cancel = Abbrechen

# Hosts-Liste (hosts_list.html)
admin-hosts-page-title = Hosts
admin-hosts-subtitle = Linux-Maschinen, die gegen Forsetis POSIX/NSS-Resolver eingeschrieben sind. Jeder Host authentifiziert sich mit einem Einmal-Secret, das bei der Einschreibung angezeigt wird.
admin-hosts-action-enroll = Host einschreiben
admin-hosts-credential-heading = Host-Zugangsdaten (einmalig angezeigt)
admin-hosts-credential-note-prefix = Format:
admin-hosts-credential-note-suffix = . Den Host-Agenten jetzt mit diesen Zugangsdaten konfigurieren. Das reine Secret wird nicht gespeichert, nur sein SHA-256-Hash.
admin-hosts-col-hostname = Hostname
admin-hosts-col-teams = Teams
admin-hosts-col-force-mfa = MFA erzwingen
admin-hosts-col-enrolled = Eingeschrieben
admin-hosts-col-last-seen = Zuletzt gesehen
admin-hosts-empty-prefix = Keine Hosts eingeschrieben.
admin-hosts-empty-link = Jetzt einschreiben
admin-hosts-empty-suffix = damit POSIX-Konten aufgelöst werden können.
admin-hosts-status-mfa-pending = MFA (ausstehend)
admin-hosts-mfa-pending-title = Gespeichert, aber noch nicht durchgesetzt; Durchsetzung erfolgt mit dem interaktiven Login (PAM).
admin-hosts-action-edit = Bearbeiten
admin-hosts-action-rotate = Rotieren
admin-hosts-action-revoke = Widerrufen

# Host bearbeiten (hosts_edit.html)
admin-hosts-edit-page-title = Host bearbeiten
admin-hosts-edit-intro = Host-Bezeichnung, MFA-Flag und zugeordnete Teams aktualisieren. Das Secret wird hier nicht angezeigt; über die Hosts-Liste rotieren, wenn ein neues benötigt wird.
admin-hosts-field-hostname = Hostname
admin-hosts-hostname-hint = Eine Bezeichnung für Ihre Unterlagen. Muss nicht mit dem tatsächlichen Hostnamen der Maschine übereinstimmen.
admin-hosts-field-org = Organisation
admin-hosts-org-fixed-note = Die Organisation eines Hosts ist bei der Einschreibung festgelegt und kann hier nicht geändert werden.
admin-hosts-field-allowed-teams = Erlaubte Teams
admin-hosts-teams-empty = Noch keine Teams vorhanden. Dieser Host erlaubt allen Organisationsmitgliedern den Zugriff. Um einen Host auf bestimmte Teams zu beschränken, wird die Organisations-Funktion benötigt.
admin-hosts-teams-hint = Diesen Host auf Mitglieder der ausgewählten Teams beschränken. Keine Auswahl bedeutet, alle Organisationsmitglieder sind erlaubt.
admin-hosts-field-force-mfa = MFA auf diesem Host erzwingen
admin-hosts-force-mfa-hint = Jetzt gespeichert; wird durchgesetzt, sobald der interaktive Login (PAM) verfügbar ist.
admin-hosts-action-cancel = Abbrechen

# Neuer Host (hosts_new.html)
admin-hosts-new-heading = Linux-Host einschreiben
admin-hosts-new-intro-prefix = Auf der nächsten Seite wird einmalig ein Secret angezeigt. Den Host-Agenten mit dem Zugangsdaten-Format
admin-hosts-new-intro-suffix = konfigurieren, das dort angezeigt wird.
admin-hosts-org-belongs-hint = Der Host gehört zu dieser Organisation. Kann nach der Einschreibung nicht mehr geändert werden.
admin-hosts-new-teams-empty = Noch keine Teams vorhanden. Dieser Host wird allen Organisationsmitgliedern den Zugriff erlauben. Um ihn auf bestimmte Teams zu beschränken, wird die Organisations-Funktion benötigt.
admin-hosts-new-teams-scope-hint = Diesen Host auf Mitglieder der ausgewählten Teams beschränken. Nur Teams der gewählten Organisation gelten; keine Auswahl bedeutet, alle Organisationsmitglieder sind erlaubt.

# SAML-SSO-Liste (saml_list.html)
admin-saml-page-title = SAML SSO
admin-saml-subtitle = Unternehmens-SAML-Verbindungen, eine pro Organisation. IdP-Metadaten und Zertifikate liegen in Jackson; Forseti verwaltet den Anker-Datensatz und den Aktivierungsschalter.
admin-saml-action-new = Neue Verbindung
admin-saml-grace-notice = Lizenz im Kulanzzeitraum. SAML-Verbindungen sind schreibgeschützt, bis die Lizenz erneuert wird. SSO-Anmeldungen funktionieren weiterhin.
admin-saml-col-org = Organisation
admin-saml-col-connection = Verbindung
admin-saml-col-sso-url = SSO-URL
admin-saml-col-enabled = Aktiviert
admin-saml-empty-prefix = Noch keine SAML-Verbindungen.
admin-saml-empty-link = Jetzt erstellen
admin-saml-empty-suffix = um SSO für eine Organisation zu aktivieren.
admin-saml-status-enabled = Aktiviert
admin-saml-status-disabled = Deaktiviert
admin-saml-action-disable = Deaktivieren
admin-saml-action-enable = Aktivieren
admin-saml-action-delete = Löschen
admin-saml-idp-values-heading = Werte für den IdP-Administrator des Kunden
admin-saml-idp-values-intro = Diese Werte an die Person weitergeben, die die SAML-App auf der Identity-Provider-Seite konfiguriert. Sie sind für jede Verbindung gleich.
admin-saml-idp-acs-url = ACS-URL
admin-saml-idp-entity-id = SP-Entity-ID

# Audit-Paginierung
admin-audit-range = Zeige { $from }–{ $to } von { $total } Zeilen.
admin-audit-page = Seite { $page }
admin-saml-entity-id-note-prefix = Die Entity-ID folgt Jacksons
admin-saml-entity-id-note-suffix = -Einstellung; dort ändern, wenn der Standardwert überschrieben wird.

# Neue SAML-Verbindung (saml_new.html)
admin-saml-new-page-title = Neue SAML-Verbindung
admin-saml-new-intro = Organisation mit ihrem Identity Provider verbinden. Die IdP-Metadaten-XML einfügen oder eine Metadaten-URL angeben, die Jackson selbst abruft: genau eine der beiden Optionen.
admin-saml-new-field-org = Organisation
admin-saml-new-org-hint = Eine Verbindung pro Organisation.
admin-saml-new-field-name = Verbindungsname
admin-saml-new-name-hint = Nur für Ihre Unterlagen; Mitglieder sehen dies nicht.
admin-saml-new-field-metadata-url = Metadaten-URL
admin-saml-new-metadata-url-hint = Leer lassen, wenn die XML-Metadaten unten eingefügt werden.
admin-saml-new-metadata-url-https-note = Jackson ruft nur HTTPS-Metadaten-URLs (oder localhost) ab. Für einfaches HTTP den XML-Inhalt unten einfügen.
admin-saml-new-field-metadata-xml = Metadaten-XML
admin-saml-new-metadata-xml-hint = Leer lassen, wenn oben eine Metadaten-URL angegeben wurde.
admin-saml-new-action-create = Verbindung erstellen
admin-saml-new-action-cancel = Abbrechen

# Inline-Code-Aufteilungen (Punkt 8: 2+ Code-Elemente pro Zeichenkette)

# client_form.html - Antworttypen-Hinweis (code: code, token)
admin-client-field-response-types-hint-part1 = Durch Komma getrennt, z. B.
admin-client-field-response-types-hint-part2 = (Auth-Code) oder
admin-client-field-response-types-hint-part3 = (Client-Credentials).

# client_form.html - Audience-Hinweis (code: audience=<value>)
admin-client-field-audience-hint-part1 = Eine pro Zeile. Hydra verlangt, dass Audience-Werte hier vorregistriert werden (RFC 8707 wird noch nicht unterstützt). Clients übergeben
admin-client-field-audience-hint-part2 = bei der Autorisierungsanfrage.

# client_form.html - PKCE-Hinweis (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = Die globale Durchsetzung liegt in
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). Dieses Flag dient als Absichtsmarkierung des Operators.

# client_form.html + client_show.html - Webhook-Hinweis (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = Wenn ein Nutzer sein Konto löscht, sendet Forseti ein RFC 8417 Security Event Token (RISC
admin-client-field-webhook-hint-part2 = ) hierher per POST. Leer lassen zum Deaktivieren. Empfänger prüfen die JWS-Signatur gegen Forsetis JWKS unter
admin-client-field-webhook-hint-part3 = .

# client_show.html - undokumentierte Scopes Beschreibung (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = Diese Scopes sind auf diesem Client registriert, haben aber keinen Eintrag unter
admin-client-undoc-scopes-desc-part2 = in
admin-client-undoc-scopes-desc-part3 = . Die Zustimmungsseite fällt für sie auf den rohen Scope-Namen zurück.

# client_show.html - Discovery-Fehler (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = Hydras Discovery-Endpunkt ist nicht erreichbar, daher sind Aussteller und Endpunkte ausgeblendet, um falsche Werte zu vermeiden. Bitte selbst abrufen unter
admin-client-discovery-error-part2 = .

# client_show.html - Bearbeitungsbereich Einleitung (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Felder des Clients unten aktualisieren. Änderungen werden über Hydras
admin-client-edit-intro-part2 = übertragen; nicht betroffene Felder bleiben erhalten.

# dcr_tokens_list.html - Untertitel (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Bearer-Tokens, die
admin-dcr-subtitle-part2 = autorisieren. Einem MCP-Client-Entwickler übergeben, damit er sich selbst registrieren kann, ohne dass Sie es manuell tun müssen.

# dcr_tokens_list.html - Angezeigtes-Token Beschreibung (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Mit dem Client-Autor teilen. Dieser sendet es als
admin-dcr-revealed-desc-part2 = beim Aufruf von
admin-dcr-revealed-desc-part3 = . Den Rohwert speichern wir nicht, nur seinen SHA-256-Hash.

# dcr_token_new.html - Untertitel (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = Das Token wird einmalig auf der nächsten Seite angezeigt. Es an den Client-Autor weitergeben. Dieser sendet es als
admin-dcr-new-subtitle-part2 = bei einem einzelnen
admin-dcr-new-subtitle-part3 = Aufruf.

# dcr_token_new.html - Max-Nutzungen Hinweis (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = Leer lassen für unbegrenzte Nutzung. Einmalige Nutzung (
admin-dcr-new-field-max-uses-hint-part2 = ) ist der sicherste Standard.

# client_type_picker.html - Bekannte-Apps Beschreibung (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Für eine bekannte App vorausgefüllt. URLs verwenden
admin-client-type-popular-desc-part2 = (und manchmal
admin-client-type-popular-desc-part3 = ) als Platzhalter. Nach dem Öffnen des Formulars durch eigene Werte ersetzen.

# posix_account.html - SSH-Schlüssel Absatz (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = Hier hinterlegte öffentliche Schlüssel werden dem sshd des Geräts bereitgestellt (
admin-posix-ssh-keys-desc-part2 = ), damit sich dieser Nutzer mit seinem Schlüssel per
admin-posix-ssh-keys-desc-part3 = einloggen kann, ohne eine gerätespezifische
admin-posix-ssh-keys-desc-part4 = Datei zu benötigen. Erfordert den sshd-Hook des Hosts (automatisch eingerichtet durch den
admin-posix-ssh-keys-desc-part5 = Guix-Dienst; manuelle sshd-Konfiguration auf anderen Distributionen). Nicht für Konsolen- oder PAM-Login verwendet.

# posix_new.html - Shell-Hinweis (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Muss auf den Geräten vorhanden sein, die dieses Konto bedienen;
admin-posix-new-shell-hint-part2 = ist der sichere Cross-Distro-Standard (Guix hat kein
admin-posix-new-shell-hint-part3 = ). Das Home-Verzeichnis wird aus dem Home-Präfix und dem Benutzernamen abgeleitet.

# saml_list.html - Nicht-konfiguriert-Block (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = ist nicht konfiguriert
admin-saml-not-configured-part2 = fügen Sie die Jackson-Bridge-Einstellungen zu
admin-saml-not-configured-part3 = hinzu, um SAML SSO zu aktivieren. Siehe
admin-saml-not-configured-part4 = .

# Admin-Flash-Meldungen (als Banner nach einer Weiterleitung angezeigt)
flash-identity-disabled = Identität deaktiviert.
flash-identity-enabled = Identität aktiviert.
flash-session-revoked = Sitzung widerrufen.
flash-client-create-failed = Client konnte nicht erstellt werden: { $error }
flash-client-account-deletion-url-rejected = Konto-Lösch-URL abgelehnt: { $error }
flash-client-secret-stage-failed = Client erstellt, aber wir konnten das Secret nicht für die einmalige Anzeige bereitstellen. Rotieren Sie das Secret, um einen neuen Wert zu erhalten.
