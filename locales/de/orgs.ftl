# Gemeinsame Feldbezeichnungen für alle Organisationsseiten
orgs-field-name = Name
orgs-field-slug = Slug
orgs-field-email = E-Mail
orgs-field-role = Rolle

# Organisations-Umschalter (Navigations-Dropdown)
orgs-switcher-label = Organisation wechseln
orgs-switcher-manage-link = Organisationen verwalten

# Organisationsliste (list.html)
orgs-list-title = Organisationen
orgs-list-heading = Ihre Organisationen
orgs-list-create-heading = Neue Organisation erstellen
orgs-list-field-slug-optional = Slug (optional)
orgs-list-action-create = Erstellen
orgs-list-field-access-mode = Zugriffsmodus
orgs-list-mode-internal-title = Intern
orgs-list-mode-internal-body = Nur auf Einladung. Mitglieder treten per Einladung bei (später auch über eine verifizierte Firmendomäne).
orgs-list-mode-external-title = Extern
orgs-list-mode-external-body = Öffentliche Selbstregistrierung. Das Mitgliederverzeichnis ist auf Administratoren beschränkt.
orgs-list-tier-gate-heading = Mehrere Organisationen sind ein { $tier }-Feature
orgs-list-license-missing = Ihre aktuelle Lizenz enthält die Funktion „Organisationen“ nicht.
orgs-list-unlicensed = Diese { $brand }-Installation läuft ohne Lizenz, daher sind zusätzliche Organisationen über die Standardorganisation hinaus gesperrt.
orgs-list-license-upgrade = Aktivieren oder aktualisieren Sie eine Lizenz, um weitere zu erstellen.
orgs-list-link-get-license = Lizenz erwerben
orgs-list-link-activate-license = Bestehende Lizenz aktivieren

# Organisationsübersicht - Inhaberansicht (overview.html)
orgs-overview-subtitle-default = Dies ist die Standardorganisation dieser { $brand }-Installation. Alle neu registrierten Benutzer werden automatisch Mitglied.
orgs-overview-subtitle = Verwalten Sie die Einstellungen, das Branding und die Mitgliedschaft dieser Organisation.
orgs-overview-identity-heading = Identität
orgs-overview-quicklinks-heading = Schnelllinks
orgs-link-branding = Branding
orgs-link-members = Mitglieder
orgs-link-teams = Teams
orgs-link-domains = Domains
orgs-sso-heading = Enterprise SSO
orgs-sso-status-enabled = aktiviert
orgs-sso-status-disabled = deaktiviert
orgs-sso-operator-note = SSO-Verbindungen werden vom Betreiber verwaltet.
orgs-access-mode-heading = Zugriffsmodus
orgs-access-mode-label = Modus
orgs-access-mode-internal = Intern
orgs-access-mode-external = Extern
orgs-access-mode-note-default = Die Standardorganisation ist immer intern.
orgs-access-mode-note-internal = Mitglieder treten per Einladung bei. Der Wechsel zu extern aktiviert die öffentliche Registrierung.
orgs-access-mode-note-external = Die öffentliche Registrierung ist aktiviert. Das Mitgliederverzeichnis ist im externen Modus auf Administratoren beschränkt.
orgs-access-mode-action-switch-external = Zu extern wechseln
orgs-access-mode-action-switch-internal = Zu intern wechseln
orgs-confirm-switch-external = Zu extern wechseln? Dies aktiviert die öffentliche Registrierungsseite und beschränkt das Mitgliederverzeichnis auf Administratoren.
orgs-confirm-switch-internal = Zu intern wechseln? Dies deaktiviert die öffentliche Registrierungsseite. Bestehende Mitglieder behalten ihre Mitgliedschaft.
orgs-danger-heading = Gefahrenbereich
orgs-danger-delete-body = Diese Organisation endgültig löschen. Forseti verweigert dies, wenn noch OAuth2-Clients zugeordnet sind.
orgs-danger-delete-action = Organisation löschen
orgs-confirm-delete-org = { $name } löschen? Dies kann nicht rückgängig gemacht werden.

# Organisationsübersicht - Mitgliederansicht (overview_info.html)
orgs-info-subtitle-default = Dies ist die Standardorganisation dieser { $brand }-Installation. Sie sind Mitglied.
orgs-info-subtitle = Sie sind Mitglied dieser Organisation.
orgs-info-org-heading = Organisation
orgs-info-members-label = Mitglieder
orgs-info-managed-by-heading = Verwaltet von
orgs-info-managed-by-note = Wenden Sie sich an einen Inhaber, um Name, Branding oder Mitgliedschaft der Organisation zu ändern.

# Mitgliederseite (members.html)
orgs-members-page-heading = Mitglieder
orgs-members-subtitle = Inhaber können Mitglieder befördern / zurückstufen und alle außer dem letzten Inhaber entfernen.
orgs-members-visibility-note-admins-only = Nur Administratoren können die vollständige Mitgliederliste einsehen.
orgs-members-visibility-note-same-group = Sie sehen Mitglieder, die mit Ihnen in einem Team sind.
orgs-members-visibility-note-all = Alle Mitglieder sind sichtbar.
orgs-members-invite-heading = Per E-Mail einladen
orgs-members-role-member = Mitglied
orgs-members-role-owner = Inhaber
orgs-members-action-invite = Einladung senden
orgs-members-visibility-heading = Verzeichnissichtbarkeit
orgs-members-visibility-label = Wer kann die Mitgliederliste einsehen
orgs-members-visibility-opt-all = Alle Mitglieder
orgs-members-visibility-opt-same-group = Nur das gleiche Team
orgs-members-visibility-opt-admins-only = Nur Administratoren
orgs-members-visibility-hint = „Nur das gleiche Team“ erfordert mindestens ein bestehendes Team.
orgs-members-col-joined = Beigetreten
orgs-members-badge-you = Sie
orgs-members-badge-hidden = Ausgeblendet
orgs-members-action-show = Anzeigen
orgs-members-action-hide = Ausblenden
orgs-members-action-update = Aktualisieren
orgs-members-action-remove = Entfernen
orgs-confirm-remove-member = { $email } entfernen?
orgs-members-invites-heading = Ausstehende Einladungen
orgs-members-invites-col-sent = Gesendet
orgs-members-invites-col-expires = Läuft ab

# Teamseite (teams.html)
orgs-teams-page-heading = Teams
orgs-teams-subtitle = Fassen Sie Mitglieder in Teams zusammen. Teams steuern den Host-Zugriff und die Verzeichnissichtbarkeit für das gleiche Team.
orgs-teams-create-heading = Team erstellen
orgs-teams-action-create = Team erstellen
orgs-teams-col-team = Team
orgs-teams-col-members = Mitglieder
orgs-teams-action-rename = Umbenennen
orgs-teams-action-manage-members = Mitglieder verwalten
orgs-teams-action-delete = Löschen
orgs-confirm-delete-team = { $name } löschen? Das Team und alle seine Mitgliedschaften werden entfernt.
orgs-teams-selected-heading = Mitglieder von { $team }
orgs-teams-add-member-label = Mitglied hinzufügen
orgs-teams-action-add = Hinzufügen

# Domains-Seite (domains.html)
orgs-domains-page-heading = Zulässige Domains
orgs-domains-subtitle = Nutzer mit einer verifizierten E-Mail-Adresse an einer bestätigten Domain treten dieser Organisation automatisch bei.
orgs-domains-add-heading = Domain hinzufügen
orgs-domains-field-domain = Domain
orgs-domains-field-method = Verifizierungsmethode
orgs-domains-method-http_file = HTTP-Datei
orgs-domains-method-dns_txt = DNS-TXT-Eintrag
orgs-domains-method-email = E-Mail
orgs-domains-action-add = Domain hinzufügen
orgs-domains-col-domain = Domain
orgs-domains-col-method = Methode
orgs-domains-col-status = Status
orgs-domains-status-verified = Verifiziert
orgs-domains-status-pending = Ausstehend
orgs-domains-instructions-http_file = Stelle { $token } unter https://{ $domain }/.well-known/forseti-domain-verify bereit
orgs-domains-instructions-dns_txt = Erstelle einen TXT-Eintrag bei _forseti-verify.{ $domain } mit dem Wert: { $token }
orgs-domains-instructions-email = Ein Code wurde an admin@{ $domain } und postmaster@{ $domain } gesendet. Unten einfügen.
orgs-domains-action-verify = Verifizieren
orgs-domains-action-confirm = Code bestätigen
orgs-domains-field-token = Bestätigungscode
orgs-domains-action-remove = Entfernen
orgs-confirm-remove-domain = { $domain } entfernen? Der automatische Beitritt für diese Domain wird sofort gestoppt.
orgs-domains-policy-heading = Beitrittsrichtlinie
orgs-domains-policy-subtitle = Legen Sie fest, wie Benutzer mit einer verifizierten E-Mail-Adresse einer nachgewiesenen Domain dieser Organisation beitreten.
orgs-domains-policy-field = Richtlinie
orgs-domains-policy-invite-only = Nur auf Einladung
orgs-domains-policy-auto-join = Benutzer verifizierter Domains können selbst beitreten
orgs-domains-policy-save = Richtlinie speichern

# Branding-Seite (branding.html)
orgs-branding-page-heading = Branding
orgs-branding-subtitle-prefix = Das Standardbranding von Forseti kann mit dem Logo und der Support-E-Mail dieser Organisation überschrieben werden. Greift auf
orgs-branding-subtitle-infix = in
orgs-branding-subtitle-suffix = zurück, wenn nicht gesetzt.
orgs-branding-field-logo-url = Logo-URL
orgs-branding-field-logo-file = Logo-Bild (PNG, JPEG oder WebP; max. 256 KB)
orgs-branding-logo-remove = Logo entfernen
orgs-branding-logo-save = Logo hochladen
orgs-branding-field-support-email = Support-E-Mail
orgs-branding-theme-preset = Design-Vorlage
orgs-branding-primary = Primärfarbe
orgs-branding-on-primary = Text auf Primärfarbe
orgs-branding-secondary = Akzentfarbe
orgs-branding-request-public = Öffentliche Anmeldeseite aktivieren (/o/ihr-slug)
orgs-branding-preview = Vorschau

# Flash notices (post-save banners)
flash-org-updated = Organisation aktualisiert.
flash-branding-saved = Branding gespeichert.
flash-logo-updated = Logo aktualisiert.
flash-logo-removed = Logo entfernt.

# Öffentliche Landingpage (public_landing.html)
orgs-public-landing-note = Zum Anmelden öffnen Sie die Anwendung, die Ihr Team bereitgestellt hat. Die Anmeldung erfolgt dort.
orgs-public-landing-register = Konto erstellen

# Beitrittsbestätigung (join_confirm.html)
join-confirm-page-title = Organisation beitreten
join-confirm-heading = { $org } beitreten
join-confirm-body = Sie treten { $org } bei. Fortfahren?
join-confirm-cta = Beitreten
join-confirm-register-cta = Registrieren, um { $org } beizutreten
