# Etichette dei campi condivise tra le pagine dell'organizzazione
orgs-field-name = Nome
orgs-field-slug = Slug
orgs-field-email = Email
orgs-field-role = Ruolo

# Selettore di organizzazione (menu a discesa in alto)
orgs-switcher-label = Cambia organizzazione
orgs-switcher-manage-link = Gestisci organizzazioni

# Elenco organizzazioni (list.html)
orgs-list-title = Organizzazioni
orgs-list-heading = Le tue organizzazioni
orgs-list-create-heading = Crea una nuova organizzazione
orgs-list-field-slug-optional = Slug (facoltativo)
orgs-list-action-create = Crea
orgs-list-tier-gate-heading = La gestione di più organizzazioni è una funzionalità { $tier }
orgs-list-license-missing = La tua licenza attuale non include la funzionalità Organizzazioni.
orgs-list-unlicensed = Questa installazione di { $brand } è priva di licenza, quindi le organizzazioni aggiuntive oltre a quella predefinita sono bloccate.
orgs-list-license-upgrade = Attiva o aggiorna una licenza per crearne altre.
orgs-list-link-get-license = Ottieni una licenza
orgs-list-link-activate-license = Attiva una licenza esistente

# Panoramica dell'organizzazione - vista proprietario (overview.html)
orgs-overview-subtitle-default = Questa è l'organizzazione predefinita di questa installazione di { $brand }. Chiunque si registri vi si unisce automaticamente.
orgs-overview-subtitle = Gestisci le impostazioni, il branding e i membri di questa organizzazione.
orgs-overview-identity-heading = Identità
orgs-overview-quicklinks-heading = Link rapidi
orgs-link-branding = Branding
orgs-link-members = Membri
orgs-link-teams = Team
orgs-sso-heading = SSO aziendale
orgs-sso-status-enabled = attivato
orgs-sso-status-disabled = disattivato
orgs-sso-operator-note = Le connessioni SSO sono gestite dall'operatore.
orgs-danger-heading = Zona pericolosa
orgs-danger-delete-body = Elimina definitivamente questa organizzazione. Forseti rifiuta se sono ancora associati dei client OAuth2.
orgs-danger-delete-action = Elimina organizzazione
orgs-confirm-delete-org = Eliminare { $name }? L'operazione non può essere annullata.

# Panoramica dell'organizzazione - vista non proprietario (overview_info.html)
orgs-info-subtitle-default = Questa è l'organizzazione predefinita di questa installazione di { $brand }. Ne sei membro.
orgs-info-subtitle = Sei membro di questa organizzazione.
orgs-info-org-heading = Organizzazione
orgs-info-members-label = Membri
orgs-info-managed-by-heading = Gestita da
orgs-info-managed-by-note = Contatta un proprietario per modificare il nome, il branding o i membri dell'organizzazione.

# Pagina dei membri (members.html)
orgs-members-page-heading = Membri
orgs-members-subtitle = I proprietari possono promuovere / retrocedere i membri e rimuovere chiunque tranne l'ultimo proprietario.
orgs-members-visibility-note-admins-only = Solo gli amministratori possono vedere l'elenco completo dei membri.
orgs-members-visibility-note-same-group = Vedi i membri che condividono un team con te.
orgs-members-visibility-note-all = Tutti i membri sono visibili.
orgs-members-invite-heading = Invita via email
orgs-members-role-member = Membro
orgs-members-role-owner = Proprietario
orgs-members-action-invite = Invia invito
orgs-members-visibility-heading = Visibilità della directory
orgs-members-visibility-label = Chi può vedere l'elenco dei membri
orgs-members-visibility-opt-all = Tutti i membri
orgs-members-visibility-opt-same-group = Solo lo stesso team
orgs-members-visibility-opt-admins-only = Solo gli amministratori
orgs-members-visibility-hint = "Solo lo stesso team" richiede che esista prima almeno un team.
orgs-members-col-joined = Iscritto
orgs-members-badge-you = tu
orgs-members-badge-hidden = Nascosto
orgs-members-action-show = Mostra
orgs-members-action-hide = Nascondi
orgs-members-action-update = Aggiorna
orgs-members-action-remove = Rimuovi
orgs-confirm-remove-member = Rimuovere { $email }?
orgs-members-invites-heading = Inviti in sospeso
orgs-members-invites-col-sent = Inviato
orgs-members-invites-col-expires = Scade

# Pagina dei team (teams.html)
orgs-teams-page-heading = Team
orgs-teams-subtitle = Raggruppa i membri in team. I team delimitano l'accesso agli host e determinano la visibilità della directory dello stesso team.
orgs-teams-create-heading = Crea un team
orgs-teams-action-create = Crea team
orgs-teams-col-team = Team
orgs-teams-col-members = Membri
orgs-teams-action-rename = Rinomina
orgs-teams-action-manage-members = Gestisci membri
orgs-teams-action-delete = Elimina
orgs-confirm-delete-team = Eliminare { $name }? Questo rimuove il team e le sue appartenenze.
orgs-teams-selected-heading = Membri di { $team }
orgs-teams-add-member-label = Aggiungi membro
orgs-teams-action-add = Aggiungi

# Pagina di branding (branding.html)
orgs-branding-page-heading = Branding
orgs-branding-subtitle-prefix = Sostituisci il branding predefinito di Forseti con il logo e l'email di supporto di questa organizzazione. Ripiega su
orgs-branding-subtitle-infix = in
orgs-branding-subtitle-suffix = quando non impostato.
orgs-branding-field-logo-url = URL del logo
orgs-branding-field-support-email = Email di supporto
orgs-branding-theme-preset = Preset del tema
orgs-branding-primary = Colore principale
orgs-branding-on-primary = Testo sul colore principale
orgs-branding-secondary = Colore d'accento
orgs-branding-request-public = Abilita una pagina di accesso pubblica (/o/il-suo-slug)
orgs-branding-preview = Anteprima

# Pagina di destinazione pubblica (public_landing.html)
orgs-public-landing-note = Per accedere, apra l'applicazione fornita dal suo team. L'accesso avviene da lì.
orgs-public-landing-register = Crea un account
