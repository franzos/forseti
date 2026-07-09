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
orgs-list-field-access-mode = Modalità di accesso
orgs-list-mode-internal-title = Interno
orgs-list-mode-internal-body = Solo su invito. I membri si uniscono su invito (e, in futuro, tramite un dominio aziendale verificato).
orgs-list-mode-external-title = Esterno
orgs-list-mode-external-body = Registrazione pubblica self-service. La directory dei membri è limitata agli amministratori.
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
orgs-link-domains = Domini
orgs-sso-heading = SSO aziendale
orgs-sso-status-enabled = attivato
orgs-sso-status-disabled = disattivato
orgs-sso-operator-note = Le connessioni SSO sono gestite dall'operatore.
orgs-access-mode-heading = Modalità di accesso
orgs-access-mode-label = Modalità
orgs-access-mode-internal = Interno
orgs-access-mode-external = Esterno
orgs-access-mode-note-default = L'organizzazione predefinita è sempre interna.
orgs-access-mode-note-internal = I membri si uniscono su invito. Passare a esterno abilita la registrazione pubblica.
orgs-access-mode-note-external = La registrazione pubblica è abilitata. La directory dei membri è limitata agli amministratori finché è esterna.
orgs-access-mode-action-switch-external = Passa a esterno
orgs-access-mode-action-switch-internal = Passa a interno
orgs-confirm-switch-external = Passare a esterno? Questo abilita la pagina di registrazione pubblica e limita la directory dei membri ai soli amministratori.
orgs-confirm-switch-internal = Passare a interno? Questo disabilita la pagina di registrazione pubblica. I membri esistenti mantengono la loro appartenenza.
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

# Pagina dei domini (domains.html)
orgs-domains-page-heading = Domini consentiti
orgs-domains-subtitle = Gli utenti con un'email verificata su un dominio comprovato si uniscono automaticamente a questa organizzazione.
orgs-domains-add-heading = Aggiungi un dominio
orgs-domains-field-domain = Dominio
orgs-domains-field-method = Metodo di verifica
orgs-domains-method-http_file = File HTTP
orgs-domains-method-dns_txt = Record DNS TXT
orgs-domains-method-email = Email
orgs-domains-action-add = Aggiungi dominio
orgs-domains-col-domain = Dominio
orgs-domains-col-method = Metodo
orgs-domains-col-status = Stato
orgs-domains-status-verified = Verificato
orgs-domains-status-pending = In sospeso
orgs-domains-instructions-http_file = Servi { $token } su https://{ $domain }/.well-known/forseti-domain-verify
orgs-domains-instructions-dns_txt = Crea un record TXT su _forseti-verify.{ $domain } con il valore: { $token }
orgs-domains-instructions-email = Un codice e stato inviato a admin@{ $domain } e postmaster@{ $domain }. Incollalo qui sotto.
orgs-domains-action-verify = Verifica
orgs-domains-action-confirm = Conferma codice
orgs-domains-field-token = Codice di conferma
orgs-domains-action-remove = Rimuovi
orgs-confirm-remove-domain = Rimuovere { $domain }? Il collegamento automatico per questo dominio termina subito.
orgs-domains-policy-heading = Criterio di adesione
orgs-domains-policy-subtitle = Scegli come gli utenti con un'email verificata su un dominio provato entrano in questa organizzazione.
orgs-domains-policy-field = Criterio
orgs-domains-policy-invite-only = Solo su invito
orgs-domains-policy-auto-join = Gli utenti dei domini verificati possono aderire autonomamente
orgs-domains-policy-save = Salva criterio

# Pagina di branding (branding.html)
orgs-branding-page-heading = Branding
orgs-branding-subtitle-prefix = Sostituisci il branding predefinito di Forseti con il logo e l'email di supporto di questa organizzazione. Ripiega su
orgs-branding-subtitle-infix = in
orgs-branding-subtitle-suffix = quando non impostato.
orgs-branding-field-logo-url = URL del logo
orgs-branding-field-logo-file = Immagine del logo (PNG, JPEG o WebP; max 256 KB)
orgs-branding-logo-remove = Rimuovi logo
orgs-branding-logo-save = Carica logo
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

# Conferma di adesione (join_confirm.html)
join-confirm-page-title = Unisciti all'organizzazione
join-confirm-heading = Unisciti a { $org }
join-confirm-body = Stai per unirti a { $org }. Continuare?
join-confirm-cta = Unisciti
join-confirm-register-cta = Registrati per unirti a { $org }
