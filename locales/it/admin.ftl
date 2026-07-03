# Banner admin (admin_shell.html)
admin-banner-label = ADMIN
admin-banner-body = Ti trovi su una superficie con privilegi. Le azioni qui vengono registrate a fini di audit.

# Intestazione della barra laterale di navigazione admin (admin_nav.html)
admin-nav-heading = Amministrazione
admin-nav-subtitle = Strumenti per l'operatore

# Intestazioni delle sezioni di navigazione admin
admin-nav-section-system = Sistema
admin-nav-section-access = Accesso
admin-nav-section-linux = Linux

# Etichette delle voci di navigazione admin
admin-nav-status = Stato
admin-nav-configuration = Configurazione
admin-nav-audit = Audit
admin-nav-webhooks = Webhook
admin-nav-license = Licenza
admin-nav-identities = Identità
admin-nav-sessions = Sessioni
admin-nav-clients = Client OAuth2
admin-nav-dcr-tokens = Token DCR
admin-nav-saml = SAML SSO
admin-nav-hosts = Host
admin-nav-accounts = Account

# Elenco identità (identities_list.html)
admin-identities-page-title = Identità
admin-identities-subtitle = Identità gestite da Kratos e il loro stato.
admin-identities-search-placeholder = Cerca per ID o email
admin-identities-search-button = Cerca
admin-identities-col-email = Email
admin-identities-col-state = Stato
admin-identities-col-created = Creata
admin-identities-empty = Nessuna identità trovata.
admin-identities-prev = Torna all'inizio
admin-identities-next = Pagina successiva

# Dettaglio identità (identity_show.html)
admin-identity-status-active = attiva
admin-identity-recovery-code-heading = Codice di recupero (mostrato una volta)
admin-identity-recovery-link-heading = Link di recupero
admin-identity-recovery-note = Condividilo con l'utente tramite un canale attendibile. Non verrà mostrato di nuovo.
admin-identity-section-actions = Azioni
admin-identity-action-generate-recovery = Genera codice di recupero
admin-identity-action-disable = Disattiva
admin-identity-action-enable = Attiva
admin-identity-action-delete = Elimina
admin-identity-section-traits = Trait
admin-identity-section-addresses = Indirizzi verificabili
admin-identity-addresses-empty = Nessun indirizzo verificabile su questa identità.
admin-identity-status-verified = verificato
admin-identity-status-pending = in sospeso
admin-identity-section-credentials = Credenziali
admin-identity-credentials-empty = Nessuna credenziale configurata.
admin-identity-section-sessions = Sessioni recenti
admin-identity-sessions-empty = Nessuna cronologia delle sessioni.
admin-identity-action-revoke-session = Revoca sessione

# Selettore di identità (identity_picker.html)
admin-identity-picker-page-title = Seleziona utente
admin-identity-picker-subtitle = Scegli un'identità per continuare.
admin-identity-picker-invalid-return = Destinazione di ritorno non valida.
admin-identity-picker-search-placeholder = Cerca per ID o email
admin-identity-picker-search-button = Cerca
admin-identity-picker-col-email = Email
admin-identity-picker-col-state = Stato
admin-identity-picker-col-created = Creata
admin-identity-picker-empty = Nessuna identità trovata.
admin-identity-picker-action-select = Seleziona
admin-identity-picker-prev = Torna all'inizio
admin-identity-picker-next = Pagina successiva

# Elenco sessioni (sessions_list.html)
admin-sessions-page-title = Sessioni
admin-sessions-subtitle = Ogni sessione nota a Kratos, su tutte le identità.
admin-sessions-filter-active-only = Solo sessioni attive
admin-sessions-col-identity = Identità
admin-sessions-col-authenticated = Autenticata
admin-sessions-col-expires = Scade
admin-sessions-col-device = Dispositivo
admin-sessions-empty = Nessuna sessione da mostrare.
admin-sessions-action-revoke = Revoca
admin-sessions-prev = Torna all'inizio
admin-sessions-next = Pagina successiva

# Dialogo di conferma generico (confirm.html)
admin-confirm-cancel = Annulla

# Pagina di accesso vietato (forbidden.html)
admin-forbidden-back = Torna alla dashboard

# Pagina di errore admin (error.html)
admin-error-back = Torna allo stato dell'amministrazione

# Elenco client (clients_list.html)
admin-clients-page-title = Client OAuth2
admin-clients-subtitle = Relying party registrate su Hydra.
admin-clients-action-new = Nuovo client
admin-clients-search-placeholder = Cerca per nome client o ID
admin-clients-filter-all-types = Tutti i tipi
admin-clients-filter-all-verifications = Tutte le verifiche
admin-clients-filter-verified = Verificati
admin-clients-filter-unverified = Non verificati
admin-clients-search-button = Cerca
admin-clients-col-name = Nome
admin-clients-col-type = Tipo
admin-clients-col-grants = Grant
admin-clients-col-created = Creato
admin-clients-badge-unverified-title = Non controllato da un amministratore
admin-clients-badge-self-registered = Auto-registrato
admin-clients-badge-self-registered-title = Registrato tramite /oauth2/register (RFC 7591)
admin-clients-empty = Nessun client registrato.
admin-clients-prev = Torna all'inizio
admin-clients-next = Pagina successiva

# Badge condivisi dei client (clients_list.html, client_show.html)
admin-client-badge-verified = Verificato
admin-client-badge-unverified = Non verificato
admin-client-badge-unverified-title = Un amministratore non ha controllato questo client. La schermata di consenso avvisa gli utenti finali.

# Intestazioni della pagina del modulo client (client_form.html)
admin-client-form-title-new = Nuovo client
admin-client-form-title-edit = Modifica client
admin-client-form-heading-new = Nuovo client OAuth2
admin-client-form-heading-edit = Modifica client
admin-client-form-preset-note = I valori predefiniti per questo tipo sono già compilati.
admin-client-form-preset-change = Cambia tipo

# Campi del modulo condivisi tra i client (client_form.html, modulo di modifica client_show.html)
admin-client-field-name = Nome client
admin-client-field-grant-types = Tipi di grant
admin-client-grant-auth-code-hint = (accesso guidato dall'utente)
admin-client-grant-refresh-hint = (sessioni a lunga durata)
admin-client-grant-client-creds-hint = (servizio-a-servizio)
admin-client-field-response-types = Tipi di risposta
admin-client-field-scope = Scope
admin-client-field-scope-hint = Scope OAuth2 separati da spazi.
admin-client-field-redirect-uris = URI di reindirizzamento
admin-client-field-redirect-uris-hint = Uno per riga (o separati da virgola).
admin-client-field-post-logout-uris = URI di reindirizzamento post-logout
admin-client-section-logout-fanout = Fan-out del logout OIDC
admin-client-section-logout-fanout-desc = Quando l'utente termina la propria sessione tramite Forseti, Hydra notifica i client su questi URI in modo che ogni app possa cancellare la propria sessione locale. Lascia vuoto per escludere questo client dal fan-out.
admin-client-field-backchannel-uri = URI di logout back-channel
admin-client-field-backchannel-uri-hint = Hydra invia qui un token di logout firmato tramite POST (server-a-server). In genere ha senso solo per app web renderizzate lato server e BFF.
admin-client-field-backchannel-sid-prefix = Richiedi la claim
admin-client-field-backchannel-sid-suffix = nel token di logout back-channel
admin-client-field-backchannel-sid-short = claim richiesta
admin-client-field-frontchannel-uri = URI di logout front-channel
admin-client-field-frontchannel-uri-hint = Hydra carica questo URL in un iframe durante il logout, in modo che ogni app possa cancellare i cookie di sessione nel browser.
admin-client-field-frontchannel-sid-prefix = Richiedi i parametri di query
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = al logout front-channel
admin-client-field-frontchannel-sid-short = parametri di query richiesti
admin-client-field-token-auth = Metodo di autenticazione dell'endpoint token
admin-client-token-auth-post-hint = (segreto nel corpo POST)
admin-client-token-auth-basic-hint = (segreto nell'header Authorization)
admin-client-token-auth-none-hint = (client pubblico, PKCE)
admin-client-token-auth-none-short = nessuno (pubblico + PKCE)
admin-client-field-audience = Allow-list delle audience
admin-client-field-audience-hint-short = Una per riga. Hydra richiede che i valori di audience siano pre-registrati qui.
admin-client-field-require-pkce = Richiedi PKCE (informativo)
admin-client-field-skip-consent = Client attendibile (salta la schermata di consenso)
admin-client-field-webhook-url = URL del webhook di eliminazione account
admin-client-action-cancel = Annulla

# Pagina di dettaglio del client (client_show.html)
admin-client-action-revoke-verification = Revoca verifica
admin-client-action-mark-verified = Segna come verificato
admin-client-action-rotate-secret = Ruota segreto
admin-client-action-delete = Elimina
admin-client-credentials-heading = Credenziali: mostrate una volta
admin-client-credentials-note = Copiale ora. Non verranno mostrate di nuovo; ricarica per chiudere. L'ID client e gli endpoint qui sopra non sono segreti e restano visibili.
admin-client-credentials-secret-label = Segreto del client
admin-client-credentials-rat-label = Token di accesso alla registrazione
admin-client-credentials-rat-note = Ai sensi della RFC 7592: consente al client di gestire la propria registrazione (lettura/aggiornamento/eliminazione) tramite l'API di registrazione dinamica dei client di Hydra. Non può essere riemesso, quindi nel dubbio conservalo.
admin-client-undoc-scopes-heading = Scope non documentati
admin-client-section-connection = Dettagli di connessione
admin-client-connection-intro = Incolla questi valori nella configurazione del client OIDC/OAuth sul lato dell'app.
admin-client-conn-client-id = ID client
admin-client-conn-issuer = Issuer
admin-client-conn-discovery-url = URL di discovery
admin-client-conn-auth-endpoint = Endpoint di autorizzazione
admin-client-conn-token-endpoint = Endpoint token
admin-client-conn-userinfo-endpoint = Endpoint userinfo
admin-client-conn-jwks-uri = URI JWKS
admin-client-conn-end-session-endpoint = Endpoint di fine sessione
admin-client-section-config = Configurazione
admin-client-config-sid-required = (sid richiesto)
admin-client-config-iss-sid-required = (iss+sid richiesti)
admin-client-not-configured = non configurato
admin-client-audience-none = nessuna
admin-client-config-token-auth = Auth endpoint token
admin-client-config-require-pkce = Richiedi PKCE
admin-client-bool-yes = sì
admin-client-bool-no = no
admin-client-config-trusted = Attendibile (salta consenso)
admin-client-config-created = Creato
admin-client-config-provenance-audience = Audience
admin-client-config-provenance-audience-note = (dichiarata dal chiamante DCR)
admin-client-config-provenance-url = Usato presso
admin-client-config-provenance-url-note = (prima osservazione al consenso)
admin-client-config-webhook = Webhook di eliminazione account
admin-client-section-edit = Modifica
admin-client-action-save = Salva modifiche
admin-client-action-back = Torna all'elenco

# Selettore del tipo di client (client_type_picker.html)
admin-client-type-page-title = Nuovo client
admin-client-type-heading = Nuovo client OAuth2
admin-client-type-subtitle = Scegli il tipo di applicazione. La pagina successiva è lo stesso modulo, con i valori predefiniti giusti già compilati, così non puoi finire per sbaglio su una combinazione non funzionante.
admin-client-type-popular-heading = App popolari
admin-client-type-action-cancel = Annulla

# Elenco token DCR (dcr_tokens_list.html)
admin-dcr-page-title = Token di accesso iniziale DCR
admin-dcr-action-issue = Emetti token
admin-dcr-token-revealed-heading = Token di accesso iniziale (mostrato una volta)
admin-dcr-col-status = Stato
admin-dcr-col-note = Nota
admin-dcr-col-created-by = Creato da
admin-dcr-col-created = Creato
admin-dcr-col-expires = Scade
admin-dcr-col-uses-left = Utilizzi rimasti
admin-dcr-status-active = Attivo
admin-dcr-status-revoked = Revocato
admin-dcr-status-expired = Scaduto
admin-dcr-status-exhausted = Esaurito
admin-dcr-empty-prefix = Nessun token emesso.
admin-dcr-empty-link = Emettine uno
admin-dcr-empty-suffix = per abilitare l'auto-registrazione.
admin-dcr-action-revoke = Revoca

# Nuovo token DCR (dcr_token_new.html)
admin-dcr-new-page-title = Emetti token DCR
admin-dcr-new-heading = Emetti un token di accesso iniziale DCR
admin-dcr-new-field-note = Nota
admin-dcr-new-field-note-placeholder = A cosa serve questo token? (ad es. 'Claude Desktop per formshive')
admin-dcr-new-field-note-hint = Facoltativa, solo per i tuoi archivi. L'autore del client non la vede mai.
admin-dcr-new-field-ttl = TTL (ore)
admin-dcr-new-field-ttl-hint = Lascia vuoto per nessuna scadenza.
admin-dcr-new-field-max-uses = Utilizzi massimi
admin-dcr-new-action-cancel = Annulla

# Pagina di stato (status.html)
admin-status-page-title = Stato
admin-status-heading = Stato del sistema
admin-status-subtitle = Salute in tempo reale dei componenti IdP, della coda del courier e delle versioni di build.
admin-status-issuer-label = Issuer
admin-status-issuer-config-link = Visualizza configurazione →
admin-status-warning-db-label = Database
admin-status-warning-db-body = sqlite + deployment dall'aspetto di produzione. Le configurazioni multi-istanza corromperanno il database. Passa a Postgres per l'alta disponibilità.
admin-status-warning-webhook-label = Fan-out dei webhook
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } riga di webhook di eliminazione account in dead-letter
       *[other] { $count } righe di webhook di eliminazione account in dead-letter
    }
admin-status-dead-webhook-middle = (i destinatari non vengono notificati).
admin-status-dead-webhook-open = Apri /admin/webhooks
admin-status-dead-webhook-action = per rimetterle in coda o scartarle.
admin-status-section-services = Servizi
admin-status-col-service = Servizio
admin-status-col-state = Stato
admin-status-col-detail = Dettaglio
admin-status-state-up = attivo
admin-status-state-down = inattivo
admin-status-section-courier = Coda del courier
admin-status-courier-pending = In sospeso (in coda)
admin-status-courier-failed = Non riuscite (abbandonate)
admin-status-courier-last-webhook = Ultimo webhook di audit
admin-status-courier-never = mai
admin-status-section-audit = Audit
admin-status-audit-write-failures = Errori di scrittura audit (dall'avvio)
admin-status-audit-write-failures-note-prefix = Le righe sono recuperabili dalle righe strutturate
admin-status-audit-write-failures-note-suffix = su stderr emesse da Forseti al momento dell'errore.
admin-status-audit-webhook-rejected = Webhook di audit rifiutati (dall'avvio)
admin-status-audit-webhook-rejected-note-prefix = Payload malformati o azioni sconosciute, probabilmente una discrepanza tra hook/configurazione di Kratos. Controlla i
admin-status-audit-webhook-rejected-note-suffix = log di avviso.
admin-status-audit-freshness = Anomalie di freschezza dei webhook di audit (dall'avvio)
admin-status-audit-freshness-note = Payload contrassegnati come obsoleti o con data futura, di solito a causa di un flusso lento o di uno sfasamento dell'orologio. Le righe vengono comunque registrate e contrassegnate.
admin-status-section-license = Licenza
admin-status-license-oss-prefix = Deployment di livello OSS.
admin-status-license-oss-link = Attiva una licenza
admin-status-license-oss-suffix = per sbloccare le funzionalità premium.
admin-status-section-build = Versioni di build
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = Database

# Pagina di configurazione (configuration.html)
admin-config-page-title = Configurazione
admin-config-subtitle = Come è configurato questo provider di identità: endpoint e funzionalità OIDC, chiavi di firma e schemi di identità Kratos.
admin-config-discovery-warning-label = Discovery OIDC
admin-config-discovery-warning-body = Non è stato possibile raggiungere il documento di discovery di Hydra. Gli endpoint e le funzionalità restano nascosti finché non torna raggiungibile.
admin-config-section-oidc = Endpoint OIDC
admin-config-field-issuer = Issuer
admin-config-field-discovery-url = URL di discovery
admin-config-field-authorization = Autorizzazione
admin-config-field-token = Token
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = Fine sessione
admin-config-field-registration = Registrazione (DCR)
admin-config-field-revocation = Revoca
admin-config-section-capabilities = Funzionalità
admin-config-cap-scopes = Scope
admin-config-cap-grant-types = Tipi di grant
admin-config-cap-response-types = Tipi di risposta
admin-config-cap-token-auth-methods = Metodi di autenticazione dell'endpoint token
admin-config-cap-pkce-methods = Metodi PKCE
admin-config-cap-id-token-signing-algs = Algoritmi di firma dell'ID token
admin-config-cap-subject-types = Tipi di subject
admin-config-cap-backchannel-logout = Logout back-channel
admin-config-cap-frontchannel-logout = Logout front-channel
admin-config-cap-yes = Sì
admin-config-cap-no = No
admin-config-section-signing-keys = Chiavi di firma (JWKS)
admin-config-signing-keys-unavailable = Non disponibili: non è stato possibile recuperare le chiavi pubbliche di Hydra.
admin-config-signing-keys-empty = Hydra non ha pubblicizzato alcuna chiave di firma.
admin-config-col-key-id = ID chiave
admin-config-col-alg = Alg
admin-config-col-type = Tipo
admin-config-col-use = Uso
admin-config-section-schemas = Schemi di identità Kratos
admin-config-schemas-unavailable = Non disponibili: non è stato possibile recuperare gli schemi di identità da Kratos.
admin-config-schemas-empty = Nessuno schema di identità registrato.

# Elenco audit (audit.html)
admin-audit-page-title = Audit
admin-audit-subtitle = Registro eventi solo in aggiunta. Registra le azioni admin lato Forseti, i grant OAuth, le modifiche alle sessioni e i completamenti dei flussi Kratos consegnati via webhook. La conservazione è configurata dall'operatore (`[audit].audit_retention_days`); l'eliminazione è un sottocomando CLI, non automatica.
admin-audit-filter-email = L'email contiene
admin-audit-filter-action = Prefisso azione
admin-audit-filter-severity = Gravità
admin-audit-filter-since = Da
admin-audit-severity-any = Qualsiasi
admin-audit-severity-info = Info
admin-audit-severity-warning = Avviso
admin-audit-severity-error = Errore
admin-audit-severity-critical = Critico
admin-audit-filter-button = Filtra
admin-audit-col-target = Destinazione
admin-audit-col-severity = Gravità
admin-audit-col-when = Quando
admin-audit-col-actor = Attore
admin-audit-col-action = Azione
admin-audit-col-actions = Azioni
admin-audit-empty = Nessun evento corrisponde ai filtri attuali.
admin-audit-badge-critical = critico
admin-audit-badge-error = errore
admin-audit-badge-warning = avviso
admin-audit-action-view = Visualizza
admin-audit-prev = ‹ Precedente
admin-audit-next = Successivo ›

# Dettaglio audit (audit_show.html)
admin-audit-back = ← Torna all'audit
admin-audit-show-section-event = Evento
admin-audit-show-outcome = Esito
admin-audit-show-success = successo
admin-audit-show-failure = fallimento
admin-audit-show-section-actor = Attore
admin-audit-show-field-kind = Tipo
admin-audit-show-field-email = Email
admin-audit-show-none = nessuno
admin-audit-show-field-identity-id = ID identità
admin-audit-show-section-target = Destinazione
admin-audit-show-field-label = Etichetta
admin-audit-show-deleted = (eliminato)
admin-audit-show-field-target-id = ID destinazione
admin-audit-show-section-metadata = Metadati
admin-audit-show-section-request-context = Contesto della richiesta
admin-audit-show-field-ip-hash = Hash IP
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = ID richiesta
admin-audit-show-field-org-id = ID organizzazione

# Elenco webhook (webhooks.html)
admin-webhooks-page-title = Webhook
admin-webhooks-heading = Webhook in dead-letter
admin-webhooks-subtitle = Notifiche di eliminazione account che hanno esaurito i tentativi (12 tentativi o 72 ore, a seconda di quale evento si verifica prima). Clicca su una riga per il payload completo e l'ultimo errore, oppure rimettila in coda dal riepilogo se sai che il destinatario è di nuovo integro.
admin-webhooks-empty = Nessuna riga in dead-letter. Tutto viene consegnato.
admin-webhooks-col-client = Client
admin-webhooks-col-event = Evento
admin-webhooks-col-attempts = Tentativi
admin-webhooks-col-age = Età
admin-webhooks-col-actions = Azioni
admin-webhooks-deleted = (eliminato)
admin-webhooks-action-view = Visualizza
admin-webhooks-action-requeue = Rimetti in coda

# Dettaglio webhook (webhook_show.html)
admin-webhook-back = ← Torna ai webhook
admin-webhook-heading = Webhook in dead-letter
admin-webhook-action-requeue = Rimetti in coda
admin-webhook-action-discard = Scarta
admin-webhook-section-delivery = Consegna
admin-webhook-field-client = Client
admin-webhook-deleted = (eliminato)
admin-webhook-field-state = Stato
admin-webhook-field-url = URL
admin-webhook-field-attempts = Tentativi
admin-webhook-field-created = Creato
admin-webhook-field-next-attempt = Prossimo tentativo
admin-webhook-section-last-error = Ultimo errore
admin-webhook-section-payload = Payload firmato

# Elenco account POSIX (posix_list.html)
admin-posix-page-title = Account POSIX
admin-posix-subtitle = Identità Kratos materializzate in account Linux (uid/gid + chiavi SSH) per il resolver NSS.
admin-posix-seats-label = Posti in uso:
admin-posix-license-note = Una licenza commerciale di autenticazione Linux aumenta il limite.
admin-posix-action-provision = Provisiona account
admin-posix-col-username = Nome utente
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Stato
admin-posix-col-created = Creato
admin-posix-empty-prefix = Nessun account POSIX abilitato.
admin-posix-empty-link = Provisionane uno
admin-posix-empty-suffix = da un'identità Kratos.
admin-posix-status-enabled = abilitato
admin-posix-status-disabled = disabilitato
admin-posix-action-manage = Gestisci

# Dettaglio account POSIX (posix_account.html)
admin-posix-action-disable = Disabilita
admin-posix-action-enable = Abilita
admin-posix-action-delete = Elimina
admin-posix-ssh-keys-heading = Chiavi SSH
admin-posix-ssh-empty = Ancora nessuna chiave SSH.
admin-posix-ssh-key-added-prefix = aggiunta
admin-posix-ssh-action-remove = Rimuovi
admin-posix-ssh-field-public-key = Chiave pubblica
admin-posix-ssh-field-comment = Commento (facoltativo)
admin-posix-ssh-action-add = Aggiungi chiave
admin-posix-teams-heading = Team
admin-posix-hosts-heading = Host raggiungibili
admin-posix-back = ← Tutti gli account POSIX

# Nuovo account POSIX (posix_new.html)
admin-posix-new-page-title = Provisiona account POSIX
admin-posix-new-heading = Provisiona un account POSIX
admin-posix-new-choose-identity = Scegli l'identità da provisionare.
admin-posix-new-action-select-user = Seleziona utente
admin-posix-new-or-enter-directly = Oppure inserisci direttamente
admin-posix-new-placeholder-id = UUID o email
admin-posix-new-action-continue = Continua
admin-posix-new-provision-intro = Materializza un'identità Kratos in un account Linux. Un uid/gid viene allocato automaticamente e viene creato un gruppo primario.
admin-posix-new-selected-prefix = Selezionata:
admin-posix-new-action-change = Cambia
admin-posix-new-field-username = Nome utente
admin-posix-new-username-hint = Suggerito dall'email; modificalo se vuoi. 1–32 caratteri, minuscolo, che inizia con una lettera o un trattino basso. Questo diventa il nome di accesso POSIX.
admin-posix-new-field-shell = Shell di accesso
admin-posix-new-action-cancel = Annulla

# Elenco host (hosts_list.html)
admin-hosts-page-title = Host
admin-hosts-subtitle = Macchine Linux registrate presso il resolver POSIX/NSS di Forseti. Ogni host si autentica con un segreto monouso che riveli al momento della registrazione.
admin-hosts-action-enroll = Registra host
admin-hosts-credential-heading = Credenziale host (mostrata una volta)
admin-hosts-credential-note-prefix = Il formato è
admin-hosts-credential-note-suffix = . Configura ora l'agente host con questa credenziale. Non memorizziamo il segreto grezzo, solo il suo SHA-256.
admin-hosts-col-hostname = Hostname
admin-hosts-col-teams = Team
admin-hosts-col-force-mfa = Forza MFA
admin-hosts-col-enrolled = Registrato
admin-hosts-col-last-seen = Ultima visita
admin-hosts-empty-prefix = Nessun host registrato.
admin-hosts-empty-link = Registrane uno
admin-hosts-empty-suffix = per consentirgli di risolvere gli account POSIX.
admin-hosts-status-mfa-pending = MFA (in sospeso)
admin-hosts-mfa-pending-title = Registrata ma non ancora applicata; l'applicazione arriva con l'accesso interattivo (PAM).
admin-hosts-action-edit = Modifica
admin-hosts-action-rotate = Ruota
admin-hosts-action-revoke = Revoca

# Modifica host (hosts_edit.html)
admin-hosts-edit-page-title = Modifica host
admin-hosts-edit-intro = Aggiorna l'etichetta dell'host, il suo flag MFA e i team a cui è associato. Il segreto non è mostrato qui; ruotalo dall'elenco degli host se ne serve uno nuovo.
admin-hosts-field-hostname = Hostname
admin-hosts-hostname-hint = Un'etichetta per i tuoi archivi. Non deve corrispondere all'hostname effettivo della macchina.
admin-hosts-field-org = Organizzazione
admin-hosts-org-fixed-note = L'organizzazione di un host è fissata al momento della registrazione e non può essere modificata qui.
admin-hosts-field-allowed-teams = Team consentiti
admin-hosts-teams-empty = Non esiste ancora alcun team. Questo host consente l'accesso a qualsiasi membro dell'organizzazione. Limitare un host a team specifici richiede la funzionalità Organizzazioni.
admin-hosts-teams-hint = Limita questo host ai membri dei team selezionati. Non selezionarne nessuno per consentire qualsiasi membro dell'organizzazione.
admin-hosts-field-force-mfa = Forza MFA su questo host
admin-hosts-force-mfa-hint = Registrata ora; applicata una volta disponibile l'accesso interattivo (PAM).
admin-hosts-action-cancel = Annulla

# Nuovo host (hosts_new.html)
admin-hosts-new-heading = Registra un host Linux
admin-hosts-new-intro-prefix = Un segreto monouso viene rivelato una sola volta nella pagina successiva. Configura l'agente host con la credenziale
admin-hosts-new-intro-suffix = che mostra.
admin-hosts-org-belongs-hint = L'host appartiene a questa organizzazione. Fissata dopo la registrazione.
admin-hosts-new-teams-empty = Non esiste ancora alcun team. Questo host consentirà l'accesso a qualsiasi membro dell'organizzazione. Limitare un host a team specifici richiede la funzionalità Organizzazioni.
admin-hosts-new-teams-scope-hint = Limita questo host ai membri dei team selezionati. Si applicano solo i team dell'organizzazione scelta; non selezionarne nessuno per consentire qualsiasi membro dell'organizzazione.

# Elenco SAML SSO (saml_list.html)
admin-saml-page-title = SAML SSO
admin-saml-subtitle = Connessioni SAML aziendali, una per organizzazione. I metadati e i certificati dell'IdP risiedono in Jackson; Forseti mantiene la riga di ancoraggio e l'interruttore di attivazione.
admin-saml-action-new = Nuova connessione
admin-saml-grace-notice = Licenza nel periodo di tolleranza. Le connessioni SAML sono di sola lettura finché la licenza non viene rinnovata. Gli accessi SSO continuano a funzionare.
admin-saml-col-org = Organizzazione
admin-saml-col-connection = Connessione
admin-saml-col-sso-url = URL SSO
admin-saml-col-enabled = Attivata
admin-saml-empty-prefix = Ancora nessuna connessione SAML.
admin-saml-empty-link = Creane una
admin-saml-empty-suffix = per abilitare l'SSO per un'organizzazione.
admin-saml-status-enabled = Attivata
admin-saml-status-disabled = Disattivata
admin-saml-action-disable = Disattiva
admin-saml-action-enable = Attiva
admin-saml-action-delete = Elimina
admin-saml-idp-values-heading = Valori per l'amministratore IdP del cliente
admin-saml-idp-values-intro = Consegnali a chi configura l'app SAML sul lato del provider di identità. Sono gli stessi per ogni connessione.
admin-saml-idp-acs-url = URL ACS
admin-saml-idp-entity-id = Entity ID dell'SP

# Paginazione audit
admin-audit-range = Visualizzazione di { $from }–{ $to } di { $total } righe.
admin-audit-page = Pagina { $page }
admin-saml-entity-id-note-prefix = L'entity ID segue l'impostazione
admin-saml-entity-id-note-suffix = di Jackson; modificala lì se sovrascrivi il valore predefinito.

# Nuova connessione SAML SSO (saml_new.html)
admin-saml-new-page-title = Nuova connessione SAML
admin-saml-new-intro = Collega un'organizzazione al suo provider di identità. Incolla l'XML dei metadati dell'IdP, oppure fornisci un URL di metadati che Jackson recupera da solo: esattamente una delle due opzioni.
admin-saml-new-field-org = Organizzazione
admin-saml-new-org-hint = Una connessione per organizzazione.
admin-saml-new-field-name = Nome della connessione
admin-saml-new-name-hint = Solo per i tuoi archivi; i membri non lo vedono mai.
admin-saml-new-field-metadata-url = URL dei metadati
admin-saml-new-metadata-url-hint = Lascia vuoto quando incolli l'XML grezzo qui sotto.
admin-saml-new-metadata-url-https-note = Jackson recupera solo URL di metadati HTTPS (o localhost). Per metadati IdP in HTTP semplice, incolla invece l'XML qui sotto.
admin-saml-new-field-metadata-xml = XML dei metadati
admin-saml-new-metadata-xml-hint = Lascia vuoto quando usi un URL di metadati qui sopra.
admin-saml-new-action-create = Crea connessione
admin-saml-new-action-cancel = Annulla

# Suddivisioni inline-code (punto 8: 2+ elementi di codice per stringa)

# client_form.html - suggerimento sui tipi di risposta (code: code, token)
admin-client-field-response-types-hint-part1 = Separati da virgola, ad es.
admin-client-field-response-types-hint-part2 = (auth code) o
admin-client-field-response-types-hint-part3 = (client credentials).

# client_form.html - suggerimento sull'audience (code: audience=<value>)
admin-client-field-audience-hint-part1 = Una per riga. Hydra richiede che i valori di audience siano pre-registrati qui (non supporta ancora la RFC 8707). I client passano
admin-client-field-audience-hint-part2 = nella richiesta di autorizzazione.

# client_form.html - suggerimento PKCE (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = L'applicazione globale risiede in
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). Questo flag indica l'intento dell'operatore.

# client_form.html + client_show.html - suggerimento webhook (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = Quando un utente elimina il proprio account, Forseti invia qui via POST un Security Event Token RFC 8417 (RISC
admin-client-field-webhook-hint-part2 = ). Lascia vuoto per rinunciare. I destinatari verificano la firma JWS rispetto al JWKS di Forseti su
admin-client-field-webhook-hint-part3 = .

# client_show.html - descrizione degli scope non documentati (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = Questi scope sono registrati su questo client ma non hanno una voce sotto
admin-client-undoc-scopes-desc-part2 = in
admin-client-undoc-scopes-desc-part3 = . La schermata di consenso ripiega sul nome grezzo dello scope per essi.

# client_show.html - errore di discovery (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = Non è stato possibile raggiungere l'endpoint di discovery di Hydra, quindi l'issuer e gli endpoint sono nascosti per evitare di mostrare un valore errato. Recuperali tu stesso da
admin-client-discovery-error-part2 = .

# client_show.html - introduzione della sezione di modifica (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Aggiorna i campi del client qui sotto. Le modifiche vengono inviate tramite la
admin-client-edit-intro-part2 = di Hydra; i campi non correlati vengono preservati.

# dcr_tokens_list.html - sottotitolo (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Token bearer che autorizzano
admin-dcr-subtitle-part2 = . Consegnane uno all'autore di un client MCP così può auto-registrarsi senza che tu debba farlo manualmente.

# dcr_tokens_list.html - descrizione del token mostrato (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Condividilo con l'autore del client. Lo invia come
admin-dcr-revealed-desc-part2 = quando chiama
admin-dcr-revealed-desc-part3 = . Non memorizziamo il valore grezzo, solo il suo SHA-256.

# dcr_token_new.html - sottotitolo (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = Il token viene rivelato una sola volta nella pagina successiva. Consegnalo all'autore del client. Lo invia come
admin-dcr-new-subtitle-part2 = in una singola chiamata
admin-dcr-new-subtitle-part3 = .

# dcr_token_new.html - suggerimento sugli utilizzi massimi (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = Lascia vuoto per utilizzi illimitati. Monouso (
admin-dcr-new-field-max-uses-hint-part2 = ) è l'impostazione predefinita più sicura.

# client_type_picker.html - descrizione delle app popolari (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Precompilato per un'app conosciuta. Gli URL usano i segnaposto
admin-client-type-popular-desc-part2 = (e talvolta
admin-client-type-popular-desc-part3 = ). Sostituiscili con i valori della tua app dopo essere arrivato al modulo.

# posix_account.html - paragrafo sulle chiavi SSH (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = Le chiavi pubbliche aggiunte qui vengono fornite all'sshd del dispositivo (
admin-posix-ssh-keys-desc-part2 = ) così questo utente può fare
admin-posix-ssh-keys-desc-part3 = con la propria chiave, senza bisogno di un file
admin-posix-ssh-keys-desc-part4 = per host. Richiede l'hook sshd dell'host (configurato automaticamente dal servizio Guix
admin-posix-ssh-keys-desc-part5 = ; configurazione sshd manuale su altre distribuzioni). Non usato per l'accesso da console / PAM.

# posix_new.html - suggerimento sulla shell (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Deve esistere sul dispositivo (o sui dispositivi) che servono questo account;
admin-posix-new-shell-hint-part2 = è l'impostazione predefinita sicura tra le distribuzioni (Guix non ha
admin-posix-new-shell-hint-part3 = ). La home dir è derivata dal prefisso home + nome utente.

# saml_list.html - blocco non configurato (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = non è configurato
admin-saml-not-configured-part2 = aggiungi le impostazioni del bridge Jackson a
admin-saml-not-configured-part3 = per abilitare SAML SSO. Vedi
admin-saml-not-configured-part4 = .

# Messaggi flash admin (mostrati come banner dopo un reindirizzamento)
flash-identity-disabled = Identità disattivata.
flash-identity-enabled = Identità attivata.
flash-session-revoked = Sessione revocata.
flash-client-create-failed = Creazione del client non riuscita: { $error }
flash-client-account-deletion-url-rejected = URL di eliminazione account rifiutato: { $error }
flash-client-secret-stage-failed = Client creato, ma non è stato possibile predisporre il segreto per la visualizzazione singola. Ruota il segreto per recuperare un nuovo valore.
