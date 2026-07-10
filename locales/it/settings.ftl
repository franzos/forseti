settings-hub-title = Impostazioni
settings-hub-subtitle = Gestisci le preferenze del tuo account, le impostazioni di sicurezza e le sessioni attive.
settings-hub-profile-title = Profilo
settings-hub-profile-desc = Aggiorna il tuo indirizzo email e il nome visualizzato.
settings-hub-profile-link = Gestisci profilo
settings-hub-password-title = Password
settings-hub-password-desc = Cambia la password del tuo account.
settings-hub-password-link = Cambia password
settings-hub-2fa-title = Autenticazione a due fattori
settings-hub-2fa-desc = Configura TOTP, codici di recupero e chiavi di sicurezza.
settings-hub-2fa-link = Gestisci 2FA
settings-hub-sessions-title = Sessioni attive
settings-hub-sessions-desc = Controlla i dispositivi connessi al tuo account.
settings-hub-sessions-link = Visualizza sessioni
settings-hub-apps-title = App autorizzate
settings-hub-apps-desc = Controlla e revoca le app OAuth a cui hai concesso l'accesso.
settings-hub-apps-link = Gestisci app
settings-hub-providers-title = Provider collegati
settings-hub-providers-desc = Collega o rimuovi provider di accesso di terze parti.
settings-hub-providers-link = Gestisci provider
settings-hub-account-title = Account
settings-hub-account-desc = Modifiche permanenti: elimina il tuo account.
settings-hub-account-link = Zona pericolosa
settings-nav-general = Generale
settings-nav-security = Sicurezza
settings-nav-connections = Connessioni
settings-nav-overview = Panoramica
settings-nav-profile = Profilo
settings-nav-organization = Organizzazione
settings-nav-password = Password
settings-nav-2fa = 2FA
settings-nav-sessions = Sessioni
settings-nav-offline = Accesso offline
settings-nav-authorized-apps = App autorizzate
settings-nav-linked-providers = Provider collegati
settings-nav-account = Account

# Sotto-pagina del profilo
settings-profile-heading = Profilo
settings-profile-subtitle = Aggiorna il tuo indirizzo email e il nome visualizzato.
settings-profile-email-not-verified = Non verificato
settings-profile-email-send-verification = Invia email di verifica
settings-profile-public-heading = Profilo pubblico
settings-profile-public-saved = Profilo salvato.
settings-profile-public-label-bio = Bio
settings-profile-public-label-location = Località
settings-profile-public-label-pronouns = Pronomi
settings-profile-public-label-website = Sito web
settings-profile-public-label-avatar = URL dell'avatar
settings-profile-public-avatar-hint = Facoltativo. Lascia vuoto per usare l'identicon generato automaticamente.
settings-profile-public-label-links = Link
settings-profile-public-save = Salva profilo
settings-profile-back = Torna alle impostazioni
settings-profile-language-label = Lingua preferita
settings-profile-language-help = Si applica a tutti i tuoi dispositivi.

# Sotto-pagina della password
settings-password-heading = Password
settings-password-subtitle = Cambia la password usata per accedere.
settings-password-back = Torna alle impostazioni

# Sotto-pagina dell'account
settings-account-heading = Account
settings-account-subtitle = Modifiche permanenti al tuo account.
settings-account-delete-section-heading = Elimina account
settings-account-delete-body = Elimina definitivamente il tuo account, ogni sessione attiva e tutti i dati di 2FA / recupero. Le app che detengono copie dei tuoi dati vengono notificate per poter ripulire la loro parte. L'operazione non può essere annullata.
settings-account-delete-action = Elimina il mio account

# Pagina di conferma eliminazione account
settings-account-delete-page-title = Conferma eliminazione
settings-account-delete-confirm-heading = Eliminare il tuo account?
settings-account-delete-confirm-subtitle-prefix = Questo rimuove definitivamente
settings-account-delete-confirm-subtitle-suffix = e ogni sessione, codice di recupero e credenziale ad esso associati.
settings-account-delete-apps-heading = Queste app riceveranno la notifica della tua eliminazione
settings-account-delete-apps-note = Le app copiano i dati di cui hanno bisogno (profilo, impostazioni) e li mantengono collegati al tuo ID account. Le notifichiamo tramite il webhook di eliminazione che hanno registrato in modo che possano ripulire la loro copia.
settings-account-delete-no-apps = Al momento nessuna app di terze parti ha copie dei tuoi dati. Nessuno da notificare.
settings-account-delete-confirm-label = Per confermare, digita la tua email qui sotto:
settings-account-delete-confirm-placeholder = Digita la tua email per confermare
settings-account-delete-confirm-submit = Sì, elimina il mio account
settings-account-delete-confirm-cancel = Annulla

# Sotto-pagina dell'accesso offline
settings-offline-heading = Accesso offline all'host
settings-offline-subtitle = Imposta una passphrase dedicata che ti permette di accedere dal terminale di un host Linux registrato quando non riesce a raggiungere questo server. È separata dalla password del tuo account. Usa qualcosa che ricordi ma che non riutilizzeresti.
settings-offline-status-set-prefix = Una passphrase offline è
settings-offline-status-set-word = impostata
settings-offline-status-set-suffix = . Inseriscine una nuova qui sotto per cambiarla, oppure rimuovila del tutto.
settings-offline-status-unset = Non è ancora impostata alcuna passphrase offline. Senza una non puoi accedere a un host registrato mentre è offline.
settings-offline-label-new-passphrase = Nuova passphrase offline
settings-offline-label-passphrase = Passphrase offline
settings-offline-passphrase-hint = Almeno { $min_len } caratteri. Non riutilizzare la password del tuo account.
settings-offline-action-change = Cambia passphrase
settings-offline-action-set = Imposta passphrase
settings-offline-remove-heading = Rimuovi accesso offline
settings-offline-remove-body = Elimina la tua passphrase offline. Gli host registrati la eliminano alla loro prossima sincronizzazione e non potrai più accedervi mentre sono offline.
settings-offline-action-remove = Rimuovi passphrase
settings-offline-back = Torna alle impostazioni

# Passaggio della password (recupero → imposta nuova password)
settings-handoff-heading = Imposta una nuova password
settings-handoff-subtitle = Hai effettuato l'accesso tramite il codice di recupero. Scegli una nuova password per completare.
settings-handoff-countdown-label = Tempo rimanente per impostare la tua nuova password:
settings-handoff-sign-out = Esci senza modificare

# Sotto-pagina 2FA
settings-2fa-heading = Autenticazione a due fattori
settings-2fa-subtitle = Rafforza il tuo account con un secondo fattore.
settings-2fa-no-recovery-warning-heading = Nessun codice di recupero: rischi di rimanere bloccato fuori
settings-2fa-no-recovery-warning-body = L'autenticazione a due fattori è attiva, ma non hai codici di recupero. Se perdi il tuo autenticatore o la tua chiave di sicurezza, i codici di recupero sono l'unico modo per rientrare nel tuo account. Generali ora.
settings-2fa-no-recovery-warning-action = Genera codici
settings-2fa-totp-heading = App di autenticazione (TOTP)
settings-2fa-totp-desc = Usa un'app come 1Password, Bitwarden, Aegis o Authy per generare codici di 6 cifre.
settings-2fa-totp-enabled = Attivata
settings-2fa-totp-scan-hint = Scansiona questo codice QR con la tua app di autenticazione, oppure inserisci il segreto manualmente:
settings-2fa-totp-not-offered = La configurazione dell'app di autenticazione non è attualmente offerta dal tuo server.
settings-2fa-recovery-heading = Codici di recupero
settings-2fa-recovery-desc = Codici monouso che ti permettono di accedere se perdi l'accesso al tuo autenticatore.
settings-2fa-recovery-active = Attivi
settings-2fa-recovery-save-strong = Salvali ora.
settings-2fa-recovery-save-suffix = Non verranno mostrati di nuovo. Conservali in un luogo sicuro. Un gestore di password funziona bene.
settings-2fa-recovery-not-offered = I codici di recupero non sono attualmente offerti dal tuo server.
settings-2fa-webauthn-heading = Chiavi di sicurezza e passkey
settings-2fa-webauthn-desc = Usa una chiave hardware (YubiKey, Titan) o una passkey di piattaforma (Touch ID, Windows Hello) come secondo fattore.
settings-2fa-webauthn-remove-fallback = Rimuovi chiave di sicurezza
settings-2fa-webauthn-not-enabled = Il supporto per le passkey non è stato attivato dal tuo amministratore.
settings-2fa-back = Torna alle impostazioni

# Sotto-pagina delle sessioni
settings-sessions-heading = Sessioni attive
settings-sessions-subtitle = Dispositivi attualmente connessi al tuo account. Revoca quelli che non riconosci.
settings-sessions-revoke-action = Esci
settings-sessions-revoke-others-heading = Esci da tutti gli altri dispositivi
settings-sessions-revoke-others-desc = Mantiene attiva questa sessione e revoca tutte le altre.
settings-sessions-revoke-others-action = Esci dagli altri
settings-sessions-back = Torna alle impostazioni

# Sotto-pagina delle app autorizzate
settings-apps-heading = App autorizzate
settings-apps-subtitle = App a cui hai concesso l'accesso al tuo account. Revoca quelle che non usi più. Dovranno chiedere di nuovo il permesso al tuo prossimo accesso.
settings-apps-empty = Nessuna app ha ancora ottenuto l'accesso al tuo account.
settings-apps-verified-label = Verificata
settings-apps-access-granted-prefix = Accesso concesso
settings-apps-revoke-action = Revoca accesso
settings-apps-back = Torna alle impostazioni
settings-apps-reviewed-title = Verificata dal tuo amministratore

# Residui 2FA
settings-2fa-qr-alt = Codice QR TOTP

# Scadenza del countdown del passaggio della password (renderizzato in JS)
settings-handoff-expired-lead = La tua finestra di recupero è scaduta.
settings-handoff-expired-link = Ricomincia

# Sotto-pagina dei provider collegati
settings-providers-heading = Provider collegati
settings-providers-subtitle = Accedi al tuo account usando un provider di identità di terze parti.
settings-providers-empty-heading = Nessun provider upstream configurato dal tuo amministratore.
settings-providers-empty-desc = Contatta il tuo amministratore per abilitare Google, GitHub o altri provider di accesso.
settings-providers-back = Torna alle impostazioni
settings-providers-status-connected = Connesso il { $date }
settings-providers-status-connected-plain = Connesso
settings-providers-status-not-connected = Non connesso
settings-providers-link = Collega
settings-providers-unlink = Scollega
settings-providers-unlink-blocked = Questo è il tuo unico metodo di accesso. Aggiungi una password o una passkey prima di poterlo scollegare.
settings-providers-confirm-unlink = Scollegare { $provider }? Non potrai più accedere con questo metodo.

# Suddivisioni inline-code (punto 8: 2+ elementi di codice per stringa)

# settings_profile.html - descrizione del profilo pubblico (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Visibile ai membri della tua organizzazione sulla pagina
settings-profile-public-desc-part2 = e alle app a cui concedi lo scope OAuth
settings-profile-public-desc-part3 = o
settings-profile-public-desc-part4 = . Lascia vuoto un campo qualsiasi per nasconderlo.

# settings_profile.html - suggerimento sui link (code: Label|https://url)
settings-profile-links-hint-part1 = Uno per riga, nel formato
settings-profile-links-hint-part2 = .

# Messaggi flash e testi di errore inline impostati nei gestori Rust.
flash-session-signed-out = Sessione disconnessa.
flash-session-signout-failed = Non è stato possibile disconnettere questa sessione.
flash-sessions-signed-out-others =
    { $count ->
        [one] Disconnessa { $count } altra sessione.
       *[other] Disconnesse { $count } altre sessioni.
    }
flash-sessions-signout-others-failed = Non è stato possibile disconnettere le altre sessioni.
flash-app-access-revoked = Accesso revocato.
flash-app-access-revoke-failed = Non è stato possibile revocare l'accesso per questa applicazione.
flash-offline-passphrase-saved = Passphrase offline salvata. Gli host registrati la acquisiranno alla loro prossima sincronizzazione.
flash-offline-passphrase-save-failed = Non è stato possibile salvare la tua passphrase offline. Riprova.
flash-offline-passphrase-too-short = La tua passphrase offline deve essere lunga almeno { $min_len } caratteri.
flash-offline-passphrase-removed = Passphrase offline rimossa. Gli host la elimineranno alla loro prossima sincronizzazione.
flash-offline-passphrase-none = Non hai impostato alcuna passphrase offline.
flash-offline-passphrase-remove-failed = Non è stato possibile rimuovere la tua passphrase offline. Riprova.
settings-profile-url-invalid = Il sito web e l'URL dell'avatar devono essere URL http:// o https:// validi.
settings-profile-link-url-invalid = Ogni URL di link deve essere un URL http:// o https:// valido.
settings-save-failed = Non è stato possibile salvare le tue modifiche. Riprova.
