# Pagina di accesso
auth-login-page-title = Accedi
auth-login-card-title = Accedi al tuo account
auth-login-card-subtitle = Bentornato su { $brand }.
auth-login-aal2-body = Quest'area richiede l'autenticazione a due fattori, ma il tuo account non ha ancora un secondo fattore configurato.
auth-login-aal2-hint = Configura un'app di autenticazione, una chiave di sicurezza o dei codici di recupero nelle impostazioni, poi torna qui.
auth-login-aal2-setup-link = Configura l'autenticazione a due fattori
auth-login-forgot-password = Password dimenticata?
auth-login-no-account = Non hai un account?
auth-login-create-account = Crea un account

# Separatore condiviso (accesso + registrazione)
auth-or-continue-with = Oppure continua con

# Pagina di registrazione
auth-registration-page-title = Crea un account
auth-registration-card-title = Crea un account
auth-registration-card-subtitle = Registrati per gestire la tua identità in modo sicuro.
auth-registration-have-account = Hai già un account?
auth-registration-sign-in-link = Accedi
auth-registration-claim-body = Se questo è il tuo indirizzo email e non hai mai completato la registrazione,
auth-registration-claim-link = rivendicalo

# Pagina di recupero
auth-recovery-page-title = Recupero dell'account
auth-recovery-card-title-sent = Controlla la tua email
auth-recovery-card-title-default = Hai dimenticato la password?
auth-recovery-card-subtitle-sent = Abbiamo inviato un codice di recupero alla tua casella di posta. Inseriscilo qui sotto per continuare.
auth-recovery-card-subtitle-default = Inserisci la tua email e ti invieremo un link per reimpostarla.
auth-recovery-back-to-sign-in = Torna all'accesso

# Pagina di verifica
auth-verification-page-title = Verifica la tua email
auth-verification-card-title-passed = Email verificata
auth-verification-card-title-sent = Controlla la tua email
auth-verification-card-title-default = Verifica la tua email
auth-verification-card-subtitle-passed = Il tuo indirizzo email è stato confermato. Puoi chiudere questa scheda o continuare.
auth-verification-card-subtitle-sent = Abbiamo inviato un codice di verifica alla tua casella di posta. Inseriscilo qui sotto per confermare.
auth-verification-card-subtitle-default = Inserisci la tua email per ricevere un codice di verifica.
auth-verification-sent-email-hint = Usa il codice dell'email di verifica più recente, oppure apri il link contenuto in quell'email invece di digitare il codice a mano.
auth-verification-back-to-dashboard = Torna alla dashboard
auth-verification-back-to-sign-in = Torna all'accesso

# Testi lato browser per WebAuthn / passkey (incorporati tramite attributi data in webauthn_helper.html)
auth-webauthn-no-support = Il tuo browser non supporta WebAuthn / le passkey.
auth-passkey-needs-platform = L'accesso con passkey richiede una credenziale di piattaforma su questo dispositivo (Touch ID, Windows Hello, un dispositivo Android o una passkey sincronizzata). Il tuo browser non ne ha nessuna configurata.
auth-webauthn-err-not-allowed = La richiesta della credenziale è stata annullata, è scaduta o non era disponibile alcuna credenziale corrispondente.
auth-webauthn-err-security = Il tuo browser ha rifiutato l'operazione di sicurezza. Verifica che il sito sia caricato da un'origine attendibile e che l'identificatore registrato corrisponda.
auth-webauthn-err-invalid-state = Una credenziale è già registrata su questo dispositivo. Prova invece ad accedere, oppure usa un altro dispositivo.
auth-webauthn-err-not-supported = Il tuo browser non supporta i parametri di credenziale richiesti.
auth-webauthn-err-abort = La richiesta della credenziale è stata interrotta prima del completamento.
auth-webauthn-err-generic-prefix = Errore dell'autenticatore:

# Etichette dei campi del flusso. Kratos emette i campi trait con il `title` dello
# schema sotto l'ID etichetta passthrough generico 1070002; flow_view.rs le sovrascrive per nome.
auth-field-email = Email
auth-field-first-name = Nome
auth-field-last-name = Cognome
