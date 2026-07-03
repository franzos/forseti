# Pagina di errore
error-reference-id = ID di riferimento:
error-cta-back-to-sign-in = Torna all'accesso

# Conferma di logout OAuth
logout-card-title = Uscire da tutte le app?
logout-card-subtitle = Questo terminerà la tua sessione con { $brand } e notificherà tutte le app a cui hai effettuato l'accesso.
logout-body-text = L'app che ti ha chiesto di uscire riceverà conferma del completamento della richiesta. Alcune app potrebbero mantenere dati nella cache locale per un breve periodo; uscendo qui termini la sessione su { $brand }.
logout-action-sign-out = Esci
logout-action-cancel = Annulla

# Titoli e testi dei dialoghi admin usati da render_admin_error nei punti di chiamata che hanno una locale.
# I punti di chiamata senza locale (funzioni di supporto, error boundary) mantengono i loro testi in inglese.
dialog-identity-unavailable-title = Identità non disponibile
dialog-identity-unavailable-body = Non è stato possibile caricare questa identità. Potrebbe essere stata eliminata.
dialog-recovery-code-failed-title = Codice di recupero non riuscito
dialog-recovery-code-failed-body = Abbiamo generato il codice di recupero ma non è stato possibile predisporlo per la visualizzazione singola. Genera un nuovo codice per riprovare.
dialog-disable-failed-title = Disattivazione non riuscita
dialog-enable-failed-title = Attivazione non riuscita
dialog-delete-failed-title = Eliminazione non riuscita
dialog-revoke-failed-title = Revoca non riuscita

# Error boundary (error_boundary.html), titolo/testo/cta impostati nei gestori Rust.
error-boundary-auth-unavailable-title = Autenticazione non disponibile
error-boundary-auth-unavailable-body = Non è stato possibile raggiungere il servizio di autenticazione. Riprova tra un momento.
error-boundary-cta-try-again = Riprova
error-boundary-cta-sign-in = Accedi
error-boundary-cta-back-to-settings = Torna alle impostazioni
error-boundary-cta-back-to-dashboard = Torna alla dashboard
error-boundary-cta-back-to-account = Torna all'account
error-boundary-signin-title = Accesso non disponibile
error-boundary-signup-title = Registrazione non disponibile
error-boundary-recovery-title = Recupero non disponibile
error-boundary-verification-title = Verifica non disponibile
error-boundary-settings-title = Impostazioni non disponibili
error-boundary-logout-title = Uscita non disponibile
error-boundary-logout-body = Non è stato possibile completare l'uscita perché il servizio di autenticazione non è raggiungibile. La tua sessione è ancora attiva, quindi riprova tra un momento.
error-boundary-sessions-title = Sessioni non disponibili
error-boundary-sessions-body = Non è stato possibile elencare le tue sessioni attive. Riprova tra un momento.
error-boundary-authorized-apps-title = App autorizzate non disponibili
error-boundary-authorized-apps-no-session-body = Non è stato possibile leggere la tua sessione. Effettua di nuovo l'accesso.
error-boundary-authorized-apps-service-body = Non è stato possibile raggiungere il servizio OAuth. Riprova tra un momento.
error-boundary-account-deletion-title = Eliminazione dell'account non riuscita
error-boundary-account-delete-bad-session = La tua sessione si trova in uno stato imprevisto. Effettua di nuovo l'accesso e riprova.
error-boundary-account-delete-sole-owner = Sei l'unico proprietario di { $names }. Trasferisci la proprietà a un altro membro prima di eliminare il tuo account.
error-boundary-account-delete-ownership-check-failed = Non è stato possibile verificare la proprietà delle tue organizzazioni. Non è stato modificato nulla; riprova tra un momento.
error-boundary-account-delete-consent-unreachable = Non è stato possibile raggiungere il servizio di consenso per notificare le tue app collegate. Non è stato modificato nulla; riprova tra un momento.
error-boundary-account-delete-notifications-failed = Non è stato possibile preparare le notifiche di eliminazione. Non è stato modificato nulla; riprova.
error-boundary-account-delete-failed = Non è stato possibile eliminare il tuo account. Riprova tra un momento.

# Error boundary SAML (renderizzato con la locale predefinita; il callback ACS non trasporta alcuna locale di richiesta).
error-boundary-sso-unavailable-title = Single sign-on non disponibile
error-boundary-sso-unavailable-body = Il single sign-on non è disponibile per questo indirizzo. Controlla il link fornito dal tuo amministratore, oppure accedi con il tuo metodo abituale.
error-boundary-sso-failed-title = Single sign-on non riuscito
error-boundary-sso-validation-failed-body = Non è stato possibile convalidare questo tentativo di accesso. Ricomincia dal link SSO della tua organizzazione.
error-boundary-sso-upstream-failed-body = Il servizio di accesso è temporaneamente non disponibile. Riprova.
error-boundary-sso-no-email-body = Il provider di identità non ha fornito un indirizzo email. Chiedi al tuo amministratore di mappare l'attributo email sulla connessione SAML.

# Pagina di errore self-service di Kratos (error.html), fallback impostati in Rust.
error-page-generic-title = Qualcosa è andato storto
error-page-generic-body = Non è stato possibile caricare la pagina richiesta. Il link potrebbe essere scaduto o già utilizzato.
error-page-link-expired-title = Link scaduto
error-page-link-expired-body = Questo link non è più valido. Ricomincia dall'accesso.
error-page-security-title = Controllo di sicurezza non riuscito
error-page-already-signed-in-title = Già connesso
error-page-default-message = Non è stato possibile completare questa richiesta.

# Pagina di accesso negato dell'admin gate (admin/forbidden.html), impostata in Rust.
error-admin-access-denied-title = Accesso negato
error-admin-access-denied-body = Il tuo account non è autorizzato a usare gli strumenti di amministrazione.
error-admin-access-denied-forseti-body = Il tuo account non è autorizzato a usare gli strumenti di amministrazione a livello di Forseti.
error-admin-access-denied-org-body = Non hai accesso amministrativo a questa organizzazione.

# SAML bloccato
error-saml-blocked-page-title = Accesso bloccato
error-saml-blocked-card-title = Non è stato possibile eseguire l'accesso
error-saml-unverified-prefix = Un account per
error-saml-unverified-suffix = esiste già ma il suo indirizzo email non è stato verificato, quindi il single sign-on non può collegarsi ad esso in modo sicuro. Verifica l'indirizzo tramite l'email di registrazione originale, oppure chiedi aiuto al tuo amministratore.
error-saml-cross-org-not-member = Il tuo account non è ancora membro di questa organizzazione. Chiedi al tuo amministratore di aggiungerti, poi riprova.
error-saml-conflict = Non è stato possibile eseguire l'accesso. Contatta il tuo amministratore.
error-saml-blocked-cta = Vai all'accesso
