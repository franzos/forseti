# Superficie di onboarding (modelli claim_email e invite)

# Rivendicazione email (claim_email.html)
claim-page-title = Rivendica email
claim-card-title = Rivendica indirizzo email
claim-subtitle = Se qualcuno ha registrato la tua email ma non l'ha mai verificata, puoi prenderne possesso confermando di ricevere la posta a questo indirizzo.
claim-email-label = Email
claim-send-code = Invia codice
claim-changed-mind = Hai cambiato idea?
claim-back-to-signup = Torna alla registrazione

# Conferma rivendicazione (claim_email_confirm.html)
claim-confirm-page-title = Conferma rivendicazione
claim-confirm-card-title = Conferma il tuo codice
claim-confirm-subtitle = Inserisci il codice di 6 cifre che abbiamo appena inviato. I codici scadono dopo 15 minuti.
claim-confirm-code-label = Codice
claim-confirm-button = Conferma
claim-confirm-no-code = Non hai ricevuto un codice?
claim-confirm-start-over = Ricomincia

# Accetta invito (invite/accept.html)
invite-accept-page-title = Accetta invito
invite-accept-heading = Unisciti a { $org }
invite-accept-body = Sei stato invitato a unirti a { $org } come { $role }. L'invito è stato inviato a { $email }.

# Invito non disponibile (invite/invalid.html)
invite-invalid-page-title = Invito non disponibile
invite-invalid-heading = Invito non disponibile
invite-invalid-contact = Contatta la persona che ti ha invitato per richiedere un nuovo link.
invite-invalid-back = Torna alla dashboard

# Errori del flusso claim-email (impostati in Rust)
claim-error-invalid-email = Inserisci un indirizzo email valido.
claim-error-code-expired = Il codice è scaduto. Ricomincia.
claim-error-invalid-token = Token non valido. Ricomincia.
claim-error-service-unavailable = Servizio temporaneamente non disponibile. Riprova tra un momento.
claim-error-too-many-attempts = Troppi codici errati. Ricomincia.
claim-error-code-mismatch = Il codice non corrisponde. Riprova.
claim-error-no-longer-claimable = Questa email non può più essere rivendicata.
claim-error-release-failed = Non è stato possibile rilasciare l'email. Contatta l'assistenza.

# Finalizzazione invito (impostato in Rust)
invite-error-corrupt = L'invito è danneggiato. Contatta il tuo amministratore.
