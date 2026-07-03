# Messaggi dei flussi Kratos indicizzati per ID numerico stabile.
# Passthrough (NON in questo catalogo): 4000001 (validazione generica: il testo È il payload).
# Il testo inglese corrisponde all'inglese di Ory Kratos OSS dove Fluent lo consente; i messaggi di flusso scaduto
# usano un testo semplificato perché Fluent non può calcolare %.2f minuti da un timestamp unix.

# --- Accesso (1010xxx) ---
kratos-1010001 = Accedi
kratos-1010002 = Accedi con { $provider }
kratos-1010003 = Conferma questa azione verificando la tua identità.
kratos-1010004 = Completa la seconda verifica di autenticazione.
kratos-1010005 = Verifica
kratos-1010006 = Codice di autenticazione
kratos-1010007 = Codice di recupero di backup
kratos-1010008 = Accedi con una chiave hardware
kratos-1010009 = Usa l'app di autenticazione
kratos-1010010 = Usa un codice di recupero di backup
kratos-1010011 = Accedi con una chiave hardware
kratos-1010012 = Prepara il tuo dispositivo WebAuthn (ad es. chiave di sicurezza, scanner biometrico, ...) e premi continua.
kratos-1010013 = Continua
kratos-1010014 = Un codice è stato inviato all'indirizzo che hai fornito. Se non l'hai ricevuto, controlla l'ortografia dell'indirizzo e riprova.
kratos-1010015 = Invia codice di accesso
kratos-1010021 = Accedi con passkey
kratos-1010022 = Accedi con password

# --- Registrazione (1040xxx) ---
kratos-1040001 = Registrati
kratos-1040002 = Registrati con { $provider }
kratos-1040003 = Continua
kratos-1040004 = Registrati con una chiave di sicurezza
kratos-1040005 = Un codice è stato inviato all'indirizzo (o agli indirizzi) che hai fornito. Se non hai ricevuto un'email, controlla l'ortografia dell'indirizzo e assicurati di usare l'indirizzo con cui ti sei registrato.
kratos-1040006 = Invia codice di registrazione
kratos-1040007 = Registrati con passkey
kratos-1040008 = Indietro

# --- Impostazioni (1050xxx) ---
kratos-1050001 = Le tue modifiche sono state salvate!
kratos-1050002 = Collega { $provider }
kratos-1050003 = Scollega { $provider }
kratos-1050004 = Scollega l'app di autenticazione TOTP
kratos-1050007 = Mostra i codici di recupero di backup
kratos-1050008 = Genera nuovi codici di recupero di backup
kratos-1050010 = Questi sono i tuoi codici di recupero di backup. Conservali in un luogo sicuro!
kratos-1050011 = Conferma i codici di recupero di backup
kratos-1050012 = Aggiungi chiave di sicurezza
kratos-1050013 = Nome della chiave di sicurezza
kratos-1050016 = Disattiva questo metodo
kratos-1050017 = Questo è il segreto della tua app di autenticazione. Usalo se non riesci a scansionare il codice QR.
kratos-1050018 = Rimuovi la chiave di sicurezza "{ $display_name }"
kratos-1050019 = Aggiungi passkey
kratos-1050020 = Rimuovi la passkey "{ $display_name }"
kratos-1050023 = Il tuo account è gestito dalla tua organizzazione. Per modificare queste impostazioni, contatta l'amministratore della tua organizzazione.

# --- Recupero (1060xxx) ---
# 1060001: il testo di Ory contiene "within the next %.2f minutes" ma il contesto trasporta un
# timestamp, non i minuti. Semplificato qui; il fallback fornisce l'inglese esatto di Ory.
kratos-1060001 = Hai recuperato correttamente il tuo account. Cambia presto la tua password o configura un metodo di accesso alternativo (ad es. accesso social).
kratos-1060002 = Un'email contenente un link di recupero è stata inviata all'indirizzo email che hai fornito. Se non hai ricevuto un'email, controlla l'ortografia dell'indirizzo e assicurati di usare l'indirizzo con cui ti sei registrato.
kratos-1060003 = Un'email contenente un codice di recupero è stata inviata all'indirizzo email che hai fornito. Se non hai ricevuto un'email, controlla l'ortografia dell'indirizzo e assicurati di usare l'indirizzo con cui ti sei registrato.
kratos-1060004 = Un codice di recupero è stato inviato a { $masked_address }. Se non l'hai ricevuto, controlla l'ortografia dell'indirizzo e assicurati di usare l'indirizzo con cui ti sei registrato.

# --- Etichette dei nodi (1070xxx) ---
kratos-1070001 = Password
kratos-1070003 = Salva
kratos-1070004 = ID
kratos-1070005 = Invia
kratos-1070006 = Verifica il codice
kratos-1070007 = Email
kratos-1070008 = Invia di nuovo il codice
kratos-1070009 = Continua
kratos-1070010 = Codice di recupero
kratos-1070011 = Codice di verifica
kratos-1070012 = Codice di registrazione
kratos-1070013 = Codice di accesso
kratos-1070016 = Indirizzo di recupero

# --- Verifica (1080xxx) ---
kratos-1080001 = Un'email contenente un link di verifica è stata inviata all'indirizzo email che hai fornito. Se non hai ricevuto un'email, controlla l'ortografia dell'indirizzo e assicurati di usare l'indirizzo con cui ti sei registrato.
kratos-1080002 = Hai verificato correttamente il tuo indirizzo email.
kratos-1080003 = Un'email contenente un codice di verifica è stata inviata all'indirizzo email che hai fornito. Se non hai ricevuto un'email, controlla l'ortografia dell'indirizzo e assicurati di usare l'indirizzo con cui ti sei registrato.

# --- Errori di validazione (4000xxx) ---
# 4000001 è passthrough: il testo È il motivo di validazione dinamico.
kratos-4000002 = La proprietà { $property } è mancante.
kratos-4000003 = la lunghezza deve essere >= { $min_length }, ma è { $actual_length }
# 4000005: $reason proviene dalla configurazione delle policy di Kratos; sarà in inglese all'interno di una frase tradotta.
kratos-4000005 = La password non può essere utilizzata perché { $reason }.
kratos-4000006 = Le credenziali fornite non sono valide, controlla eventuali errori di battitura nella password o nel nome utente, nell'indirizzo email o nel numero di telefono.
kratos-4000007 = Esiste già un account con lo stesso identificatore (email, telefono, nome utente, ...).
kratos-4000008 = Il codice di autenticazione fornito non è valido, riprova.
kratos-4000032 = La password deve essere lunga almeno { $min_length } caratteri, ma ne ha { $actual_length }.
kratos-4000035 = Questo account non esiste o non ha configurato l'accesso con codice.

# --- Errori del flusso di accesso (4010xxx) ---
# Semplificato: Ory calcola "X.XX minutes ago" da un timestamp che non possiamo formattare in Fluent.
kratos-4010001 = Il flusso di accesso è scaduto, riprova.
kratos-4010008 = Il codice di accesso non è valido o è già stato utilizzato. Riprova.

# --- Errori del flusso di registrazione (4040xxx) ---
kratos-4040001 = Il flusso di registrazione è scaduto, riprova.
kratos-4040003 = Il codice di registrazione non è valido o è già stato utilizzato. Riprova.

# --- Errori del flusso delle impostazioni (4050xxx) ---
kratos-4050001 = Il flusso delle impostazioni è scaduto, riprova.

# --- Errori del flusso di recupero (4060xxx) ---
kratos-4060004 = Il token di recupero non è valido o è già stato utilizzato. Riprova il flusso.
kratos-4060006 = Il codice di recupero non è valido o è già stato utilizzato. Riprova.

# --- Errori del flusso di verifica (4070xxx) ---
kratos-4070001 = Il token di verifica non è valido o è già stato utilizzato. Riprova il flusso.
kratos-4070005 = Il flusso di verifica è scaduto, riprova.
kratos-4070006 = Il codice di verifica non è valido o è già stato utilizzato. Riprova.
