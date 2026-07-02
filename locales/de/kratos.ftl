# Kratos-Flow-Nachrichten nach stabiler numerischer ID.
# Formelle Anrede (Sie). Passthrough (NICHT im Katalog): 4000001.

# --- Anmeldung (1010xxx) ---
kratos-1010001 = Anmelden
kratos-1010002 = Mit { $provider } anmelden
kratos-1010003 = Bitte bestätigen Sie diese Aktion, indem Sie sich verifizieren.
kratos-1010004 = Bitte schließen Sie die zweite Authentifizierung ab.
kratos-1010005 = Bestätigen
kratos-1010006 = Authentifizierungscode
kratos-1010007 = Backup-Wiederherstellungscode
kratos-1010008 = Mit einem Hardware-Schlüssel anmelden
kratos-1010009 = Authenticator verwenden
kratos-1010010 = Backup-Wiederherstellungscode verwenden
kratos-1010011 = Mit einem Hardware-Schlüssel anmelden
kratos-1010012 = Bereiten Sie Ihr WebAuthn-Gerät vor (z. B. Sicherheitsschlüssel, Biometriescanner, ...) und klicken Sie auf Weiter.
kratos-1010013 = Weiter
kratos-1010014 = Ein Code wurde an die angegebene Adresse gesendet. Falls Sie ihn nicht erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse und versuchen Sie es erneut.
kratos-1010015 = Anmeldecode senden
kratos-1010021 = Mit Passkey anmelden
kratos-1010022 = Mit Passwort anmelden

# --- Registrierung (1040xxx) ---
kratos-1040001 = Registrieren
kratos-1040002 = Mit { $provider } registrieren
kratos-1040003 = Weiter
kratos-1040004 = Mit Sicherheitsschlüssel registrieren
kratos-1040005 = Ein Code wurde an die angegebene(n) Adresse(n) gesendet. Falls Sie keine E-Mail erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse und stellen Sie sicher, dass Sie die bei der Registrierung verwendete Adresse angeben.
kratos-1040006 = Registrierungscode senden
kratos-1040007 = Mit Passkey registrieren
kratos-1040008 = Zurück

# --- Einstellungen (1050xxx) ---
kratos-1050001 = Ihre Änderungen wurden gespeichert!
kratos-1050002 = { $provider } verknüpfen
kratos-1050003 = { $provider } trennen
kratos-1050004 = TOTP-Authenticator-App trennen
kratos-1050007 = Backup-Wiederherstellungscodes anzeigen
kratos-1050008 = Neue Backup-Wiederherstellungscodes generieren
kratos-1050010 = Dies sind Ihre Backup-Wiederherstellungscodes. Bewahren Sie diese bitte sicher auf!
kratos-1050011 = Backup-Wiederherstellungscodes bestätigen
kratos-1050012 = Sicherheitsschlüssel hinzufügen
kratos-1050013 = Name des Sicherheitsschlüssels
kratos-1050016 = Diese Methode deaktivieren
kratos-1050017 = Dies ist der geheime Schlüssel Ihrer Authenticator-App. Verwenden Sie ihn, wenn Sie den QR-Code nicht scannen können.
kratos-1050018 = Sicherheitsschlüssel "{ $display_name }" entfernen
kratos-1050019 = Passkey hinzufügen
kratos-1050020 = Passkey "{ $display_name }" entfernen
kratos-1050023 = Ihr Konto wird von Ihrer Organisation verwaltet. Um diese Einstellungen zu ändern, wenden Sie sich an Ihren Organisationsadministrator.

# --- Kontowiederherstellung (1060xxx) ---
kratos-1060001 = Ihr Konto wurde erfolgreich wiederhergestellt. Bitte ändern Sie Ihr Passwort oder richten Sie eine alternative Anmeldemethode ein (z. B. Social Login).
kratos-1060002 = Eine E-Mail mit einem Wiederherstellungslink wurde an die angegebene E-Mail-Adresse gesendet. Falls Sie keine E-Mail erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse.
kratos-1060003 = Eine E-Mail mit einem Wiederherstellungscode wurde an die angegebene E-Mail-Adresse gesendet. Falls Sie keine E-Mail erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse.
kratos-1060004 = Ein Wiederherstellungscode wurde an { $masked_address } gesendet. Falls Sie ihn nicht erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse.

# --- Knotenbezeichnungen (1070xxx) ---
kratos-1070001 = Passwort
kratos-1070003 = Speichern
kratos-1070004 = ID
kratos-1070005 = Absenden
kratos-1070006 = Code bestätigen
kratos-1070007 = E-Mail
kratos-1070008 = Code erneut senden
kratos-1070009 = Weiter
kratos-1070010 = Wiederherstellungscode
kratos-1070011 = Bestätigungscode
kratos-1070012 = Registrierungscode
kratos-1070013 = Anmeldecode
kratos-1070016 = Wiederherstellungsadresse

# --- E-Mail-Verifizierung (1080xxx) ---
kratos-1080001 = Eine E-Mail mit einem Bestätigungslink wurde an die angegebene E-Mail-Adresse gesendet. Falls Sie keine E-Mail erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse.
kratos-1080002 = Ihre E-Mail-Adresse wurde erfolgreich bestätigt.
kratos-1080003 = Eine E-Mail mit einem Bestätigungscode wurde an die angegebene E-Mail-Adresse gesendet. Falls Sie keine E-Mail erhalten haben, überprüfen Sie bitte die Schreibweise der Adresse.

# --- Validierungsfehler (4000xxx) ---
# 4000001 ist Passthrough: Der Text IST die dynamische Fehlermeldung.
kratos-4000002 = Das Pflichtfeld { $property } fehlt.
kratos-4000003 = Länge muss >= { $min_length } sein, hat aber { $actual_length }
# 4000005: $reason kommt aus der Kratos-Konfiguration (englischer Text).
kratos-4000005 = Das Passwort kann nicht verwendet werden, weil { $reason }.
kratos-4000006 = Die eingegebenen Zugangsdaten sind ungültig. Überprüfen Sie bitte Tippfehler in Ihrem Passwort, Benutzernamen, Ihrer E-Mail-Adresse oder Telefonnummer.
kratos-4000007 = Es gibt bereits ein Konto mit dieser Kennung (E-Mail, Telefon, Benutzername, ...).
kratos-4000008 = Der eingegebene Authentifizierungscode ist ungültig, bitte versuchen Sie es erneut.
kratos-4000032 = Das Passwort muss mindestens { $min_length } Zeichen lang sein, enthält aber nur { $actual_length }.
kratos-4000035 = Dieses Konto existiert nicht oder hat keine Code-Anmeldung konfiguriert.

# --- Anmelde-Flow-Fehler (4010xxx) ---
kratos-4010001 = Der Anmelde-Flow ist abgelaufen, bitte versuchen Sie es erneut.
kratos-4010008 = Der Anmeldecode ist ungültig oder wurde bereits verwendet. Bitte versuchen Sie es erneut.

# --- Registrierungs-Flow-Fehler (4040xxx) ---
kratos-4040001 = Der Registrierungs-Flow ist abgelaufen, bitte versuchen Sie es erneut.
kratos-4040003 = Der Registrierungscode ist ungültig oder wurde bereits verwendet. Bitte versuchen Sie es erneut.

# --- Einstellungs-Flow-Fehler (4050xxx) ---
kratos-4050001 = Der Einstellungs-Flow ist abgelaufen, bitte versuchen Sie es erneut.

# --- Kontowiederherstellungs-Flow-Fehler (4060xxx) ---
kratos-4060004 = Das Wiederherstellungstoken ist ungültig oder wurde bereits verwendet. Bitte starten Sie den Vorgang erneut.
kratos-4060006 = Der Wiederherstellungscode ist ungültig oder wurde bereits verwendet. Bitte versuchen Sie es erneut.

# --- E-Mail-Verifizierungs-Flow-Fehler (4070xxx) ---
kratos-4070001 = Das Verifizierungstoken ist ungültig oder wurde bereits verwendet. Bitte starten Sie den Vorgang erneut.
kratos-4070005 = Der Verifizierungs-Flow ist abgelaufen, bitte versuchen Sie es erneut.
kratos-4070006 = Der Bestätigungscode ist ungültig oder wurde bereits verwendet. Bitte versuchen Sie es erneut.
