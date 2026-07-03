# Messages de flux Kratos indexés par ID numérique stable.
# Vouvoiement (registre formel). Passthrough (PAS dans ce catalogue) : 4000001 (validation générique - le texte EST la charge utile).
# Le texte anglais correspond à l'anglais d'Ory Kratos OSS lorsque Fluent le permet ; les messages
# de flux expiré utilisent un texte simplifié car Fluent ne peut pas calculer %.2f minutes depuis un timestamp unix.

# --- Connexion (1010xxx) ---
kratos-1010001 = Se connecter
kratos-1010002 = Se connecter avec { $provider }
kratos-1010003 = Veuillez confirmer cette action en vérifiant qu'il s'agit bien de vous.
kratos-1010004 = Veuillez compléter le second défi d'authentification.
kratos-1010005 = Vérifier
kratos-1010006 = Code d'authentification
kratos-1010007 = Code de récupération de secours
kratos-1010008 = Se connecter avec une clé matérielle
kratos-1010009 = Utiliser l'application d'authentification
kratos-1010010 = Utiliser un code de récupération de secours
kratos-1010011 = Se connecter avec une clé matérielle
kratos-1010012 = Préparez votre appareil WebAuthn (p. ex. clé de sécurité, lecteur biométrique, ...) et cliquez sur Continuer.
kratos-1010013 = Continuer
kratos-1010014 = Un code a été envoyé à l'adresse indiquée. Si vous ne l'avez pas reçu, vérifiez l'orthographe de l'adresse et réessayez.
kratos-1010015 = Envoyer le code de connexion
kratos-1010021 = Se connecter avec une clé d'accès
kratos-1010022 = Se connecter avec un mot de passe

# --- Inscription (1040xxx) ---
kratos-1040001 = S'inscrire
kratos-1040002 = S'inscrire avec { $provider }
kratos-1040003 = Continuer
kratos-1040004 = S'inscrire avec une clé de sécurité
kratos-1040005 = Un code a été envoyé à la ou aux adresses indiquées. Si vous n'avez pas reçu d'e-mail, vérifiez l'orthographe de l'adresse et assurez-vous d'utiliser l'adresse avec laquelle vous vous êtes inscrit.
kratos-1040006 = Envoyer le code d'inscription
kratos-1040007 = S'inscrire avec une clé d'accès
kratos-1040008 = Retour

# --- Paramètres (1050xxx) ---
kratos-1050001 = Vos modifications ont été enregistrées !
kratos-1050002 = Associer { $provider }
kratos-1050003 = Dissocier { $provider }
kratos-1050004 = Dissocier l'application d'authentification TOTP
kratos-1050007 = Afficher les codes de récupération de secours
kratos-1050008 = Générer de nouveaux codes de récupération de secours
kratos-1050010 = Voici vos codes de récupération de secours. Conservez-les en lieu sûr !
kratos-1050011 = Confirmer les codes de récupération de secours
kratos-1050012 = Ajouter une clé de sécurité
kratos-1050013 = Nom de la clé de sécurité
kratos-1050016 = Désactiver cette méthode
kratos-1050017 = Voici le secret de votre application d'authentification. Utilisez-le si vous ne pouvez pas scanner le code QR.
kratos-1050018 = Supprimer la clé de sécurité "{ $display_name }"
kratos-1050019 = Ajouter une clé d'accès
kratos-1050020 = Supprimer la clé d'accès "{ $display_name }"
kratos-1050023 = Votre compte est géré par votre organisation. Pour modifier ces paramètres, contactez l'administrateur de votre organisation.

# --- Récupération de compte (1060xxx) ---
# 1060001 : le texte d'Ory contient "within the next %.2f minutes" mais le contexte porte
# un timestamp, pas des minutes. Simplifié ici ; la valeur de repli donne l'anglais exact d'Ory.
kratos-1060001 = Vous avez récupéré votre compte avec succès. Veuillez changer votre mot de passe ou configurer prochainement une méthode de connexion alternative (p. ex. connexion sociale).
kratos-1060002 = Un e-mail contenant un lien de récupération a été envoyé à l'adresse e-mail indiquée. Si vous n'avez pas reçu d'e-mail, vérifiez l'orthographe de l'adresse et assurez-vous d'utiliser l'adresse avec laquelle vous vous êtes inscrit.
kratos-1060003 = Un e-mail contenant un code de récupération a été envoyé à l'adresse e-mail indiquée. Si vous n'avez pas reçu d'e-mail, vérifiez l'orthographe de l'adresse et assurez-vous d'utiliser l'adresse avec laquelle vous vous êtes inscrit.
kratos-1060004 = Un code de récupération a été envoyé à { $masked_address }. Si vous ne l'avez pas reçu, vérifiez l'orthographe de l'adresse et assurez-vous d'utiliser l'adresse avec laquelle vous vous êtes inscrit.

# --- Libellés de nœud (1070xxx) ---
kratos-1070001 = Mot de passe
kratos-1070003 = Enregistrer
kratos-1070004 = ID
kratos-1070005 = Envoyer
kratos-1070006 = Vérifier le code
kratos-1070007 = E-mail
kratos-1070008 = Renvoyer le code
kratos-1070009 = Continuer
kratos-1070010 = Code de récupération
kratos-1070011 = Code de vérification
kratos-1070012 = Code d'inscription
kratos-1070013 = Code de connexion
kratos-1070016 = Adresse de récupération

# --- Vérification (1080xxx) ---
kratos-1080001 = Un e-mail contenant un lien de vérification a été envoyé à l'adresse e-mail indiquée. Si vous n'avez pas reçu d'e-mail, vérifiez l'orthographe de l'adresse et assurez-vous d'utiliser l'adresse avec laquelle vous vous êtes inscrit.
kratos-1080002 = Vous avez vérifié votre adresse e-mail avec succès.
kratos-1080003 = Un e-mail contenant un code de vérification a été envoyé à l'adresse e-mail indiquée. Si vous n'avez pas reçu d'e-mail, vérifiez l'orthographe de l'adresse et assurez-vous d'utiliser l'adresse avec laquelle vous vous êtes inscrit.

# --- Erreurs de validation (4000xxx) ---
# 4000001 est passthrough : le texte EST la raison de validation dynamique.
kratos-4000002 = La propriété { $property } est manquante.
kratos-4000003 = la longueur doit être >= { $min_length }, mais elle est de { $actual_length }
# 4000005 : $reason provient de la configuration de politique de Kratos ; il sera en anglais au sein d'une phrase traduite.
kratos-4000005 = Le mot de passe ne peut pas être utilisé car { $reason }.
kratos-4000006 = Les identifiants fournis sont invalides, vérifiez les fautes de frappe dans votre mot de passe, votre nom d'utilisateur, votre adresse e-mail ou votre numéro de téléphone.
kratos-4000007 = Un compte avec le même identifiant (e-mail, téléphone, nom d'utilisateur, ...) existe déjà.
kratos-4000008 = Le code d'authentification fourni est invalide, veuillez réessayer.
kratos-4000032 = Le mot de passe doit comporter au moins { $min_length } caractères, mais il n'en compte que { $actual_length }.
kratos-4000035 = Ce compte n'existe pas ou n'a pas configuré la connexion par code.

# --- Erreurs du flux de connexion (4010xxx) ---
# Simplifié : Ory calcule "X.XX minutes ago" depuis un timestamp que nous ne pouvons pas mettre en forme dans Fluent.
kratos-4010001 = Le processus de connexion a expiré, veuillez réessayer.
kratos-4010008 = Le code de connexion est invalide ou a déjà été utilisé. Veuillez réessayer.

# --- Erreurs du flux d'inscription (4040xxx) ---
kratos-4040001 = Le processus d'inscription a expiré, veuillez réessayer.
kratos-4040003 = Le code d'inscription est invalide ou a déjà été utilisé. Veuillez réessayer.

# --- Erreurs du flux de paramètres (4050xxx) ---
kratos-4050001 = Le processus de modification des paramètres a expiré, veuillez réessayer.

# --- Erreurs du flux de récupération (4060xxx) ---
kratos-4060004 = Le jeton de récupération est invalide ou a déjà été utilisé. Veuillez recommencer le processus.
kratos-4060006 = Le code de récupération est invalide ou a déjà été utilisé. Veuillez réessayer.

# --- Erreurs du flux de vérification (4070xxx) ---
kratos-4070001 = Le jeton de vérification est invalide ou a déjà été utilisé. Veuillez recommencer le processus.
kratos-4070005 = Le processus de vérification a expiré, veuillez réessayer.
kratos-4070006 = Le code de vérification est invalide ou a déjà été utilisé. Veuillez réessayer.
