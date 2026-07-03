# Page de connexion
auth-login-page-title = Se connecter
auth-login-card-title = Connectez-vous à votre compte
auth-login-card-subtitle = Bienvenue à nouveau sur { $brand }.
auth-login-aal2-body = Cette zone nécessite l'authentification à deux facteurs, mais votre compte n'a pas encore de deuxième facteur configuré.
auth-login-aal2-hint = Configurez une application d'authentification, une clé de sécurité ou des codes de récupération dans les paramètres, puis revenez.
auth-login-aal2-setup-link = Configurer l'authentification à deux facteurs
auth-login-forgot-password = Mot de passe oublié ?
auth-login-no-account = Vous n'avez pas de compte ?
auth-login-create-account = Créer un compte

# Séparateur partagé (connexion + inscription)
auth-or-continue-with = Ou continuer avec

# Page d'inscription
auth-registration-page-title = Créer un compte
auth-registration-card-title = Créer un compte
auth-registration-card-subtitle = Inscrivez-vous pour gérer votre identité en toute sécurité.
auth-registration-have-account = Vous avez déjà un compte ?
auth-registration-sign-in-link = Se connecter
auth-registration-claim-body = Si c'est votre adresse e-mail et que vous n'avez jamais terminé votre inscription,
auth-registration-claim-link = revendiquez-la

# Page de récupération
auth-recovery-page-title = Récupération de compte
auth-recovery-card-title-sent = Consultez votre boîte mail
auth-recovery-card-title-default = Mot de passe oublié ?
auth-recovery-card-subtitle-sent = Nous avons envoyé un code de récupération dans votre boîte de réception. Saisissez-le ci-dessous pour continuer.
auth-recovery-card-subtitle-default = Saisissez votre adresse e-mail et nous vous enverrons un lien pour le réinitialiser.
auth-recovery-back-to-sign-in = Retour à la connexion

# Page de vérification
auth-verification-page-title = Vérifiez votre adresse e-mail
auth-verification-card-title-passed = Adresse e-mail vérifiée
auth-verification-card-title-sent = Consultez votre boîte mail
auth-verification-card-title-default = Vérifiez votre adresse e-mail
auth-verification-card-subtitle-passed = Votre adresse e-mail a été confirmée. Vous pouvez fermer cet onglet ou continuer.
auth-verification-card-subtitle-sent = Nous avons envoyé un code de vérification dans votre boîte de réception. Saisissez-le ci-dessous pour confirmer.
auth-verification-card-subtitle-default = Saisissez votre adresse e-mail pour recevoir un code de vérification.
auth-verification-sent-email-hint = Utilisez le code du dernier e-mail de vérification, ou ouvrez le lien de cet e-mail plutôt que de saisir le code à la main.
auth-verification-back-to-dashboard = Retour au tableau de bord
auth-verification-back-to-sign-in = Retour à la connexion

# Textes côté navigateur pour WebAuthn / clé d'accès (intégrés via des attributs de données dans webauthn_helper.html)
auth-webauthn-no-support = Votre navigateur ne prend pas en charge WebAuthn / les clés d'accès.
auth-passkey-needs-platform = La connexion par clé d'accès nécessite un authentifiant de plateforme sur cet appareil (Touch ID, Windows Hello, un appareil Android ou une clé d'accès synchronisée). Votre navigateur n'en a aucun de configuré.
auth-webauthn-err-not-allowed = La demande d'authentifiant a été annulée, a expiré, ou aucun authentifiant correspondant n'était disponible.
auth-webauthn-err-security = Votre navigateur a refusé l'opération de sécurité. Vérifiez que le site est chargé depuis une origine de confiance et que l'identifiant enregistré correspond.
auth-webauthn-err-invalid-state = Un authentifiant est déjà enregistré avec cet appareil. Essayez plutôt de vous connecter, ou utilisez un autre appareil.
auth-webauthn-err-not-supported = Votre navigateur ne prend pas en charge les paramètres d'authentifiant demandés.
auth-webauthn-err-abort = La demande d'authentifiant a été interrompue avant son achèvement.
auth-webauthn-err-generic-prefix = Erreur de l'authentifiant :

# Libellés des champs de flux. Kratos émet les champs de trait avec le `title` du schéma
# sous l'ID de libellé générique 1070002 ; flow_view.rs les remplace par leur nom.
auth-field-email = E-mail
auth-field-first-name = Prénom
auth-field-last-name = Nom
