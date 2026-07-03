settings-hub-title = Paramètres
settings-hub-subtitle = Gérez vos préférences de compte, vos paramètres de sécurité et vos sessions actives.
settings-hub-profile-title = Profil
settings-hub-profile-desc = Mettez à jour votre adresse e-mail et votre nom d'affichage.
settings-hub-profile-link = Gérer le profil
settings-hub-password-title = Mot de passe
settings-hub-password-desc = Changez le mot de passe de votre compte.
settings-hub-password-link = Changer le mot de passe
settings-hub-2fa-title = Authentification à deux facteurs
settings-hub-2fa-desc = Configurez TOTP, les codes de récupération et les clés de sécurité.
settings-hub-2fa-link = Gérer la 2FA
settings-hub-sessions-title = Sessions actives
settings-hub-sessions-desc = Examinez les appareils connectés à votre compte.
settings-hub-sessions-link = Voir les sessions
settings-hub-apps-title = Applications autorisées
settings-hub-apps-desc = Examinez et révoquez les applications OAuth auxquelles vous avez accordé l'accès.
settings-hub-apps-link = Gérer les applications
settings-hub-providers-title = Fournisseurs associés
settings-hub-providers-desc = Connectez ou supprimez des fournisseurs de connexion tiers.
settings-hub-providers-link = Gérer les fournisseurs
settings-hub-account-title = Compte
settings-hub-account-desc = Modifications permanentes : supprimez votre compte.
settings-hub-account-link = Zone dangereuse
settings-nav-general = Général
settings-nav-security = Sécurité
settings-nav-connections = Connexions
settings-nav-overview = Vue d'ensemble
settings-nav-profile = Profil
settings-nav-organization = Organisation
settings-nav-password = Mot de passe
settings-nav-2fa = 2FA
settings-nav-sessions = Sessions
settings-nav-offline = Connexion hors ligne
settings-nav-authorized-apps = Applications autorisées
settings-nav-linked-providers = Fournisseurs associés
settings-nav-account = Compte

# Sous-page de profil
settings-profile-heading = Profil
settings-profile-subtitle = Mettez à jour votre adresse e-mail et votre nom d'affichage.
settings-profile-email-not-verified = Non vérifiée
settings-profile-email-send-verification = Envoyer l'e-mail de vérification
settings-profile-public-heading = Profil public
settings-profile-public-saved = Profil enregistré.
settings-profile-public-label-bio = Bio
settings-profile-public-label-location = Localisation
settings-profile-public-label-pronouns = Pronoms
settings-profile-public-label-website = Site web
settings-profile-public-label-avatar = URL de l'avatar
settings-profile-public-avatar-hint = Facultatif. Laissez vide pour utiliser l'identicon généré automatiquement.
settings-profile-public-label-links = Liens
settings-profile-public-save = Enregistrer le profil
settings-profile-back = Retour aux paramètres
settings-profile-language-label = Langue préférée
settings-profile-language-help = S'applique sur tous vos appareils.

# Sous-page de mot de passe
settings-password-heading = Mot de passe
settings-password-subtitle = Changez le mot de passe utilisé pour vous connecter.
settings-password-back = Retour aux paramètres

# Sous-page de compte
settings-account-heading = Compte
settings-account-subtitle = Modifications permanentes de votre compte.
settings-account-delete-section-heading = Supprimer le compte
settings-account-delete-body = Supprimez définitivement votre compte, chaque session active et tout l'état 2FA / récupération. Les applications qui détiennent des copies de vos données sont notifiées afin qu'elles puissent nettoyer leur côté. Cette action est irréversible.
settings-account-delete-action = Supprimer mon compte

# Page de confirmation de suppression de compte
settings-account-delete-page-title = Confirmer la suppression
settings-account-delete-confirm-heading = Supprimer votre compte ?
settings-account-delete-confirm-subtitle-prefix = Cela supprime définitivement
settings-account-delete-confirm-subtitle-suffix = ainsi que chaque session, code de récupération et identifiant qui y est rattaché.
settings-account-delete-apps-heading = Ces applications seront informées de votre départ
settings-account-delete-apps-note = Les applications copient les données dont elles ont besoin (profil, paramètres) et les conservent liées à l'ID de votre compte. Nous les notifions via le webhook de suppression qu'elles ont enregistré afin qu'elles puissent nettoyer leur copie.
settings-account-delete-no-apps = Aucune application tierce ne détient de copie de vos données pour le moment. Personne à notifier.
settings-account-delete-confirm-label = Pour confirmer, saisissez votre adresse e-mail ci-dessous :
settings-account-delete-confirm-placeholder = Saisissez votre e-mail pour confirmer
settings-account-delete-confirm-submit = Oui, supprimer mon compte
settings-account-delete-confirm-cancel = Annuler

# Sous-page d'accès hors ligne
settings-offline-heading = Connexion à un hôte hors ligne
settings-offline-subtitle = Définissez une phrase secrète dédiée qui vous permet de vous connecter au terminal d'un hôte Linux enrôlé lorsqu'il ne peut pas joindre ce serveur. Elle est distincte du mot de passe de votre compte. Utilisez quelque chose dont vous vous souviendrez mais que vous ne réutiliseriez pas.
settings-offline-status-set-prefix = Une phrase secrète hors ligne est
settings-offline-status-set-word = définie
settings-offline-status-set-suffix = . Saisissez-en une nouvelle ci-dessous pour la modifier, ou supprimez-la entièrement.
settings-offline-status-unset = Aucune phrase secrète hors ligne n'est encore définie. Sans elle, vous ne pouvez pas vous connecter à un hôte enrôlé lorsqu'il est hors ligne.
settings-offline-label-new-passphrase = Nouvelle phrase secrète hors ligne
settings-offline-label-passphrase = Phrase secrète hors ligne
settings-offline-passphrase-hint = Au moins { $min_len } caractères. Ne réutilisez pas le mot de passe de votre compte.
settings-offline-action-change = Changer la phrase secrète
settings-offline-action-set = Définir la phrase secrète
settings-offline-remove-heading = Supprimer l'accès hors ligne
settings-offline-remove-body = Supprimez votre phrase secrète hors ligne. Les hôtes enrôlés l'abandonnent à leur prochaine synchronisation, et vous ne pourrez plus vous y connecter lorsqu'ils sont hors ligne.
settings-offline-action-remove = Supprimer la phrase secrète
settings-offline-back = Retour aux paramètres

# Transfert de mot de passe (récupération → définir un nouveau mot de passe)
settings-handoff-heading = Définir un nouveau mot de passe
settings-handoff-subtitle = Vous êtes connecté via le code de récupération. Choisissez un nouveau mot de passe pour terminer.
settings-handoff-countdown-label = Temps restant pour définir votre nouveau mot de passe :
settings-handoff-sign-out = Se déconnecter sans changer

# Sous-page 2FA
settings-2fa-heading = Authentification à deux facteurs
settings-2fa-subtitle = Renforcez votre compte avec un deuxième facteur.
settings-2fa-no-recovery-warning-heading = Aucun code de récupération : vous risquez d'être bloqué
settings-2fa-no-recovery-warning-body = L'authentification à deux facteurs est active, mais vous n'avez aucun code de récupération. Si vous perdez votre authentifiant ou votre clé de sécurité, les codes de récupération sont le seul moyen de revenir dans votre compte. Générez-les maintenant.
settings-2fa-no-recovery-warning-action = Générer des codes
settings-2fa-totp-heading = Application d'authentification (TOTP)
settings-2fa-totp-desc = Utilisez une application comme 1Password, Bitwarden, Aegis ou Authy pour générer des codes à 6 chiffres.
settings-2fa-totp-enabled = Activée
settings-2fa-totp-scan-hint = Scannez ce code QR avec votre application d'authentification, ou saisissez le secret manuellement :
settings-2fa-totp-not-offered = La configuration d'une application d'authentification n'est pas proposée actuellement par votre serveur.
settings-2fa-recovery-heading = Codes de récupération
settings-2fa-recovery-desc = Codes à usage unique qui vous permettent de vous connecter si vous perdez l'accès à votre authentifiant.
settings-2fa-recovery-active = Actifs
settings-2fa-recovery-save-strong = Enregistrez-les maintenant.
settings-2fa-recovery-save-suffix = Ils ne seront plus affichés. Conservez-les en lieu sûr. Un gestionnaire de mots de passe convient bien.
settings-2fa-recovery-not-offered = Les codes de récupération ne sont pas proposés actuellement par votre serveur.
settings-2fa-webauthn-heading = Clés de sécurité et clés d'accès
settings-2fa-webauthn-desc = Utilisez une clé matérielle (YubiKey, Titan) ou une clé d'accès de plateforme (Touch ID, Windows Hello) comme deuxième facteur.
settings-2fa-webauthn-remove-fallback = Supprimer la clé de sécurité
settings-2fa-webauthn-not-enabled = La prise en charge des clés d'accès n'est pas activée par votre administrateur.
settings-2fa-back = Retour aux paramètres

# Sous-page des sessions
settings-sessions-heading = Sessions actives
settings-sessions-subtitle = Appareils actuellement connectés à votre compte. Révoquez tous ceux que vous ne reconnaissez pas.
settings-sessions-revoke-action = Se déconnecter
settings-sessions-revoke-others-heading = Se déconnecter de tous les autres appareils
settings-sessions-revoke-others-desc = Garde cette session active et révoque toutes les autres.
settings-sessions-revoke-others-action = Déconnecter les autres
settings-sessions-back = Retour aux paramètres

# Sous-page des applications autorisées
settings-apps-heading = Applications autorisées
settings-apps-subtitle = Applications auxquelles vous avez accordé l'accès à votre compte. Révoquez toutes celles que vous n'utilisez plus. Elles devront redemander l'autorisation la prochaine fois que vous vous connecterez.
settings-apps-empty = Aucune application n'a encore obtenu l'accès à votre compte.
settings-apps-verified-label = Vérifiée
settings-apps-access-granted-prefix = Accès accordé
settings-apps-revoke-action = Révoquer l'accès
settings-apps-back = Retour aux paramètres
settings-apps-reviewed-title = Contrôlée par votre administrateur

# Restes 2FA
settings-2fa-qr-alt = Code QR TOTP

# Expiration du compte à rebours du transfert de mot de passe (rendue en JS)
settings-handoff-expired-lead = Votre fenêtre de récupération a expiré.
settings-handoff-expired-link = Recommencer

# Sous-page des fournisseurs associés
settings-providers-heading = Fournisseurs associés
settings-providers-subtitle = Connectez-vous à votre compte à l'aide d'un fournisseur d'identité tiers.
settings-providers-empty-heading = Aucun fournisseur en amont configuré par votre administrateur.
settings-providers-empty-desc = Contactez votre administrateur pour activer Google, GitHub ou d'autres fournisseurs de connexion.
settings-providers-back = Retour aux paramètres

# Découpages de code en ligne (élément 8 : 2 éléments de code ou plus par chaîne)

# settings_profile.html - description du profil public (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Visible par les membres de votre organisation sur votre page
settings-profile-public-desc-part2 = et par les applications auxquelles vous accordez les scopes OAuth
settings-profile-public-desc-part3 = ou
settings-profile-public-desc-part4 = . Laissez un champ vide pour le masquer.

# settings_profile.html - indice des liens (code: Label|https://url)
settings-profile-links-hint-part1 = Un par ligne, au format
settings-profile-links-hint-part2 = .

# Messages flash et corps d'erreur en ligne définis dans les gestionnaires Rust.
flash-session-signed-out = Session déconnectée.
flash-session-signout-failed = Impossible de déconnecter cette session.
flash-sessions-signed-out-others =
    { $count ->
        [one] { $count } autre session déconnectée.
       *[other] { $count } autres sessions déconnectées.
    }
flash-sessions-signout-others-failed = Impossible de déconnecter les autres sessions.
flash-app-access-revoked = Accès révoqué.
flash-app-access-revoke-failed = Impossible de révoquer l'accès de cette application.
flash-offline-passphrase-saved = Phrase secrète hors ligne enregistrée. Les hôtes enrôlés la récupéreront à leur prochaine synchronisation.
flash-offline-passphrase-save-failed = Impossible d'enregistrer votre phrase secrète hors ligne. Veuillez réessayer.
flash-offline-passphrase-too-short = Votre phrase secrète hors ligne doit comporter au moins { $min_len } caractères.
flash-offline-passphrase-removed = Phrase secrète hors ligne supprimée. Les hôtes l'abandonneront à leur prochaine synchronisation.
flash-offline-passphrase-none = Vous n'avez pas de phrase secrète hors ligne définie.
flash-offline-passphrase-remove-failed = Impossible de supprimer votre phrase secrète hors ligne. Veuillez réessayer.
settings-profile-url-invalid = Le site web et l'URL de l'avatar doivent être des URL http:// ou https:// valides.
settings-profile-link-url-invalid = Chaque URL de lien doit être une URL http:// ou https:// valide.
settings-save-failed = Nous n'avons pas pu enregistrer vos modifications. Veuillez réessayer.
