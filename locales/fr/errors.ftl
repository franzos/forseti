# Page d'erreur
error-reference-id = ID de référence :
error-cta-back-to-sign-in = Retour à la connexion

# Confirmation de déconnexion OAuth
logout-card-title = Se déconnecter de toutes les applications ?
logout-card-subtitle = Cela mettra fin à votre session avec { $brand } et notifiera chaque application à laquelle vous vous êtes connecté.
logout-body-text = L'application qui vous a demandé de vous déconnecter sera informée que la demande est terminée. Certaines applications peuvent conserver des données en cache pendant un court moment ; se déconnecter ici met fin à la session sur { $brand }.
logout-action-sign-out = Se déconnecter
logout-action-cancel = Annuler

# Titres et corps de dialogue admin utilisés par render_admin_error aux points d'appel disposant d'une locale.
# Les points d'appel sans locale (fonctions utilitaires, limites d'erreur) conservent leurs littéraux anglais.
dialog-identity-unavailable-title = Identité indisponible
dialog-identity-unavailable-body = Nous n'avons pas pu charger cette identité. Elle a peut-être été supprimée.
dialog-recovery-code-failed-title = Échec du code de récupération
dialog-recovery-code-failed-body = Nous avons généré le code de récupération mais n'avons pas pu le préparer pour un affichage unique. Générez un nouveau code pour réessayer.
dialog-disable-failed-title = Échec de la désactivation
dialog-enable-failed-title = Échec de l'activation
dialog-delete-failed-title = Échec de la suppression
dialog-revoke-failed-title = Échec de la révocation

# Limite d'erreur (error_boundary.html), titre/corps/cta définis dans les gestionnaires Rust.
error-boundary-auth-unavailable-title = Authentification indisponible
error-boundary-auth-unavailable-body = Nous n'avons pas pu joindre le service d'authentification. Veuillez réessayer dans un instant.
error-boundary-cta-try-again = Réessayer
error-boundary-cta-sign-in = Se connecter
error-boundary-cta-back-to-settings = Retour aux paramètres
error-boundary-cta-back-to-dashboard = Retour au tableau de bord
error-boundary-cta-back-to-account = Retour au compte
error-boundary-signin-title = Connexion indisponible
error-boundary-signup-title = Inscription indisponible
error-boundary-recovery-title = Récupération indisponible
error-boundary-verification-title = Vérification indisponible
error-boundary-settings-title = Paramètres indisponibles
error-boundary-logout-title = Déconnexion indisponible
error-boundary-logout-body = Nous n'avons pas pu finaliser votre déconnexion car le service d'authentification est injoignable. Votre session est toujours active, veuillez réessayer dans un instant.
error-boundary-sessions-title = Sessions indisponibles
error-boundary-sessions-body = Nous n'avons pas pu lister vos sessions actives. Veuillez réessayer dans un instant.
error-boundary-authorized-apps-title = Applications autorisées indisponibles
error-boundary-authorized-apps-no-session-body = Nous n'avons pas pu lire votre session. Veuillez vous reconnecter.
error-boundary-authorized-apps-service-body = Nous n'avons pas pu joindre le service OAuth. Veuillez réessayer dans un instant.
error-boundary-account-deletion-title = Échec de la suppression du compte
error-boundary-account-delete-bad-session = Votre session est dans un état inattendu. Veuillez vous reconnecter et réessayer.
error-boundary-account-delete-sole-owner = Vous êtes le seul propriétaire de { $names }. Transférez la propriété à un autre membre avant de supprimer votre compte.
error-boundary-account-delete-ownership-check-failed = Nous n'avons pas pu vérifier la propriété de votre organisation. Rien n'a été modifié ; veuillez réessayer dans un instant.
error-boundary-account-delete-consent-unreachable = Nous n'avons pas pu joindre le service de consentement pour notifier vos applications connectées. Rien n'a été modifié ; veuillez réessayer dans un instant.
error-boundary-account-delete-notifications-failed = Nous n'avons pas pu préparer les notifications de suppression. Rien n'a été modifié ; veuillez réessayer.
error-boundary-account-delete-failed = Nous n'avons pas pu supprimer votre compte. Veuillez réessayer dans un instant.

# Limite d'erreur SAML (rendue avec la locale par défaut ; le callback ACS ne porte aucune locale de requête).
error-boundary-sso-unavailable-title = Authentification unique indisponible
error-boundary-sso-unavailable-body = L'authentification unique n'est pas disponible pour cette adresse. Vérifiez le lien fourni par votre administrateur, ou connectez-vous avec votre méthode habituelle.
error-boundary-sso-failed-title = Échec de l'authentification unique
error-boundary-sso-validation-failed-body = Cette tentative d'authentification n'a pas pu être validée. Recommencez à partir du lien SSO de votre organisation.
error-boundary-sso-upstream-failed-body = Le service d'authentification est temporairement indisponible. Veuillez réessayer.
error-boundary-sso-no-email-body = Le fournisseur d'identité n'a pas fourni d'adresse e-mail. Demandez à votre administrateur de mapper l'attribut e-mail sur la connexion SAML.

# Page d'erreur en libre-service de Kratos (error.html), valeurs de repli définies dans Rust.
error-page-generic-title = Une erreur s'est produite
error-page-generic-body = Nous n'avons pas pu charger la page demandée. Le lien a peut-être expiré ou a déjà été utilisé.
error-page-link-expired-title = Lien expiré
error-page-link-expired-body = Ce lien n'est plus valide. Veuillez recommencer à partir de la connexion.
error-page-security-title = Échec du contrôle de sécurité
error-page-already-signed-in-title = Déjà connecté
error-page-default-message = Nous n'avons pas pu finaliser cette demande.

# Page d'accès interdit du contrôle admin (admin/forbidden.html), définie dans Rust.
error-admin-access-denied-title = Accès refusé
error-admin-access-denied-body = Votre compte n'est pas autorisé à utiliser les outils d'administration.
error-admin-access-denied-forseti-body = Votre compte n'est pas autorisé à utiliser les outils d'administration à l'échelle de Forseti.
error-admin-access-denied-org-body = Vous n'avez pas d'accès administrateur à cette organisation.

# SAML bloqué
error-saml-blocked-page-title = Authentification bloquée
error-saml-blocked-card-title = Nous n'avons pas pu vous connecter
error-saml-unverified-prefix = Un compte pour
error-saml-unverified-suffix = existe déjà mais son adresse e-mail n'a pas été vérifiée, l'authentification unique ne peut donc pas s'y rattacher en toute sécurité. Vérifiez l'adresse à partir de votre e-mail d'inscription initial, ou demandez de l'aide à votre administrateur.
error-saml-cross-org-not-member = Votre compte n'est pas encore membre de cette organisation. Demandez à votre administrateur de vous ajouter, puis réessayez.
error-saml-conflict = Nous n'avons pas pu vous connecter. Veuillez contacter votre administrateur.
error-saml-blocked-cta = Aller à la connexion
