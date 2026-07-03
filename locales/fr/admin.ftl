# Bannière admin (admin_shell.html)
admin-banner-label = ADMIN
admin-banner-body = Vous êtes sur une surface privilégiée. Les actions effectuées ici sont consignées dans le journal d'audit.

# En-tête de la barre latérale admin (admin_nav.html)
admin-nav-heading = Administration
admin-nav-subtitle = Outils d'opérateur

# En-têtes de section de la navigation admin
admin-nav-section-system = Système
admin-nav-section-access = Accès
admin-nav-section-linux = Linux

# Libellés des éléments de navigation admin
admin-nav-status = Statut
admin-nav-configuration = Configuration
admin-nav-audit = Audit
admin-nav-webhooks = Webhooks
admin-nav-license = Licence
admin-nav-identities = Identités
admin-nav-sessions = Sessions
admin-nav-clients = Clients OAuth2
admin-nav-dcr-tokens = Jetons DCR
admin-nav-saml = SAML SSO
admin-nav-hosts = Hôtes
admin-nav-accounts = Comptes

# Liste des identités (identities_list.html)
admin-identities-page-title = Identités
admin-identities-subtitle = Identités gérées par Kratos et leur état.
admin-identities-search-placeholder = Rechercher par ID ou e-mail
admin-identities-search-button = Rechercher
admin-identities-col-email = E-mail
admin-identities-col-state = État
admin-identities-col-created = Créée
admin-identities-empty = Aucune identité trouvée.
admin-identities-prev = Retour au début
admin-identities-next = Page suivante

# Détail de l'identité (identity_show.html)
admin-identity-status-active = active
admin-identity-recovery-code-heading = Code de récupération (affiché une seule fois)
admin-identity-recovery-link-heading = Lien de récupération
admin-identity-recovery-note = Partagez-le avec l'utilisateur via un canal de confiance. Il ne sera plus affiché.
admin-identity-section-actions = Actions
admin-identity-action-generate-recovery = Générer un code de récupération
admin-identity-action-disable = Désactiver
admin-identity-action-enable = Activer
admin-identity-action-delete = Supprimer
admin-identity-section-traits = Traits
admin-identity-section-addresses = Adresses vérifiables
admin-identity-addresses-empty = Aucune adresse vérifiable pour cette identité.
admin-identity-status-verified = vérifiée
admin-identity-status-pending = en attente
admin-identity-section-credentials = Identifiants
admin-identity-credentials-empty = Aucun identifiant configuré.
admin-identity-section-sessions = Sessions récentes
admin-identity-sessions-empty = Aucun historique de session.
admin-identity-action-revoke-session = Révoquer la session

# Sélecteur d'identité (identity_picker.html)
admin-identity-picker-page-title = Sélectionner un utilisateur
admin-identity-picker-subtitle = Choisissez une identité pour continuer.
admin-identity-picker-invalid-return = Cible de retour invalide.
admin-identity-picker-search-placeholder = Rechercher par ID ou e-mail
admin-identity-picker-search-button = Rechercher
admin-identity-picker-col-email = E-mail
admin-identity-picker-col-state = État
admin-identity-picker-col-created = Créée
admin-identity-picker-empty = Aucune identité trouvée.
admin-identity-picker-action-select = Sélectionner
admin-identity-picker-prev = Retour au début
admin-identity-picker-next = Page suivante

# Liste des sessions (sessions_list.html)
admin-sessions-page-title = Sessions
admin-sessions-subtitle = Toutes les sessions connues de Kratos, pour toutes les identités.
admin-sessions-filter-active-only = Sessions actives uniquement
admin-sessions-col-identity = Identité
admin-sessions-col-authenticated = Authentifiée
admin-sessions-col-expires = Expire
admin-sessions-col-device = Appareil
admin-sessions-empty = Aucune session à afficher.
admin-sessions-action-revoke = Révoquer
admin-sessions-prev = Retour au début
admin-sessions-next = Page suivante

# Boîte de dialogue de confirmation générique (confirm.html)
admin-confirm-cancel = Annuler

# Page d'accès interdit (forbidden.html)
admin-forbidden-back = Retour au tableau de bord

# Page d'erreur admin (error.html)
admin-error-back = Retour au statut admin

# Liste des clients (clients_list.html)
admin-clients-page-title = Clients OAuth2
admin-clients-subtitle = Relying parties enregistrées via Hydra.
admin-clients-action-new = Nouveau client
admin-clients-search-placeholder = Rechercher par nom de client ou ID
admin-clients-filter-all-types = Tous les types
admin-clients-filter-all-verifications = Toutes les vérifications
admin-clients-filter-verified = Vérifiés
admin-clients-filter-unverified = Non vérifiés
admin-clients-search-button = Rechercher
admin-clients-col-name = Nom
admin-clients-col-type = Type
admin-clients-col-grants = Grants
admin-clients-col-created = Créé
admin-clients-badge-unverified-title = Non contrôlé par un administrateur
admin-clients-badge-self-registered = Auto-enregistré
admin-clients-badge-self-registered-title = Enregistré via /oauth2/register (RFC 7591)
admin-clients-empty = Aucun client enregistré.
admin-clients-prev = Retour au début
admin-clients-next = Page suivante

# Badges partagés des clients (clients_list.html, client_show.html)
admin-client-badge-verified = Vérifié
admin-client-badge-unverified = Non vérifié
admin-client-badge-unverified-title = Un administrateur n'a pas contrôlé ce client. L'écran de consentement en avertit les utilisateurs.

# Titres de page du formulaire client (client_form.html)
admin-client-form-title-new = Nouveau client
admin-client-form-title-edit = Modifier le client
admin-client-form-heading-new = Nouveau client OAuth2
admin-client-form-heading-edit = Modifier le client
admin-client-form-preset-note = Les valeurs par défaut sont préremplies pour ce type.
admin-client-form-preset-change = Changer de type

# Champs de formulaire partagés (client_form.html, client_show.html formulaire de modification)
admin-client-field-name = Nom du client
admin-client-field-grant-types = Types de grant
admin-client-grant-auth-code-hint = (connexion pilotée par l'utilisateur)
admin-client-grant-refresh-hint = (sessions de longue durée)
admin-client-grant-client-creds-hint = (service à service)
admin-client-field-response-types = Types de réponse
admin-client-field-scope = Scope
admin-client-field-scope-hint = Scopes OAuth2 séparés par des espaces.
admin-client-field-redirect-uris = URI de redirection
admin-client-field-redirect-uris-hint = Une par ligne (ou séparées par des virgules).
admin-client-field-post-logout-uris = URI de redirection post-déconnexion
admin-client-section-logout-fanout = Diffusion de déconnexion OIDC
admin-client-section-logout-fanout-desc = Lorsque l'utilisateur met fin à sa session via Forseti, Hydra notifie les clients à ces URI afin que chaque application puisse effacer sa session locale. Laissez vide pour exclure ce client de la diffusion.
admin-client-field-backchannel-uri = URI de déconnexion Back-Channel
admin-client-field-backchannel-uri-hint = Hydra envoie ici un jeton de déconnexion signé par POST (serveur à serveur). Généralement pertinent uniquement pour les applications web rendues côté serveur et les BFF.
admin-client-field-backchannel-sid-prefix = Exiger la revendication
admin-client-field-backchannel-sid-suffix = dans le jeton de déconnexion Back-Channel
admin-client-field-backchannel-sid-short = revendication requise
admin-client-field-frontchannel-uri = URI de déconnexion Front-Channel
admin-client-field-frontchannel-uri-hint = Hydra charge cette URL dans une iframe lors de la déconnexion afin que chaque application puisse effacer ses cookies de session dans le navigateur.
admin-client-field-frontchannel-sid-prefix = Exiger
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = comme paramètres de requête lors de la déconnexion Front-Channel
admin-client-field-frontchannel-sid-short = paramètres de requête requis
admin-client-field-token-auth = Méthode d'authentification du point de terminaison de jeton
admin-client-token-auth-post-hint = (secret dans le corps POST)
admin-client-token-auth-basic-hint = (secret dans l'en-tête Authorization)
admin-client-token-auth-none-hint = (client public, PKCE)
admin-client-token-auth-none-short = none (public + PKCE)
admin-client-field-audience = Liste d'autorisation d'audience
admin-client-field-audience-hint-short = Une par ligne. Hydra exige que les valeurs d'audience soient préenregistrées ici.
admin-client-field-require-pkce = Exiger PKCE (informatif)
admin-client-field-skip-consent = Client de confiance (ignorer l'écran de consentement)
admin-client-field-webhook-url = URL de webhook de suppression de compte
admin-client-action-cancel = Annuler

# Page de détail du client (client_show.html)
admin-client-action-revoke-verification = Révoquer la vérification
admin-client-action-mark-verified = Marquer comme vérifié
admin-client-action-rotate-secret = Renouveler le secret
admin-client-action-delete = Supprimer
admin-client-credentials-heading = Identifiants : affichés une seule fois
admin-client-credentials-note = Copiez-les maintenant. Ils ne seront plus affichés ; rechargez pour fermer. L'ID client et les points de terminaison ci-dessus ne sont pas secrets et restent visibles.
admin-client-credentials-secret-label = Secret client
admin-client-credentials-rat-label = Jeton d'accès d'enregistrement
admin-client-credentials-rat-note = Conformément à la RFC 7592 : permet au client de gérer son propre enregistrement (lecture/mise à jour/suppression) via l'API d'enregistrement dynamique de clients de Hydra. Il ne peut pas être réémis, donc en cas de doute, conservez-le.
admin-client-undoc-scopes-heading = Scopes non documentés
admin-client-section-connection = Détails de connexion
admin-client-connection-intro = Collez ces valeurs dans la configuration du client OIDC/OAuth côté application.
admin-client-conn-client-id = ID client
admin-client-conn-issuer = Émetteur
admin-client-conn-discovery-url = URL de découverte
admin-client-conn-auth-endpoint = Point de terminaison d'autorisation
admin-client-conn-token-endpoint = Point de terminaison de jeton
admin-client-conn-userinfo-endpoint = Point de terminaison userinfo
admin-client-conn-jwks-uri = URI JWKS
admin-client-conn-end-session-endpoint = Point de terminaison de fin de session
admin-client-section-config = Configuration
admin-client-config-sid-required = (sid requis)
admin-client-config-iss-sid-required = (iss+sid requis)
admin-client-not-configured = non configuré
admin-client-audience-none = aucune
admin-client-config-token-auth = Auth du point de terminaison de jeton
admin-client-config-require-pkce = Exiger PKCE
admin-client-bool-yes = oui
admin-client-bool-no = non
admin-client-config-trusted = De confiance (ignorer le consentement)
admin-client-config-created = Créé
admin-client-config-provenance-audience = Audience
admin-client-config-provenance-audience-note = (déclarée par l'appelant DCR)
admin-client-config-provenance-url = Utilisé à
admin-client-config-provenance-url-note = (observé pour la première fois lors du consentement)
admin-client-config-webhook = Webhook de suppression de compte
admin-client-section-edit = Modifier
admin-client-action-save = Enregistrer les modifications
admin-client-action-back = Retour à la liste

# Sélecteur de type de client (client_type_picker.html)
admin-client-type-page-title = Nouveau client
admin-client-type-heading = Nouveau client OAuth2
admin-client-type-subtitle = Choisissez le type d'application. La page suivante est le même formulaire, avec les bonnes valeurs par défaut déjà remplies, pour que vous ne tombiez pas accidentellement sur une combinaison invalide.
admin-client-type-popular-heading = Applications connues
admin-client-type-action-cancel = Annuler

# Liste des jetons DCR (dcr_tokens_list.html)
admin-dcr-page-title = Jetons d'accès initiaux DCR
admin-dcr-action-issue = Émettre un jeton
admin-dcr-token-revealed-heading = Jeton d'accès initial (affiché une seule fois)
admin-dcr-col-status = Statut
admin-dcr-col-note = Note
admin-dcr-col-created-by = Créé par
admin-dcr-col-created = Créé
admin-dcr-col-expires = Expire
admin-dcr-col-uses-left = Utilisations restantes
admin-dcr-status-active = Actif
admin-dcr-status-revoked = Révoqué
admin-dcr-status-expired = Expiré
admin-dcr-status-exhausted = Épuisé
admin-dcr-empty-prefix = Aucun jeton émis.
admin-dcr-empty-link = En émettre un
admin-dcr-empty-suffix = pour activer l'auto-enregistrement.
admin-dcr-action-revoke = Révoquer

# Nouveau jeton DCR (dcr_token_new.html)
admin-dcr-new-page-title = Émettre un jeton DCR
admin-dcr-new-heading = Émettre un jeton d'accès initial DCR
admin-dcr-new-field-note = Note
admin-dcr-new-field-note-placeholder = À quoi sert ce jeton ? (p. ex. 'Claude Desktop pour formshive')
admin-dcr-new-field-note-hint = Facultatif, pour vos archives uniquement. L'auteur du client ne le voit jamais.
admin-dcr-new-field-ttl = TTL (heures)
admin-dcr-new-field-ttl-hint = Laisser vide pour aucune expiration.
admin-dcr-new-field-max-uses = Utilisations maximales
admin-dcr-new-action-cancel = Annuler

# Page de statut (status.html)
admin-status-page-title = Statut
admin-status-heading = État du système
admin-status-subtitle = État en temps réel des composants de l'IdP, de la file d'attente du courrier et des versions de build.
admin-status-issuer-label = Émetteur
admin-status-issuer-config-link = Voir la configuration →
admin-status-warning-db-label = Base de données
admin-status-warning-db-body = SQLite avec un déploiement d'allure production. Les configurations multi-instances corrompent la base de données. Passez à Postgres pour la haute disponibilité.
admin-status-warning-webhook-label = Diffusion de webhooks
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } ligne de webhook de suppression de compte en échec définitif
       *[other] { $count } lignes de webhook de suppression de compte en échec définitif
    }
admin-status-dead-webhook-middle = (les destinataires ne sont pas notifiés).
admin-status-dead-webhook-open = Ouvrir /admin/webhooks
admin-status-dead-webhook-action = pour les remettre en file d'attente ou les supprimer.
admin-status-section-services = Services
admin-status-col-service = Service
admin-status-col-state = État
admin-status-col-detail = Détail
admin-status-state-up = actif
admin-status-state-down = inactif
admin-status-section-courier = File d'attente du courrier
admin-status-courier-pending = En attente (mise en file)
admin-status-courier-failed = Échouées (abandonnées)
admin-status-courier-last-webhook = Dernier webhook d'audit
admin-status-courier-never = jamais
admin-status-section-audit = Audit
admin-status-audit-write-failures = Échecs d'écriture d'audit (depuis le démarrage)
admin-status-audit-write-failures-note-prefix = Les lignes peuvent être récupérées à partir des lignes structurées
admin-status-audit-write-failures-note-suffix = stderr émises par Forseti au moment de l'échec.
admin-status-audit-webhook-rejected = Webhooks d'audit rejetés (depuis le démarrage)
admin-status-audit-webhook-rejected-note-prefix = Charges utiles malformées ou actions inconnues, probablement une incohérence entre un hook Kratos et la configuration. Vérifiez les
admin-status-audit-webhook-rejected-note-suffix = journaux warn.
admin-status-audit-freshness = Anomalies de fraîcheur des webhooks d'audit (depuis le démarrage)
admin-status-audit-freshness-note = Charges utiles horodatées comme périmées ou dans le futur, généralement dues à un processus lent ou à un décalage d'horloge. Les lignes sont tout de même enregistrées et signalées.
admin-status-section-license = Licence
admin-status-license-oss-prefix = Déploiement de niveau OSS.
admin-status-license-oss-link = Activer une licence
admin-status-license-oss-suffix = pour débloquer les fonctionnalités premium.
admin-status-section-build = Versions de build
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = Base de données

# Page de configuration (configuration.html)
admin-config-page-title = Configuration
admin-config-subtitle = Comment ce fournisseur d'identité est configuré : points de terminaison et capacités OIDC, clés de signature et schémas d'identité Kratos.
admin-config-discovery-warning-label = Découverte OIDC
admin-config-discovery-warning-body = Impossible d'atteindre le document de découverte de Hydra. Les points de terminaison et les capacités sont masqués jusqu'à ce qu'il soit de nouveau accessible.
admin-config-section-oidc = Points de terminaison OIDC
admin-config-field-issuer = Émetteur
admin-config-field-discovery-url = URL de découverte
admin-config-field-authorization = Autorisation
admin-config-field-token = Jeton
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = Fin de session
admin-config-field-registration = Enregistrement (DCR)
admin-config-field-revocation = Révocation
admin-config-section-capabilities = Capacités
admin-config-cap-scopes = Scopes
admin-config-cap-grant-types = Types de grant
admin-config-cap-response-types = Types de réponse
admin-config-cap-token-auth-methods = Méthodes d'authentification du point de terminaison de jeton
admin-config-cap-pkce-methods = Méthodes PKCE
admin-config-cap-id-token-signing-algs = Algorithmes de signature du jeton d'ID
admin-config-cap-subject-types = Types de sujet
admin-config-cap-backchannel-logout = Déconnexion Back-Channel
admin-config-cap-frontchannel-logout = Déconnexion Front-Channel
admin-config-cap-yes = Oui
admin-config-cap-no = Non
admin-config-section-signing-keys = Clés de signature (JWKS)
admin-config-signing-keys-unavailable = Indisponible : impossible de récupérer les clés publiques de Hydra.
admin-config-signing-keys-empty = Hydra n'a annoncé aucune clé de signature.
admin-config-col-key-id = ID de clé
admin-config-col-alg = Alg
admin-config-col-type = Type
admin-config-col-use = Utilisation
admin-config-section-schemas = Schémas d'identité Kratos
admin-config-schemas-unavailable = Indisponible : impossible de récupérer les schémas d'identité depuis Kratos.
admin-config-schemas-empty = Aucun schéma d'identité enregistré.

# Liste d'audit (audit.html)
admin-audit-page-title = Audit
admin-audit-subtitle = Journal d'événements en ajout seul. Enregistre les actions admin côté Forseti, les grants OAuth, les changements de session et les processus Kratos terminés, transmis via webhook. La rétention est configurée par l'opérateur (`[audit].audit_retention_days`) ; la purge est une sous-commande CLI, pas automatique.
admin-audit-filter-email = L'e-mail contient
admin-audit-filter-action = Préfixe d'action
admin-audit-filter-severity = Gravité
admin-audit-filter-since = Depuis
admin-audit-severity-any = Toutes
admin-audit-severity-info = Info
admin-audit-severity-warning = Avertissement
admin-audit-severity-error = Erreur
admin-audit-severity-critical = Critique
admin-audit-filter-button = Filtrer
admin-audit-col-target = Cible
admin-audit-col-severity = Gravité
admin-audit-col-when = Quand
admin-audit-col-actor = Acteur
admin-audit-col-action = Action
admin-audit-col-actions = Actions
admin-audit-empty = Aucun événement ne correspond aux filtres actuels.
admin-audit-badge-critical = critique
admin-audit-badge-error = erreur
admin-audit-badge-warning = avertissement
admin-audit-action-view = Voir
admin-audit-prev = ‹ Précédent
admin-audit-next = Suivant ›

# Détail d'audit (audit_show.html)
admin-audit-back = ← Retour à l'audit
admin-audit-show-section-event = Événement
admin-audit-show-outcome = Résultat
admin-audit-show-success = succès
admin-audit-show-failure = échec
admin-audit-show-section-actor = Acteur
admin-audit-show-field-kind = Type
admin-audit-show-field-email = E-mail
admin-audit-show-none = aucun
admin-audit-show-field-identity-id = ID d'identité
admin-audit-show-section-target = Cible
admin-audit-show-field-label = Libellé
admin-audit-show-deleted = (supprimé)
admin-audit-show-field-target-id = ID de cible
admin-audit-show-section-metadata = Métadonnées
admin-audit-show-section-request-context = Contexte de la requête
admin-audit-show-field-ip-hash = Hachage IP
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = ID de requête
admin-audit-show-field-org-id = ID d'organisation

# Liste des webhooks (webhooks.html)
admin-webhooks-page-title = Webhooks
admin-webhooks-heading = Webhooks en échec définitif
admin-webhooks-subtitle = Notifications de suppression de compte ayant épuisé leurs tentatives (12 tentatives ou 72 heures, selon la première échéance atteinte). Cliquez sur une ligne pour voir la charge utile complète et la dernière erreur, ou remettez-la en file d'attente depuis le récapitulatif si vous savez que le destinataire est de nouveau opérationnel.
admin-webhooks-empty = Aucune ligne en échec définitif. Tout est bien transmis.
admin-webhooks-col-client = Client
admin-webhooks-col-event = Événement
admin-webhooks-col-attempts = Tentatives
admin-webhooks-col-age = Âge
admin-webhooks-col-actions = Actions
admin-webhooks-deleted = (supprimé)
admin-webhooks-action-view = Voir
admin-webhooks-action-requeue = Remettre en file

# Détail du webhook (webhook_show.html)
admin-webhook-back = ← Retour aux webhooks
admin-webhook-heading = Webhook en échec définitif
admin-webhook-action-requeue = Remettre en file
admin-webhook-action-discard = Supprimer
admin-webhook-section-delivery = Livraison
admin-webhook-field-client = Client
admin-webhook-deleted = (supprimé)
admin-webhook-field-state = État
admin-webhook-field-url = URL
admin-webhook-field-attempts = Tentatives
admin-webhook-field-created = Créé
admin-webhook-field-next-attempt = Prochaine tentative
admin-webhook-section-last-error = Dernière erreur
admin-webhook-section-payload = Charge utile signée

# Liste des comptes POSIX (posix_list.html)
admin-posix-page-title = Comptes POSIX
admin-posix-subtitle = Identités Kratos matérialisées en comptes Linux (uid/gid + clés SSH) pour le résolveur NSS.
admin-posix-seats-label = Sièges utilisés :
admin-posix-license-note = Une licence commerciale d'authentification Linux relève la limite.
admin-posix-action-provision = Provisionner un compte
admin-posix-col-username = Nom d'utilisateur
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Statut
admin-posix-col-created = Créé
admin-posix-empty-prefix = Aucun compte POSIX activé.
admin-posix-empty-link = En provisionner un
admin-posix-empty-suffix = à partir d'une identité Kratos.
admin-posix-status-enabled = activé
admin-posix-status-disabled = désactivé
admin-posix-action-manage = Gérer

# Détail du compte POSIX (posix_account.html)
admin-posix-action-disable = Désactiver
admin-posix-action-enable = Activer
admin-posix-action-delete = Supprimer
admin-posix-ssh-keys-heading = Clés SSH
admin-posix-ssh-empty = Aucune clé SSH pour le moment.
admin-posix-ssh-key-added-prefix = ajoutée
admin-posix-ssh-action-remove = Supprimer
admin-posix-ssh-field-public-key = Clé publique
admin-posix-ssh-field-comment = Commentaire (facultatif)
admin-posix-ssh-action-add = Ajouter la clé
admin-posix-teams-heading = Équipes
admin-posix-hosts-heading = Hôtes accessibles
admin-posix-back = ← Tous les comptes POSIX

# Nouveau compte POSIX (posix_new.html)
admin-posix-new-page-title = Provisionner un compte POSIX
admin-posix-new-heading = Provisionner un compte POSIX
admin-posix-new-choose-identity = Choisissez l'identité à provisionner.
admin-posix-new-action-select-user = Sélectionner un utilisateur
admin-posix-new-or-enter-directly = Ou saisir directement
admin-posix-new-placeholder-id = UUID ou e-mail
admin-posix-new-action-continue = Continuer
admin-posix-new-provision-intro = Matérialisez une identité Kratos en compte Linux. Un uid/gid est attribué automatiquement et un groupe principal est créé.
admin-posix-new-selected-prefix = Sélectionnée :
admin-posix-new-action-change = Changer
admin-posix-new-field-username = Nom d'utilisateur
admin-posix-new-username-hint = Suggéré à partir de l'e-mail ; modifiez-le si vous le souhaitez. 1 à 32 caractères, en minuscules, commençant par une lettre ou un tiret bas. Il devient le nom de connexion POSIX.
admin-posix-new-field-shell = Shell de connexion
admin-posix-new-action-cancel = Annuler

# Liste des hôtes (hosts_list.html)
admin-hosts-page-title = Hôtes
admin-hosts-subtitle = Machines Linux enrôlées auprès du résolveur POSIX/NSS de Forseti. Chaque hôte s'authentifie avec un secret à usage unique révélé lors de l'enrôlement.
admin-hosts-action-enroll = Enrôler un hôte
admin-hosts-credential-heading = Identifiant d'hôte (affiché une seule fois)
admin-hosts-credential-note-prefix = Le format est
admin-hosts-credential-note-suffix = . Configurez maintenant l'agent hôte avec cet identifiant. Nous ne stockons pas le secret brut, seulement son SHA-256.
admin-hosts-col-hostname = Nom d'hôte
admin-hosts-col-teams = Équipes
admin-hosts-col-force-mfa = Forcer la MFA
admin-hosts-col-enrolled = Enrôlé
admin-hosts-col-last-seen = Vu pour la dernière fois
admin-hosts-empty-prefix = Aucun hôte enrôlé.
admin-hosts-empty-link = En enrôler un
admin-hosts-empty-suffix = pour lui permettre de résoudre les comptes POSIX.
admin-hosts-status-mfa-pending = MFA (en attente)
admin-hosts-mfa-pending-title = Enregistrée mais pas encore appliquée ; l'application arrive avec la connexion interactive (PAM).
admin-hosts-action-edit = Modifier
admin-hosts-action-rotate = Renouveler
admin-hosts-action-revoke = Révoquer

# Modifier l'hôte (hosts_edit.html)
admin-hosts-edit-page-title = Modifier l'hôte
admin-hosts-edit-intro = Mettez à jour le libellé de l'hôte, son indicateur MFA et les équipes auxquelles il est rattaché. Le secret n'est pas affiché ici ; renouvelez-le depuis la liste des hôtes s'il vous en faut un nouveau.
admin-hosts-field-hostname = Nom d'hôte
admin-hosts-hostname-hint = Un libellé pour vos archives. Il n'a pas besoin de correspondre au nom d'hôte réel de la machine.
admin-hosts-field-org = Organisation
admin-hosts-org-fixed-note = L'organisation d'un hôte est fixée lors de l'enrôlement et ne peut pas être modifiée ici.
admin-hosts-field-allowed-teams = Équipes autorisées
admin-hosts-teams-empty = Aucune équipe n'existe encore. Cet hôte autorise tout membre de l'organisation. Restreindre un hôte à des équipes spécifiques nécessite la fonctionnalité Organisations.
admin-hosts-teams-hint = Restreignez cet hôte aux membres des équipes sélectionnées. N'en sélectionnez aucune pour autoriser tout membre de l'organisation.
admin-hosts-field-force-mfa = Forcer la MFA sur cet hôte
admin-hosts-force-mfa-hint = Enregistré maintenant ; appliqué dès que la connexion interactive (PAM) sera disponible.
admin-hosts-action-cancel = Annuler

# Nouvel hôte (hosts_new.html)
admin-hosts-new-heading = Enrôler un hôte Linux
admin-hosts-new-intro-prefix = Un secret à usage unique est révélé une seule fois sur la page suivante. Configurez l'agent hôte avec l'identifiant
admin-hosts-new-intro-suffix = qu'il affiche.
admin-hosts-org-belongs-hint = L'hôte appartient à cette organisation. Fixée après l'enrôlement.
admin-hosts-new-teams-empty = Aucune équipe n'existe encore. Cet hôte autorisera tout membre de l'organisation. Restreindre un hôte à des équipes spécifiques nécessite la fonctionnalité Organisations.
admin-hosts-new-teams-scope-hint = Restreignez cet hôte aux membres des équipes sélectionnées. Seules les équipes de l'organisation choisie s'appliquent ; n'en sélectionnez aucune pour autoriser tout membre de l'organisation.

# Liste SAML SSO (saml_list.html)
admin-saml-page-title = SAML SSO
admin-saml-subtitle = Connexions SAML d'entreprise, une par organisation. Les métadonnées et certificats de l'IdP résident dans Jackson ; Forseti conserve la ligne d'ancrage et l'interrupteur d'activation.
admin-saml-action-new = Nouvelle connexion
admin-saml-grace-notice = Licence en période de grâce. Les connexions SAML sont en lecture seule jusqu'au renouvellement de la licence. Les connexions SSO continuent de fonctionner.
admin-saml-col-org = Organisation
admin-saml-col-connection = Connexion
admin-saml-col-sso-url = URL SSO
admin-saml-col-enabled = Activée
admin-saml-empty-prefix = Aucune connexion SAML pour le moment.
admin-saml-empty-link = En créer une
admin-saml-empty-suffix = pour activer le SSO d'une organisation.
admin-saml-status-enabled = Activée
admin-saml-status-disabled = Désactivée
admin-saml-action-disable = Désactiver
admin-saml-action-enable = Activer
admin-saml-action-delete = Supprimer
admin-saml-idp-values-heading = Valeurs pour l'administrateur IdP du client
admin-saml-idp-values-intro = Transmettez-les à la personne qui configure l'application SAML côté fournisseur d'identité. Elles sont identiques pour chaque connexion.
admin-saml-idp-acs-url = URL ACS
admin-saml-idp-entity-id = ID d'entité SP

# Pagination de l'audit
admin-audit-range = Affichage de { $from } à { $to } sur { $total } lignes.
admin-audit-page = Page { $page }
admin-saml-entity-id-note-prefix = L'ID d'entité suit le paramètre
admin-saml-entity-id-note-suffix = de Jackson ; modifiez-le là-bas si vous remplacez la valeur par défaut.

# Nouvelle connexion SAML (saml_new.html)
admin-saml-new-page-title = Nouvelle connexion SAML
admin-saml-new-intro = Connectez une organisation à son fournisseur d'identité. Collez le XML de métadonnées de l'IdP, ou indiquez une URL de métadonnées que Jackson récupère lui-même : exactement l'une des deux options.
admin-saml-new-field-org = Organisation
admin-saml-new-org-hint = Une connexion par organisation.
admin-saml-new-field-name = Nom de la connexion
admin-saml-new-name-hint = Pour vos archives uniquement ; les membres ne le voient jamais.
admin-saml-new-field-metadata-url = URL de métadonnées
admin-saml-new-metadata-url-hint = Laissez vide si vous collez le XML brut ci-dessous.
admin-saml-new-metadata-url-https-note = Jackson ne récupère que les URL de métadonnées HTTPS (ou localhost). Pour des métadonnées d'IdP en HTTP simple, collez plutôt le XML ci-dessous.
admin-saml-new-field-metadata-xml = XML de métadonnées
admin-saml-new-metadata-xml-hint = Laissez vide si vous utilisez une URL de métadonnées ci-dessus.
admin-saml-new-action-create = Créer la connexion
admin-saml-new-action-cancel = Annuler

# Découpages de code en ligne (élément 8 : 2 éléments de code ou plus par chaîne)

# client_form.html - indice des types de réponse (code: code, token)
admin-client-field-response-types-hint-part1 = Séparés par des virgules, p. ex.
admin-client-field-response-types-hint-part2 = (code d'autorisation) ou
admin-client-field-response-types-hint-part3 = (client credentials).

# client_form.html - indice d'audience (code: audience=<value>)
admin-client-field-audience-hint-part1 = Une par ligne. Hydra exige que les valeurs d'audience soient préenregistrées ici (RFC 8707 n'est pas encore pris en charge). Les clients transmettent
admin-client-field-audience-hint-part2 = dans la requête d'autorisation.

# client_form.html - indice PKCE (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = L'application globale se configure dans
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). Cet indicateur reflète l'intention de l'opérateur.

# client_form.html + client_show.html - indice de webhook (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = Lorsqu'un utilisateur supprime lui-même son compte, Forseti envoie un Security Event Token RFC 8417 (RISC
admin-client-field-webhook-hint-part2 = ) ici par POST. Laissez vide pour désactiver. Les destinataires vérifient la signature JWS avec le JWKS de Forseti à l'adresse
admin-client-field-webhook-hint-part3 = .

# client_show.html - description des scopes non documentés (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = Ces scopes sont enregistrés sur ce client mais n'ont aucune entrée sous
admin-client-undoc-scopes-desc-part2 = dans
admin-client-undoc-scopes-desc-part3 = . L'écran de consentement affiche alors leur nom de scope brut.

# client_show.html - erreur de découverte (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = Le point de terminaison de découverte de Hydra est injoignable, l'émetteur et les points de terminaison sont donc masqués pour éviter d'afficher une valeur erronée. Récupérez-les vous-même depuis
admin-client-discovery-error-part2 = .

# client_show.html - introduction de la section de modification (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Mettez à jour les champs du client ci-dessous. Les modifications sont appliquées via le
admin-client-edit-intro-part2 = de Hydra ; les champs non concernés sont préservés.

# dcr_tokens_list.html - sous-titre (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Jetons Bearer qui autorisent
admin-dcr-subtitle-part2 = . Remettez-en un à l'auteur d'un client MCP pour qu'il puisse s'enregistrer lui-même, sans intervention manuelle de votre part.

# dcr_tokens_list.html - description du jeton révélé (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Partagez-le avec l'auteur du client. Il l'envoie sous la forme
admin-dcr-revealed-desc-part2 = lors de l'appel à
admin-dcr-revealed-desc-part3 = . Nous ne stockons pas la valeur brute, seulement son SHA-256.

# dcr_token_new.html - sous-titre (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = Le jeton est affiché une seule fois sur la page suivante. Remettez-le à l'auteur du client. Il l'envoie sous la forme
admin-dcr-new-subtitle-part2 = sur un unique appel
admin-dcr-new-subtitle-part3 = .

# dcr_token_new.html - indice d'utilisations max (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = Laissez vide pour un usage illimité. L'usage unique (
admin-dcr-new-field-max-uses-hint-part2 = ) est l'option la plus sûre par défaut.

# client_type_picker.html - description des applications connues (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Prérempli pour une application connue. Les URL utilisent les espaces réservés
admin-client-type-popular-desc-part2 = (et parfois
admin-client-type-popular-desc-part3 = ). Remplacez-les par les valeurs de votre application après avoir ouvert le formulaire.

# posix_account.html - paragraphe des clés SSH (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = Les clés publiques ajoutées ici sont fournies au sshd de l'appareil (
admin-posix-ssh-keys-desc-part2 = ) pour que cet utilisateur puisse se connecter en
admin-posix-ssh-keys-desc-part3 = avec sa clé, sans fichier
admin-posix-ssh-keys-desc-part4 = propre à chaque hôte. Nécessite le hook sshd de l'hôte (configuré automatiquement par le service Guix
admin-posix-ssh-keys-desc-part5 = ; configuration sshd manuelle sur les autres distributions). Non utilisé pour la connexion console / PAM.

# posix_new.html - indice du shell (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Doit exister sur le(s) appareil(s) qui desservent ce compte ;
admin-posix-new-shell-hint-part2 = est l'option multi-distribution sûre par défaut (Guix n'a pas de
admin-posix-new-shell-hint-part3 = ). Le répertoire personnel est dérivé du préfixe home et du nom d'utilisateur.

# saml_list.html - bloc non configuré (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = n'est pas configuré
admin-saml-not-configured-part2 = ajoutez les paramètres du pont Jackson à
admin-saml-not-configured-part3 = pour activer SAML SSO. Voir
admin-saml-not-configured-part4 = .

# Messages flash admin (affichés en bannière après une redirection)
flash-identity-disabled = Identité désactivée.
flash-identity-enabled = Identité activée.
flash-session-revoked = Session révoquée.
flash-client-create-failed = Échec de la création du client : { $error }
flash-client-account-deletion-url-rejected = URL de suppression de compte rejetée : { $error }
flash-client-secret-stage-failed = Client créé, mais nous n'avons pas pu préparer le secret pour l'affichage unique. Renouvelez le secret pour obtenir une nouvelle valeur.
