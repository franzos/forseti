# Libellés de champs partagés utilisés sur les pages d'organisation
orgs-field-name = Nom
orgs-field-slug = Slug
orgs-field-email = E-mail
orgs-field-role = Rôle

# Sélecteur d'organisation (menu déroulant de la barre de navigation)
orgs-switcher-label = Changer d'organisation
orgs-switcher-manage-link = Gérer les organisations

# Liste des organisations (list.html)
orgs-list-title = Organisations
orgs-list-heading = Vos organisations
orgs-list-create-heading = Créer une nouvelle organisation
orgs-list-field-slug-optional = Slug (facultatif)
orgs-list-action-create = Créer
orgs-list-field-access-mode = Mode d'accès
orgs-list-mode-internal-title = Interne
orgs-list-mode-internal-body = Sur invitation uniquement. Les membres rejoignent par invitation (et bientôt via un domaine d'entreprise vérifié).
orgs-list-mode-external-title = Externe
orgs-list-mode-external-body = Inscription publique en libre-service. L'annuaire des membres est limité aux administrateurs.
orgs-list-tier-gate-heading = Les organisations multiples sont une fonctionnalité { $tier }
orgs-list-license-missing = Votre licence actuelle n'inclut pas la fonctionnalité Organisations.
orgs-list-unlicensed = Cette installation { $brand } fonctionne sans licence, les organisations supplémentaires au-delà de celle par défaut sont donc bloquées.
orgs-list-license-upgrade = Activez ou faites évoluer une licence pour en créer davantage.
orgs-list-link-get-license = Obtenir une licence
orgs-list-link-activate-license = Activer une licence existante

# Vue d'ensemble de l'organisation - vue propriétaire (overview.html)
orgs-overview-subtitle-default = Il s'agit de l'organisation par défaut de cette installation { $brand }. Toute personne qui s'inscrit la rejoint automatiquement.
orgs-overview-subtitle = Gérez les paramètres, l'image de marque et les membres de cette organisation.
orgs-overview-identity-heading = Identité
orgs-overview-quicklinks-heading = Liens rapides
orgs-link-branding = Image de marque
orgs-link-members = Membres
orgs-link-teams = Équipes
orgs-link-domains = Domaines
orgs-sso-heading = SSO d'entreprise
orgs-sso-status-enabled = activé
orgs-sso-status-disabled = désactivé
orgs-sso-operator-note = Les connexions SSO sont gérées par l'opérateur.
orgs-access-mode-heading = Mode d'accès
orgs-access-mode-label = Mode
orgs-access-mode-internal = Interne
orgs-access-mode-external = Externe
orgs-access-mode-note-default = L'organisation par défaut est toujours interne.
orgs-access-mode-note-internal = Les membres rejoignent par invitation. Passer en externe active l'inscription publique.
orgs-access-mode-note-external = L'inscription publique est activée. L'annuaire des membres est limité aux administrateurs tant que le mode externe est actif.
orgs-access-mode-action-switch-external = Passer en externe
orgs-access-mode-action-switch-internal = Passer en interne
orgs-confirm-switch-external = Passer en externe ? Cela active la page publique de création de compte et limite le répertoire des membres aux administrateurs.
orgs-confirm-switch-internal = Passer en interne ? Cela désactive la page publique de création de compte. Les membres existants conservent leur accès.
orgs-danger-heading = Zone dangereuse
orgs-danger-delete-body = Supprimer définitivement cette organisation. Forseti refuse si des clients OAuth2 y sont encore associés.
orgs-danger-delete-action = Supprimer l'organisation
orgs-confirm-delete-org = Supprimer { $name } ? Cette action est irréversible.

# Vue d'ensemble de l'organisation - vue non-propriétaire (overview_info.html)
orgs-info-subtitle-default = Il s'agit de l'organisation par défaut de cette installation { $brand }. Vous en êtes membre.
orgs-info-subtitle = Vous êtes membre de cette organisation.
orgs-info-org-heading = Organisation
orgs-info-members-label = Membres
orgs-info-managed-by-heading = Gérée par
orgs-info-managed-by-note = Contactez un propriétaire pour modifier le nom, l'image de marque ou les membres de l'organisation.

# Page des membres (members.html)
orgs-members-page-heading = Membres
orgs-members-subtitle = Les propriétaires peuvent promouvoir / rétrograder des membres et retirer n'importe qui sauf le dernier propriétaire.
orgs-members-visibility-note-admins-only = Seuls les administrateurs peuvent voir la liste complète des membres.
orgs-members-visibility-note-same-group = Vous voyez les membres qui partagent une équipe avec vous.
orgs-members-visibility-note-all = Tous les membres sont visibles.
orgs-members-invite-heading = Inviter par e-mail
orgs-members-role-member = Membre
orgs-members-role-owner = Propriétaire
orgs-members-action-invite = Envoyer l'invitation
orgs-members-visibility-heading = Visibilité de l'annuaire
orgs-members-visibility-label = Qui peut voir la liste des membres
orgs-members-visibility-opt-all = Tous les membres
orgs-members-visibility-opt-same-group = Même équipe uniquement
orgs-members-visibility-opt-admins-only = Administrateurs uniquement
orgs-members-visibility-hint = « Même équipe uniquement » nécessite qu'au moins une équipe existe au préalable.
orgs-members-col-joined = Membre depuis
orgs-members-badge-you = vous
orgs-members-badge-hidden = Masqué
orgs-members-action-show = Afficher
orgs-members-action-hide = Masquer
orgs-members-action-update = Mettre à jour
orgs-members-action-remove = Retirer
orgs-confirm-remove-member = Retirer { $email } ?
orgs-members-invites-heading = Invitations en attente
orgs-members-invites-col-sent = Envoyée
orgs-members-invites-col-expires = Expire

# Page des équipes (teams.html)
orgs-teams-page-heading = Équipes
orgs-teams-subtitle = Regroupez les membres en équipes. Les équipes délimitent l'accès aux hôtes et pilotent la visibilité de l'annuaire au sein d'une même équipe.
orgs-teams-create-heading = Créer une équipe
orgs-teams-action-create = Créer l'équipe
orgs-teams-col-team = Équipe
orgs-teams-col-members = Membres
orgs-teams-action-rename = Renommer
orgs-teams-action-manage-members = Gérer les membres
orgs-teams-action-delete = Supprimer
orgs-confirm-delete-team = Supprimer { $name } ? Cela supprime l'équipe et ses adhésions.
orgs-teams-selected-heading = Membres de { $team }
orgs-teams-add-member-label = Ajouter un membre
orgs-teams-action-add = Ajouter

# Page des domaines (domains.html)
orgs-domains-page-heading = Domaines autorisés
orgs-domains-subtitle = Les utilisateurs avec un e-mail vérifié sur un domaine prouvé rejoignent automatiquement cette organisation.
orgs-domains-add-heading = Ajouter un domaine
orgs-domains-field-domain = Domaine
orgs-domains-field-method = Méthode de vérification
orgs-domains-method-http_file = Fichier HTTP
orgs-domains-method-dns_txt = Enregistrement DNS TXT
orgs-domains-method-email = E-mail
orgs-domains-action-add = Ajouter le domaine
orgs-domains-col-domain = Domaine
orgs-domains-col-method = Méthode
orgs-domains-col-status = Statut
orgs-domains-status-verified = Vérifié
orgs-domains-status-pending = En attente
orgs-domains-instructions-http_file = Servez { $token } à https://{ $domain }/.well-known/forseti-domain-verify
orgs-domains-instructions-dns_txt = Créez un enregistrement TXT à _forseti-verify.{ $domain } avec la valeur : { $token }
orgs-domains-instructions-email = Un code a été envoyé à admin@{ $domain } et postmaster@{ $domain }. Collez-le ci-dessous.
orgs-domains-action-verify = Vérifier
orgs-domains-action-confirm = Confirmer le code
orgs-domains-field-token = Code de confirmation
orgs-domains-action-remove = Supprimer
orgs-confirm-remove-domain = Supprimer { $domain } ? La jonction automatique pour ce domaine cesse immédiatement.
orgs-domains-policy-heading = Politique d'adhésion
orgs-domains-policy-subtitle = Choisissez comment les utilisateurs disposant d'une adresse e-mail vérifiée sur un domaine prouvé rejoignent cette organisation.
orgs-domains-policy-field = Politique
orgs-domains-policy-invite-only = Sur invitation uniquement
orgs-domains-policy-auto-join = Les utilisateurs de domaines vérifiés peuvent s'inscrire eux-mêmes
orgs-domains-policy-save = Enregistrer la politique

# Page d'image de marque (branding.html)
orgs-branding-page-heading = Image de marque
orgs-branding-subtitle-prefix = Remplacez l'image de marque par défaut de Forseti par le logo et l'e-mail de support de cette organisation. Revient à
orgs-branding-subtitle-infix = dans
orgs-branding-subtitle-suffix = lorsqu'ils ne sont pas définis.
orgs-branding-field-logo-url = URL du logo
orgs-branding-field-logo-file = Image du logo (PNG, JPEG ou WebP ; 256 Ko max.)
orgs-branding-logo-remove = Supprimer le logo
orgs-branding-logo-save = Téléverser le logo
orgs-branding-field-support-email = E-mail de support
orgs-branding-theme-preset = Préréglage de thème
orgs-branding-primary = Couleur principale
orgs-branding-on-primary = Texte sur la couleur principale
orgs-branding-secondary = Couleur d'accentuation
orgs-branding-request-public = Activer une page de connexion publique (/o/votre-slug)
orgs-branding-preview = Aperçu

# Flash notices (post-save banners)
flash-org-updated = Organisation mise à jour.
flash-branding-saved = Image de marque enregistrée.
flash-logo-updated = Logo mis à jour.
flash-logo-removed = Logo supprimé.

# Page de destination publique (public_landing.html)
orgs-public-landing-note = Connectez-vous ci-dessous ou créez un compte pour commencer.
orgs-public-landing-register = Créer un compte
orgs-public-landing-signin = Se connecter

# Confirmation d'adhésion (join_confirm.html)
join-confirm-page-title = Rejoindre l'organisation
join-confirm-heading = Rejoindre { $org }
join-confirm-body = Vous rejoignez { $org }. Continuer ?
join-confirm-cta = Rejoindre
join-confirm-register-cta = S'inscrire pour rejoindre { $org }
join-confirm-decline = Continuer sans rejoindre
