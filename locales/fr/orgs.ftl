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
orgs-sso-heading = SSO d'entreprise
orgs-sso-status-enabled = activé
orgs-sso-status-disabled = désactivé
orgs-sso-operator-note = Les connexions SSO sont gérées par l'opérateur.
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

# Page de destination publique (public_landing.html)
orgs-public-landing-note = Pour vous connecter, ouvrez l'application fournie par votre équipe. La connexion se fait depuis celle-ci.
orgs-public-landing-register = Créer un compte
