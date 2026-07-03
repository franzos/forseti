# Etiquetas de campos partilhadas entre as páginas de organização
orgs-field-name = Nome
orgs-field-slug = Slug
orgs-field-email = E-mail
orgs-field-role = Função

# Seletor de organizações (menu pendente da barra de navegação)
orgs-switcher-label = Mudar de organização
orgs-switcher-manage-link = Gerir organizações

# Lista de organizações (list.html)
orgs-list-title = Organizações
orgs-list-heading = As suas organizações
orgs-list-create-heading = Criar uma nova organização
orgs-list-field-slug-optional = Slug (opcional)
orgs-list-action-create = Criar
orgs-list-tier-gate-heading = Ter várias organizações é uma funcionalidade { $tier }
orgs-list-license-missing = A sua licença atual não inclui a funcionalidade Organizações.
orgs-list-unlicensed = Esta instalação do { $brand } está a funcionar sem licença, pelo que as organizações adicionais para além da predefinida estão bloqueadas.
orgs-list-license-upgrade = Ative ou atualize uma licença para criar mais.
orgs-list-link-get-license = Obter uma licença
orgs-list-link-activate-license = Ativar uma licença existente

# Visão geral da organização - vista do proprietário (overview.html)
orgs-overview-subtitle-default = Esta é a organização predefinida desta instalação do { $brand }. Qualquer pessoa que se registe junta-se a ela automaticamente.
orgs-overview-subtitle = Faça a gestão das definições, da identidade visual e dos membros desta organização.
orgs-overview-identity-heading = Identidade
orgs-overview-quicklinks-heading = Ligações rápidas
orgs-link-branding = Identidade visual
orgs-link-members = Membros
orgs-link-teams = Equipas
orgs-sso-heading = SSO empresarial
orgs-sso-status-enabled = ativado
orgs-sso-status-disabled = desativado
orgs-sso-operator-note = As ligações de SSO são geridas pelo operador.
orgs-danger-heading = Zona de perigo
orgs-danger-delete-body = Eliminar definitivamente esta organização. O Forseti recusa se ainda houver clientes OAuth2 associados.
orgs-danger-delete-action = Eliminar organização
orgs-confirm-delete-org = Eliminar { $name }? Isto não pode ser anulado.

# Visão geral da organização - vista de não proprietário (overview_info.html)
orgs-info-subtitle-default = Esta é a organização predefinida desta instalação do { $brand }. Você é membro dela.
orgs-info-subtitle = Você é membro desta organização.
orgs-info-org-heading = Organização
orgs-info-members-label = Membros
orgs-info-managed-by-heading = Gerida por
orgs-info-managed-by-note = Contacte um proprietário para alterações ao nome, à identidade visual ou aos membros da organização.

# Página de membros (members.html)
orgs-members-page-heading = Membros
orgs-members-subtitle = Os proprietários podem promover / despromover membros e remover qualquer pessoa exceto o último proprietário.
orgs-members-visibility-note-admins-only = Apenas os administradores podem ver a lista completa de membros.
orgs-members-visibility-note-same-group = Você vê os membros que partilham uma equipa consigo.
orgs-members-visibility-note-all = Todos os membros são visíveis.
orgs-members-invite-heading = Convidar por e-mail
orgs-members-role-member = Membro
orgs-members-role-owner = Proprietário
orgs-members-action-invite = Enviar convite
orgs-members-visibility-heading = Visibilidade do diretório
orgs-members-visibility-label = Quem pode ver a lista de membros
orgs-members-visibility-opt-all = Todos os membros
orgs-members-visibility-opt-same-group = Apenas a mesma equipa
orgs-members-visibility-opt-admins-only = Apenas administradores
orgs-members-visibility-hint = A opção apenas a mesma equipa exige que exista primeiro pelo menos uma equipa.
orgs-members-col-joined = Aderiu
orgs-members-badge-you = você
orgs-members-badge-hidden = Oculto
orgs-members-action-show = Mostrar
orgs-members-action-hide = Ocultar
orgs-members-action-update = Atualizar
orgs-members-action-remove = Remover
orgs-confirm-remove-member = Remover { $email }?
orgs-members-invites-heading = Convites pendentes
orgs-members-invites-col-sent = Enviado
orgs-members-invites-col-expires = Expira

# Página de equipas (teams.html)
orgs-teams-page-heading = Equipas
orgs-teams-subtitle = Agrupe os membros em equipas. As equipas delimitam o acesso aos hosts e determinam a visibilidade do diretório da mesma equipa.
orgs-teams-create-heading = Criar uma equipa
orgs-teams-action-create = Criar equipa
orgs-teams-col-team = Equipa
orgs-teams-col-members = Membros
orgs-teams-action-rename = Mudar o nome
orgs-teams-action-manage-members = Gerir membros
orgs-teams-action-delete = Eliminar
orgs-confirm-delete-team = Eliminar { $name }? Isto remove a equipa e os seus membros.
orgs-teams-selected-heading = Membros de { $team }
orgs-teams-add-member-label = Adicionar membro
orgs-teams-action-add = Adicionar

# Página de identidade visual (branding.html)
orgs-branding-page-heading = Identidade visual
orgs-branding-subtitle-prefix = Substitua a identidade predefinida do Forseti pelo logótipo e pelo e-mail de apoio desta organização. Recorre a
orgs-branding-subtitle-infix = em
orgs-branding-subtitle-suffix = quando não definida.
orgs-branding-field-logo-url = URL do logótipo
orgs-branding-field-support-email = E-mail de apoio
orgs-branding-theme-preset = Predefinição de tema
orgs-branding-primary = Cor principal
orgs-branding-on-primary = Texto sobre a cor principal
orgs-branding-secondary = Cor de destaque
orgs-branding-request-public = Ativar uma página de início de sessão pública (/o/o-seu-slug)
orgs-branding-preview = Pré-visualização

# Página de destino pública (public_landing.html)
orgs-public-landing-note = Para iniciar sessão, abra a aplicação que a sua equipa forneceu. O início de sessão acontece a partir daí.
orgs-public-landing-register = Criar uma conta
