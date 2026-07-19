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
orgs-list-field-access-mode = Modo de acesso
orgs-list-mode-internal-title = Interno
orgs-list-mode-internal-body = Somente por convite. Os membros entram por convite (e, futuramente, por um domínio corporativo verificado).
orgs-list-mode-external-title = Externo
orgs-list-mode-external-body = Cadastro público de autoatendimento. O diretório de membros fica restrito a administradores.
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
orgs-link-domains = Domínios
orgs-sso-heading = SSO empresarial
orgs-sso-status-enabled = ativado
orgs-sso-status-disabled = desativado
orgs-sso-operator-note = As ligações de SSO são geridas pelo operador.
orgs-access-mode-heading = Modo de acesso
orgs-access-mode-label = Modo
orgs-access-mode-internal = Interno
orgs-access-mode-external = Externo
orgs-access-mode-note-default = A organização predefinida é sempre interna.
orgs-access-mode-note-internal = Os membros entram por convite. Mudar para externo ativa o registo público.
orgs-access-mode-note-external = O registo público está ativado. O diretório de membros fica restrito a administradores enquanto estiver em modo externo.
orgs-access-mode-action-switch-external = Mudar para externo
orgs-access-mode-action-switch-internal = Mudar para interno
orgs-confirm-switch-external = Mudar para externo? Isto ativa a página de registo público e restringe o diretório de membros apenas a administradores.
orgs-confirm-switch-internal = Mudar para interno? Isto desativa a página de registo público. Os membros existentes mantêm a sua adesão.
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

# Página de domínios (domains.html)
orgs-domains-page-heading = Domínios permitidos
orgs-domains-subtitle = Utilizadores com um e-mail verificado num domínio comprovado juntam-se automaticamente a esta organização.
orgs-domains-add-heading = Adicionar um domínio
orgs-domains-field-domain = Domínio
orgs-domains-field-method = Método de verificação
orgs-domains-method-http_file = Ficheiro HTTP
orgs-domains-method-dns_txt = Registo TXT de DNS
orgs-domains-method-email = E-mail
orgs-domains-action-add = Adicionar domínio
orgs-domains-col-domain = Domínio
orgs-domains-col-method = Método
orgs-domains-col-status = Estado
orgs-domains-status-verified = Verificado
orgs-domains-status-pending = Pendente
orgs-domains-instructions-http_file = Sirva { $token } em https://{ $domain }/.well-known/forseti-domain-verify
orgs-domains-instructions-dns_txt = Crie um registo TXT em _forseti-verify.{ $domain } com o valor: { $token }
orgs-domains-instructions-email = Um código foi enviado para admin@{ $domain } e postmaster@{ $domain }. Cole-o abaixo.
orgs-domains-action-verify = Verificar
orgs-domains-action-confirm = Confirmar código
orgs-domains-field-token = Código de confirmação
orgs-domains-action-remove = Remover
orgs-confirm-remove-domain = Remover { $domain }? A adesão automática para este domínio para de imediato.
orgs-domains-policy-heading = Política de adesão
orgs-domains-policy-subtitle = Escolha como os utilizadores com um e-mail verificado num domínio comprovado aderem a esta organização.
orgs-domains-policy-field = Política
orgs-domains-policy-invite-only = Apenas por convite
orgs-domains-policy-auto-join = Os utilizadores de domínios verificados podem aderir por conta própria
orgs-domains-policy-save = Guardar política

# Página de identidade visual (branding.html)
orgs-branding-page-heading = Identidade visual
orgs-branding-subtitle-prefix = Substitua a identidade predefinida do Forseti pelo logótipo e pelo e-mail de apoio desta organização. Recorre a
orgs-branding-subtitle-infix = em
orgs-branding-subtitle-suffix = quando não definida.
orgs-branding-field-logo-url = URL do logótipo
orgs-branding-field-logo-file = Imagem do logótipo (PNG, JPEG ou WebP; máx. 256 KB)
orgs-branding-logo-remove = Remover logótipo
orgs-branding-logo-save = Carregar logótipo
orgs-branding-field-support-email = E-mail de apoio
orgs-branding-theme-preset = Predefinição de tema
orgs-branding-primary = Cor principal
orgs-branding-on-primary = Texto sobre a cor principal
orgs-branding-secondary = Cor de destaque
orgs-branding-request-public = Ativar uma página de início de sessão pública (/o/o-seu-slug)
orgs-branding-preview = Pré-visualização

# Flash notices (post-save banners)
flash-org-updated = Organização atualizada.
flash-branding-saved = Identidade visual guardada.
flash-logo-updated = Logótipo atualizado.
flash-logo-removed = Logótipo removido.

# Página de destino pública (public_landing.html)
orgs-public-landing-note = Inicie sessão abaixo ou crie uma conta para começar.
orgs-public-landing-register = Criar uma conta
orgs-public-landing-signin = Iniciar sessão

# Confirmação de adesão (join_confirm.html)
join-confirm-page-title = Ingressar na organização
join-confirm-heading = Ingressar em { $org }
join-confirm-body = Você está ingressando em { $org }. Continuar?
join-confirm-cta = Ingressar
join-confirm-register-cta = Registre-se para ingressar em { $org }
join-confirm-decline = Continuar sem aderir
