# Banner de administração (admin_shell.html)
admin-banner-label = ADMINISTRAÇÃO
admin-banner-body = Está numa superfície privilegiada. As ações aqui são registadas na auditoria.

# Título da barra lateral de navegação da administração (admin_nav.html)
admin-nav-heading = Administração
admin-nav-subtitle = Ferramentas do operador

# Cabeçalhos de secção da navegação da administração
admin-nav-section-system = Sistema
admin-nav-section-access = Acesso
admin-nav-section-linux = Linux

# Etiquetas dos itens de navegação da administração
admin-nav-status = Estado
admin-nav-configuration = Configuração
admin-nav-audit = Auditoria
admin-nav-webhooks = Webhooks
admin-nav-license = Licença
admin-nav-identities = Identidades
admin-nav-sessions = Sessões
admin-nav-clients = Clientes OAuth2
admin-nav-dcr-tokens = Tokens DCR
admin-nav-saml = SSO SAML
admin-nav-hosts = Hosts
admin-nav-accounts = Contas

# Lista de identidades (identities_list.html)
admin-identities-page-title = Identidades
admin-identities-subtitle = Identidades geridas pelo Kratos e o seu estado.
admin-identities-search-placeholder = Procurar por ID ou e-mail
admin-identities-search-button = Procurar
admin-identities-col-email = E-mail
admin-identities-col-state = Estado
admin-identities-col-created = Criada
admin-identities-empty = Nenhuma identidade encontrada.
admin-identities-prev = Voltar ao início
admin-identities-next = Página seguinte

# Detalhe da identidade (identity_show.html)
admin-identity-status-active = ativa
admin-identity-recovery-code-heading = Código de recuperação (mostrado uma vez)
admin-identity-recovery-link-heading = Ligação de recuperação
admin-identity-recovery-note = Partilhe isto com o utilizador através de um canal fidedigno. Não será mostrado novamente.
admin-identity-section-actions = Ações
admin-identity-action-generate-recovery = Gerar código de recuperação
admin-identity-action-disable = Desativar
admin-identity-action-enable = Ativar
admin-identity-action-delete = Eliminar
admin-identity-section-traits = Traits
admin-identity-section-addresses = Endereços verificáveis
admin-identity-addresses-empty = Nenhum endereço verificável nesta identidade.
admin-identity-status-verified = verificado
admin-identity-status-pending = pendente
admin-identity-section-credentials = Credenciais
admin-identity-credentials-empty = Nenhuma credencial configurada.
admin-identity-section-sessions = Sessões recentes
admin-identity-sessions-empty = Sem histórico de sessões.
admin-identity-action-revoke-session = Revogar sessão

# Seletor de identidade (identity_picker.html)
admin-identity-picker-page-title = Selecionar utilizador
admin-identity-picker-subtitle = Escolha uma identidade para continuar.
admin-identity-picker-invalid-return = Destino de retorno inválido.
admin-identity-picker-search-placeholder = Procurar por ID ou e-mail
admin-identity-picker-search-button = Procurar
admin-identity-picker-col-email = E-mail
admin-identity-picker-col-state = Estado
admin-identity-picker-col-created = Criada
admin-identity-picker-empty = Nenhuma identidade encontrada.
admin-identity-picker-action-select = Selecionar
admin-identity-picker-prev = Voltar ao início
admin-identity-picker-next = Página seguinte

# Lista de sessões (sessions_list.html)
admin-sessions-page-title = Sessões
admin-sessions-subtitle = Todas as sessões conhecidas pelo Kratos, em todas as identidades.
admin-sessions-filter-active-only = Apenas sessões ativas
admin-sessions-col-identity = Identidade
admin-sessions-col-authenticated = Autenticada
admin-sessions-col-expires = Expira
admin-sessions-col-device = Dispositivo
admin-sessions-empty = Nenhuma sessão a mostrar.
admin-sessions-action-revoke = Revogar
admin-sessions-prev = Voltar ao início
admin-sessions-next = Página seguinte

# Diálogo de confirmação genérico (confirm.html)
admin-confirm-cancel = Cancelar

# Página de acesso proibido (forbidden.html)
admin-forbidden-back = Voltar ao painel

# Página de erro da administração (error.html)
admin-error-back = Voltar ao estado da administração

# Lista de clientes (clients_list.html)
admin-clients-page-title = Clientes OAuth2
admin-clients-subtitle = Relying parties registadas no Hydra.
admin-clients-action-new = Novo cliente
admin-clients-search-placeholder = Procurar por nome ou ID do cliente
admin-clients-filter-all-types = Todos os tipos
admin-clients-filter-all-verifications = Todas as verificações
admin-clients-filter-verified = Verificado
admin-clients-filter-unverified = Não verificado
admin-clients-search-button = Procurar
admin-clients-col-name = Nome
admin-clients-col-type = Tipo
admin-clients-col-grants = Concessões
admin-clients-col-created = Criado
admin-clients-badge-unverified-title = Não avaliado por um administrador
admin-clients-badge-self-registered = Auto-registado
admin-clients-badge-self-registered-title = Registado via /oauth2/register (RFC 7591)
admin-clients-empty = Nenhum cliente registado.
admin-clients-prev = Voltar ao início
admin-clients-next = Página seguinte

# Badges partilhados de cliente (clients_list.html, client_show.html)
admin-client-badge-verified = Verificado
admin-client-badge-unverified = Não verificado
admin-client-badge-unverified-title = Um administrador não avaliou este cliente. O ecrã de consentimento avisa os utilizadores finais.

# Títulos da página de formulário de cliente (client_form.html)
admin-client-form-title-new = Novo cliente
admin-client-form-title-edit = Editar cliente
admin-client-form-heading-new = Novo cliente OAuth2
admin-client-form-heading-edit = Editar cliente
admin-client-form-preset-note = As predefinições estão preenchidas para este tipo.
admin-client-form-preset-change = Alterar tipo

# Campos partilhados do formulário de cliente (client_form.html, formulário de edição de client_show.html)
admin-client-field-name = Nome do cliente
admin-client-field-grant-types = Tipos de concessão
admin-client-grant-auth-code-hint = (início de sessão iniciado pelo utilizador)
admin-client-grant-refresh-hint = (sessões de longa duração)
admin-client-grant-client-creds-hint = (serviço a serviço)
admin-client-field-response-types = Tipos de resposta
admin-client-field-scope = Âmbito
admin-client-field-scope-hint = Âmbitos OAuth2 separados por espaços.
admin-client-field-redirect-uris = URIs de redirecionamento
admin-client-field-redirect-uris-hint = Um por linha (ou separados por vírgulas).
admin-client-field-post-logout-uris = URIs de redirecionamento pós-logout
admin-client-section-logout-fanout = Distribuição de logout OIDC
admin-client-section-logout-fanout-desc = Quando o utilizador encerra a sua sessão através do Forseti, o Hydra notifica os clientes nestes URIs para que cada aplicação possa limpar a sua sessão local. Deixe em branco para excluir este cliente da distribuição.
admin-client-field-backchannel-uri = URI de logout back-channel
admin-client-field-backchannel-uri-hint = O Hydra faz POST de um token de logout assinado aqui (servidor para servidor). Normalmente só faz sentido para aplicações web renderizadas no servidor e BFFs.
admin-client-field-backchannel-sid-prefix = Exigir a claim
admin-client-field-backchannel-sid-suffix = no token de logout back-channel
admin-client-field-backchannel-sid-short = claim
admin-client-field-frontchannel-uri = URI de logout front-channel
admin-client-field-frontchannel-uri-hint = O Hydra coloca este URL num iframe durante o logout para que cada aplicação possa limpar os cookies de sessão no navegador.
admin-client-field-frontchannel-sid-prefix = Exigir os parâmetros de consulta
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = no logout front-channel
admin-client-field-frontchannel-sid-short = parâmetros de consulta
admin-client-field-token-auth = Método de autenticação do endpoint de token
admin-client-token-auth-post-hint = (segredo no corpo do POST)
admin-client-token-auth-basic-hint = (segredo no cabeçalho Authorization)
admin-client-token-auth-none-hint = (cliente público, PKCE)
admin-client-token-auth-none-short = nenhum (público + PKCE)
admin-client-field-audience = Lista de audiências permitidas
admin-client-field-audience-hint-short = Uma por linha. O Hydra exige que os valores de audiência sejam previamente registados aqui.
admin-client-field-require-pkce = Exigir PKCE (informativo)
admin-client-field-skip-consent = Cliente fidedigno (ignorar o ecrã de consentimento)
admin-client-field-webhook-url = URL do webhook de eliminação de conta
admin-client-action-cancel = Cancelar

# Página de detalhe do cliente (client_show.html)
admin-client-action-revoke-verification = Revogar verificação
admin-client-action-mark-verified = Marcar como verificado
admin-client-action-rotate-secret = Rodar segredo
admin-client-action-delete = Eliminar
admin-client-credentials-heading = Credenciais: mostradas uma vez
admin-client-credentials-note = Copie-as agora. Não serão mostradas novamente; recarregue para dispensar. O ID do cliente e os endpoints acima não são secretos e permanecem visíveis.
admin-client-credentials-secret-label = Segredo do cliente
admin-client-credentials-rat-label = Token de acesso de registo
admin-client-credentials-rat-note = Nos termos da RFC 7592: permite ao cliente gerir o seu próprio registo (ler/atualizar/eliminar) através da API de registo dinâmico de clientes do Hydra. Não pode ser reemitido, por isso, em caso de dúvida, guarde-o.
admin-client-undoc-scopes-heading = Âmbitos não documentados
admin-client-section-connection = Detalhes da ligação
admin-client-connection-intro = Cole estes valores na configuração do cliente OIDC/OAuth do lado da aplicação.
admin-client-conn-client-id = ID do cliente
admin-client-conn-issuer = Emissor
admin-client-conn-discovery-url = URL de discovery
admin-client-conn-auth-endpoint = Endpoint de autorização
admin-client-conn-token-endpoint = Endpoint de token
admin-client-conn-userinfo-endpoint = Endpoint de userinfo
admin-client-conn-jwks-uri = URI JWKS
admin-client-conn-end-session-endpoint = Endpoint de fim de sessão
admin-client-section-config = Configuração
admin-client-config-sid-required = (sid obrigatório)
admin-client-config-iss-sid-required = (iss+sid obrigatórios)
admin-client-not-configured = não configurado
admin-client-audience-none = nenhuma
admin-client-config-token-auth = Autenticação do endpoint de token
admin-client-config-require-pkce = Exigir PKCE
admin-client-bool-yes = sim
admin-client-bool-no = não
admin-client-config-trusted = Fidedigno (ignorar consentimento)
admin-client-config-created = Criado
admin-client-config-provenance-audience = Audiência
admin-client-config-provenance-audience-note = (declarada pelo chamador DCR)
admin-client-config-provenance-url = Utilizado em
admin-client-config-provenance-url-note = (primeira observação no consentimento)
admin-client-config-webhook = Webhook de eliminação de conta
admin-client-section-edit = Editar
admin-client-action-save = Guardar alterações
admin-client-action-back = Voltar à lista

# Seletor de tipo de cliente (client_type_picker.html)
admin-client-type-page-title = Novo cliente
admin-client-type-heading = Novo cliente OAuth2
admin-client-type-subtitle = Escolha o tipo de aplicação. A página seguinte é o mesmo formulário, com as predefinições corretas já preenchidas, para não acabar acidentalmente numa combinação inválida.
admin-client-type-popular-heading = Aplicações populares
admin-client-type-action-cancel = Cancelar

# Lista de tokens DCR (dcr_tokens_list.html)
admin-dcr-page-title = Tokens de acesso inicial DCR
admin-dcr-action-issue = Emitir token
admin-dcr-token-revealed-heading = Token de acesso inicial (mostrado uma vez)
admin-dcr-col-status = Estado
admin-dcr-col-note = Nota
admin-dcr-col-created-by = Criado por
admin-dcr-col-created = Criado
admin-dcr-col-expires = Expira
admin-dcr-col-uses-left = Utilizações restantes
admin-dcr-status-active = Ativo
admin-dcr-status-revoked = Revogado
admin-dcr-status-expired = Expirado
admin-dcr-status-exhausted = Esgotado
admin-dcr-empty-prefix = Nenhum token emitido.
admin-dcr-empty-link = Emitir um
admin-dcr-empty-suffix = para permitir o auto-registo.
admin-dcr-action-revoke = Revogar

# Novo token DCR (dcr_token_new.html)
admin-dcr-new-page-title = Emitir token DCR
admin-dcr-new-heading = Emitir um token de acesso inicial DCR
admin-dcr-new-field-note = Nota
admin-dcr-new-field-note-placeholder = Para que serve este token? (por exemplo, 'Claude Desktop para formshive')
admin-dcr-new-field-note-hint = Opcional, apenas para os seus registos. O autor do cliente nunca vê isto.
admin-dcr-new-field-ttl = TTL (horas)
admin-dcr-new-field-ttl-hint = Deixe em branco para não expirar.
admin-dcr-new-field-max-uses = Utilizações máximas
admin-dcr-new-action-cancel = Cancelar

# Página de estado (status.html)
admin-status-page-title = Estado
admin-status-heading = Estado do sistema
admin-status-subtitle = Estado em tempo real dos componentes do IdP, da fila do courier e das versões de build.
admin-status-issuer-label = Emissor
admin-status-issuer-config-link = Ver configuração →
admin-status-warning-db-label = Base de dados
admin-status-warning-db-body = sqlite + implementação com aparência de produção. As configurações com várias instâncias irão corromper a base de dados. Mude para Postgres para HA.
admin-status-warning-webhook-label = Distribuição de webhooks
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } linha de webhook de eliminação de conta em dead-letter
       *[other] { $count } linhas de webhook de eliminação de conta em dead-letter
    }
admin-status-dead-webhook-middle = (os recetores não estão a ser notificados).
admin-status-dead-webhook-open = Abrir /admin/webhooks
admin-status-dead-webhook-action = para recolocar em fila ou descartar.
admin-status-section-services = Serviços
admin-status-col-service = Serviço
admin-status-col-state = Estado
admin-status-col-detail = Detalhe
admin-status-state-up = ativo
admin-status-state-down = inativo
admin-status-section-courier = Fila do courier
admin-status-courier-pending = Pendentes (em fila)
admin-status-courier-failed = Falhados (abandonados)
admin-status-courier-last-webhook = Último webhook de auditoria
admin-status-courier-never = nunca
admin-status-section-audit = Auditoria
admin-status-audit-write-failures = Falhas de escrita de auditoria (desde o arranque)
admin-status-audit-write-failures-note-prefix = As linhas são recuperáveis a partir das linhas estruturadas
admin-status-audit-write-failures-note-suffix = de stderr emitidas pelo Forseti no momento da falha.
admin-status-audit-webhook-rejected = Webhooks de auditoria rejeitados (desde o arranque)
admin-status-audit-webhook-rejected-note-prefix = Payloads malformados ou ações desconhecidas, provavelmente uma incompatibilidade de hook/config do Kratos. Verifique os
admin-status-audit-webhook-rejected-note-suffix = logs de aviso.
admin-status-audit-freshness = Anomalias de atualidade dos webhooks de auditoria (desde o arranque)
admin-status-audit-freshness-note = Payloads marcados como desatualizados ou com data futura, normalmente um fluxo lento ou desvio de relógio. As linhas continuam a ser registadas e assinaladas.
admin-status-section-license = Licença
admin-status-license-oss-prefix = Implementação de nível OSS.
admin-status-license-oss-link = Ative uma licença
admin-status-license-oss-suffix = para desbloquear funcionalidades premium.
admin-status-section-build = Versões de build
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = Base de dados

# Página de configuração (configuration.html)
admin-config-page-title = Configuração
admin-config-subtitle = Como este fornecedor de identidade está configurado: endpoints e capacidades OIDC, chaves de assinatura e esquemas de identidade do Kratos.
admin-config-discovery-warning-label = Discovery OIDC
admin-config-discovery-warning-body = Não foi possível alcançar o documento de discovery do Hydra. Os endpoints e as capacidades ficam ocultos até estar novamente acessível.
admin-config-section-oidc = Endpoints OIDC
admin-config-field-issuer = Emissor
admin-config-field-discovery-url = URL de discovery
admin-config-field-authorization = Autorização
admin-config-field-token = Token
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = Fim de sessão
admin-config-field-registration = Registo (DCR)
admin-config-field-revocation = Revogação
admin-config-section-capabilities = Capacidades
admin-config-cap-scopes = Âmbitos
admin-config-cap-grant-types = Tipos de concessão
admin-config-cap-response-types = Tipos de resposta
admin-config-cap-token-auth-methods = Métodos de autenticação do endpoint de token
admin-config-cap-pkce-methods = Métodos PKCE
admin-config-cap-id-token-signing-algs = Algoritmos de assinatura do ID token
admin-config-cap-subject-types = Tipos de subject
admin-config-cap-backchannel-logout = Logout back-channel
admin-config-cap-frontchannel-logout = Logout front-channel
admin-config-cap-yes = Sim
admin-config-cap-no = Não
admin-config-section-signing-keys = Chaves de assinatura (JWKS)
admin-config-signing-keys-unavailable = Indisponível: não foi possível obter as chaves públicas do Hydra.
admin-config-signing-keys-empty = O Hydra não anunciou nenhuma chave de assinatura.
admin-config-col-key-id = ID da chave
admin-config-col-alg = Alg
admin-config-col-type = Tipo
admin-config-col-use = Utilização
admin-config-section-schemas = Esquemas de identidade do Kratos
admin-config-schemas-unavailable = Indisponível: não foi possível obter os esquemas de identidade do Kratos.
admin-config-schemas-empty = Nenhum esquema de identidade registado.

# Lista de auditoria (audit.html)
admin-audit-page-title = Auditoria
admin-audit-subtitle = Registo de eventos só de anexação. Regista ações de administração do lado do Forseti, concessões OAuth, alterações de sessão e conclusões de fluxos do Kratos entregues via webhook. A retenção é configurada pelo operador (`[audit].audit_retention_days`); a limpeza é um subcomando da CLI, não é automática.
admin-audit-filter-email = O e-mail contém
admin-audit-filter-action = Prefixo da ação
admin-audit-filter-severity = Gravidade
admin-audit-filter-since = Desde
admin-audit-severity-any = Qualquer
admin-audit-severity-info = Info
admin-audit-severity-warning = Aviso
admin-audit-severity-error = Erro
admin-audit-severity-critical = Crítico
admin-audit-filter-button = Filtrar
admin-audit-col-target = Alvo
admin-audit-col-severity = Gravidade
admin-audit-col-when = Quando
admin-audit-col-actor = Ator
admin-audit-col-action = Ação
admin-audit-col-actions = Ações
admin-audit-empty = Nenhum evento corresponde aos filtros atuais.
admin-audit-badge-critical = crítico
admin-audit-badge-error = erro
admin-audit-badge-warning = aviso
admin-audit-action-view = Ver
admin-audit-prev = ‹ Anterior
admin-audit-next = Seguinte ›

# Detalhe da auditoria (audit_show.html)
admin-audit-back = ← Voltar à auditoria
admin-audit-show-section-event = Evento
admin-audit-show-outcome = Resultado
admin-audit-show-success = êxito
admin-audit-show-failure = falha
admin-audit-show-section-actor = Ator
admin-audit-show-field-kind = Tipo
admin-audit-show-field-email = E-mail
admin-audit-show-none = nenhum
admin-audit-show-field-identity-id = ID de identidade
admin-audit-show-section-target = Alvo
admin-audit-show-field-label = Etiqueta
admin-audit-show-deleted = (eliminado)
admin-audit-show-field-target-id = ID do alvo
admin-audit-show-section-metadata = Metadados
admin-audit-show-section-request-context = Contexto do pedido
admin-audit-show-field-ip-hash = Hash do IP
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = ID do pedido
admin-audit-show-field-org-id = ID da organização

# Lista de webhooks (webhooks.html)
admin-webhooks-page-title = Webhooks
admin-webhooks-heading = Webhooks em dead-letter
admin-webhooks-subtitle = Notificações de eliminação de conta que esgotaram as tentativas (12 tentativas ou 72 horas, o que ocorrer primeiro). Clique numa linha para ver o payload completo e o último erro, ou recoloque em fila a partir do resumo se souber que o recetor está novamente operacional.
admin-webhooks-empty = Nenhuma linha em dead-letter. Está tudo a passar.
admin-webhooks-col-client = Cliente
admin-webhooks-col-event = Evento
admin-webhooks-col-attempts = Tentativas
admin-webhooks-col-age = Idade
admin-webhooks-col-actions = Ações
admin-webhooks-deleted = (eliminado)
admin-webhooks-action-view = Ver
admin-webhooks-action-requeue = Recolocar em fila

# Detalhe do webhook (webhook_show.html)
admin-webhook-back = ← Voltar aos webhooks
admin-webhook-heading = Webhook em dead-letter
admin-webhook-action-requeue = Recolocar em fila
admin-webhook-action-discard = Descartar
admin-webhook-section-delivery = Entrega
admin-webhook-field-client = Cliente
admin-webhook-deleted = (eliminado)
admin-webhook-field-state = Estado
admin-webhook-field-url = URL
admin-webhook-field-attempts = Tentativas
admin-webhook-field-created = Criado
admin-webhook-field-next-attempt = Próxima tentativa
admin-webhook-section-last-error = Último erro
admin-webhook-section-payload = Payload assinado

# Lista de contas POSIX (posix_list.html)
admin-posix-page-title = Contas POSIX
admin-posix-subtitle = Identidades do Kratos materializadas em contas Linux (uid/gid + chaves SSH) para o resolvedor NSS.
admin-posix-seats-label = Lugares em uso:
admin-posix-license-note = Uma licença comercial de autenticação Linux aumenta o limite.
admin-posix-action-provision = Aprovisionar conta
admin-posix-col-username = Nome de utilizador
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Estado
admin-posix-col-created = Criada
admin-posix-empty-prefix = Nenhuma conta POSIX ativada.
admin-posix-empty-link = Aprovisionar uma
admin-posix-empty-suffix = a partir de uma identidade do Kratos.
admin-posix-status-enabled = ativada
admin-posix-status-disabled = desativada
admin-posix-action-manage = Gerir

# Detalhe da conta POSIX (posix_account.html)
admin-posix-action-disable = Desativar
admin-posix-action-enable = Ativar
admin-posix-action-delete = Eliminar
admin-posix-ssh-keys-heading = Chaves SSH
admin-posix-ssh-empty = Ainda não há chaves SSH.
admin-posix-ssh-key-added-prefix = adicionada
admin-posix-ssh-action-remove = Remover
admin-posix-ssh-field-public-key = Chave pública
admin-posix-ssh-field-comment = Comentário (opcional)
admin-posix-ssh-action-add = Adicionar chave
admin-posix-teams-heading = Equipas
admin-posix-hosts-heading = Hosts acessíveis
admin-posix-back = ← Todas as contas POSIX

# Nova conta POSIX (posix_new.html)
admin-posix-new-page-title = Aprovisionar conta POSIX
admin-posix-new-heading = Aprovisionar uma conta POSIX
admin-posix-new-choose-identity = Escolha a identidade a aprovisionar.
admin-posix-new-action-select-user = Selecionar utilizador
admin-posix-new-or-enter-directly = Ou introduza diretamente
admin-posix-new-placeholder-id = UUID ou e-mail
admin-posix-new-action-continue = Continuar
admin-posix-new-provision-intro = Materialize uma identidade do Kratos numa conta Linux. Um uid/gid é alocado automaticamente e um grupo primário é criado.
admin-posix-new-selected-prefix = Selecionado:
admin-posix-new-action-change = Alterar
admin-posix-new-field-username = Nome de utilizador
admin-posix-new-username-hint = Sugerido a partir do e-mail; edite se quiser. 1–32 caracteres, minúsculas, começando por uma letra ou underscore. Este passa a ser o nome de início de sessão POSIX.
admin-posix-new-field-shell = Shell de início de sessão
admin-posix-new-action-cancel = Cancelar

# Lista de hosts (hosts_list.html)
admin-hosts-page-title = Hosts
admin-hosts-subtitle = Máquinas Linux inscritas no resolvedor POSIX/NSS do Forseti. Cada host autentica-se com um segredo de uso único que revela na inscrição.
admin-hosts-action-enroll = Inscrever host
admin-hosts-credential-heading = Credencial do host (mostrada uma vez)
admin-hosts-credential-note-prefix = O formato é
admin-hosts-credential-note-suffix = . Configure o agente do host com esta credencial agora. Não guardamos o segredo em bruto, apenas o seu SHA-256.
admin-hosts-col-hostname = Nome do host
admin-hosts-col-teams = Equipas
admin-hosts-col-force-mfa = Forçar MFA
admin-hosts-col-enrolled = Inscrito
admin-hosts-col-last-seen = Visto pela última vez
admin-hosts-empty-prefix = Nenhum host inscrito.
admin-hosts-empty-link = Inscreva um
admin-hosts-empty-suffix = para lhe permitir resolver contas POSIX.
admin-hosts-status-mfa-pending = MFA (pendente)
admin-hosts-mfa-pending-title = Registado mas ainda não aplicado; a aplicação chega com o início de sessão interativo (PAM).
admin-hosts-action-edit = Editar
admin-hosts-action-rotate = Rodar
admin-hosts-action-revoke = Revogar

# Edição de host (hosts_edit.html)
admin-hosts-edit-page-title = Editar host
admin-hosts-edit-intro = Atualize a etiqueta do host, o seu indicador de MFA e as equipas a que está delimitado. O segredo não é mostrado aqui; rode-o a partir da lista de hosts se precisar de um novo.
admin-hosts-field-hostname = Nome do host
admin-hosts-hostname-hint = Uma etiqueta para os seus registos. Não tem de corresponder ao nome de host real da máquina.
admin-hosts-field-org = Organização
admin-hosts-org-fixed-note = A organização de um host é fixada na inscrição e não pode ser alterada aqui.
admin-hosts-field-allowed-teams = Equipas permitidas
admin-hosts-teams-empty = Ainda não existem equipas. Este host permite qualquer membro da organização. Delimitar um host a equipas específicas requer a funcionalidade Organizações.
admin-hosts-teams-hint = Restrinja este host aos membros das equipas selecionadas. Não selecione nenhuma para permitir qualquer membro da organização.
admin-hosts-field-force-mfa = Forçar MFA neste host
admin-hosts-force-mfa-hint = Registado agora; aplicado assim que o início de sessão interativo (PAM) estiver disponível.
admin-hosts-action-cancel = Cancelar

# Novo host (hosts_new.html)
admin-hosts-new-heading = Inscrever um host Linux
admin-hosts-new-intro-prefix = Um segredo de uso único é revelado uma vez na página seguinte. Configure o agente do host com a credencial
admin-hosts-new-intro-suffix = que ele mostra.
admin-hosts-org-belongs-hint = O host pertence a esta organização. Fixo após a inscrição.
admin-hosts-new-teams-empty = Ainda não existem equipas. Este host permitirá qualquer membro da organização. Delimitar um host a equipas específicas requer a funcionalidade Organizações.
admin-hosts-new-teams-scope-hint = Restrinja este host aos membros das equipas selecionadas. Apenas se aplicam as equipas da organização escolhida; não selecione nenhuma para permitir qualquer membro da organização.

# Lista de SSO SAML (saml_list.html)
admin-saml-page-title = SSO SAML
admin-saml-subtitle = Ligações SAML empresariais, uma por organização. Os metadados e certificados do IdP residem no Jackson; o Forseti mantém a linha âncora e o interruptor de ativação.
admin-saml-action-new = Nova ligação
admin-saml-grace-notice = Licença em período de tolerância. As ligações SAML são só de leitura até a licença ser renovada. Os inícios de sessão por SSO continuam a funcionar.
admin-saml-col-org = Organização
admin-saml-col-connection = Ligação
admin-saml-col-sso-url = URL de SSO
admin-saml-col-enabled = Ativada
admin-saml-empty-prefix = Ainda não há ligações SAML.
admin-saml-empty-link = Crie uma
admin-saml-empty-suffix = para ativar o SSO numa organização.
admin-saml-status-enabled = Ativada
admin-saml-status-disabled = Desativada
admin-saml-action-disable = Desativar
admin-saml-action-enable = Ativar
admin-saml-action-delete = Eliminar
admin-saml-idp-values-heading = Valores para o administrador do IdP do cliente
admin-saml-idp-values-intro = Entregue estes valores a quem configura a aplicação SAML do lado do fornecedor de identidade. São os mesmos para todas as ligações.
admin-saml-idp-acs-url = URL do ACS
admin-saml-idp-entity-id = ID da entidade SP

# Paginação da auditoria
admin-audit-range = A mostrar { $from }–{ $to } de { $total } linhas.
admin-audit-page = Página { $page }
admin-saml-entity-id-note-prefix = O ID da entidade segue a definição
admin-saml-entity-id-note-suffix = do Jackson; altere-o aí se substituir a predefinição.

# Nova ligação SSO SAML (saml_new.html)
admin-saml-new-page-title = Nova ligação SAML
admin-saml-new-intro = Ligue uma organização ao seu fornecedor de identidade. Cole o XML de metadados do IdP ou indique um URL de metadados que o Jackson vai buscar ele próprio: exatamente um dos dois.
admin-saml-new-field-org = Organização
admin-saml-new-org-hint = Uma ligação por organização.
admin-saml-new-field-name = Nome da ligação
admin-saml-new-name-hint = Apenas para os seus registos; os membros nunca veem isto.
admin-saml-new-field-metadata-url = URL de metadados
admin-saml-new-metadata-url-hint = Deixe em branco ao colar o XML em bruto abaixo.
admin-saml-new-metadata-url-https-note = O Jackson só vai buscar URLs de metadados HTTPS (ou localhost). Para metadados de IdP em HTTP simples, cole antes o XML abaixo.
admin-saml-new-field-metadata-xml = XML de metadados
admin-saml-new-metadata-xml-hint = Deixe em branco ao utilizar um URL de metadados acima.
admin-saml-new-action-create = Criar ligação
admin-saml-new-action-cancel = Cancelar

# Divisões de código inline (item 8: 2+ elementos de código por string)

# client_form.html - dica de tipos de resposta (código: code, token)
admin-client-field-response-types-hint-part1 = Separados por vírgulas, por exemplo,
admin-client-field-response-types-hint-part2 = (auth code) ou
admin-client-field-response-types-hint-part3 = (client credentials).

# client_form.html - dica de audiência (código: audience=<value>)
admin-client-field-audience-hint-part1 = Uma por linha. O Hydra exige que os valores de audiência sejam previamente registados aqui (ainda não suporta a RFC 8707). Os clientes passam
admin-client-field-audience-hint-part2 = no pedido de autorização.

# client_form.html - dica de PKCE (código: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = A aplicação global reside em
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). Este indicador serve para a intenção do operador.

# client_form.html + client_show.html - dica de webhook (código: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = Quando um utilizador se auto-elimina, o Forseti faz POST de um Security Event Token da RFC 8417 (RISC
admin-client-field-webhook-hint-part2 = ) aqui. Deixe em branco para não participar. Os recetores verificam o JWS contra o JWKS do Forseti em
admin-client-field-webhook-hint-part3 = .

# client_show.html - descrição dos âmbitos não documentados (código: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = Estes âmbitos estão registados neste cliente mas não têm entrada em
admin-client-undoc-scopes-desc-part2 = em
admin-client-undoc-scopes-desc-part3 = . O ecrã de consentimento recorre ao nome bruto do âmbito para eles.

# client_show.html - erro de discovery (código: <hydra-public-url>/…)
admin-client-discovery-error-part1 = Não foi possível alcançar o endpoint de discovery do Hydra, pelo que o emissor e os endpoints ficam ocultos para evitar mostrar um valor errado. Obtenha-os você mesmo a partir de
admin-client-discovery-error-part2 = .

# client_show.html - introdução da secção de edição (código: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Atualize os campos do cliente abaixo. As alterações são enviadas via
admin-client-edit-intro-part2 = do Hydra; os campos não relacionados são preservados.

# dcr_tokens_list.html - subtítulo (código: POST /oauth2/register)
admin-dcr-subtitle-part1 = Tokens Bearer que autorizam
admin-dcr-subtitle-part2 = . Entregue um ao autor de um cliente MCP para que se possa auto-registar sem que o faça manualmente.

# dcr_tokens_list.html - descrição do token revelado (código: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Partilhe isto com o autor do cliente. Ele envia-o como
admin-dcr-revealed-desc-part2 = ao chamar
admin-dcr-revealed-desc-part3 = . Não guardamos o valor em bruto, apenas o seu SHA-256.

# dcr_token_new.html - subtítulo (código: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = O token é revelado uma vez na página seguinte. Entregue-o ao autor do cliente. Ele envia-o como
admin-dcr-new-subtitle-part2 = numa única chamada
admin-dcr-new-subtitle-part3 = .

# dcr_token_new.html - dica de utilizações máximas (código: 1)
admin-dcr-new-field-max-uses-hint-part1 = Deixe em branco para ilimitado. Uma única utilização (
admin-dcr-new-field-max-uses-hint-part2 = ) é a predefinição mais segura.

# client_type_picker.html - descrição de aplicações populares (código: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Pré-preenchido para uma aplicação conhecida. Os URLs usam os marcadores
admin-client-type-popular-desc-part2 = (e por vezes
admin-client-type-popular-desc-part3 = ). Substitua-os pelos valores da sua aplicação depois de chegar ao formulário.

# posix_account.html - parágrafo das chaves SSH (código: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = As chaves públicas adicionadas aqui são servidas ao sshd do dispositivo (
admin-posix-ssh-keys-desc-part2 = ) para que este utilizador possa fazer
admin-posix-ssh-keys-desc-part3 = com a sua chave, sem necessidade de um ficheiro
admin-posix-ssh-keys-desc-part4 = por host. Requer o hook do sshd do host (configurado automaticamente pelo serviço
admin-posix-ssh-keys-desc-part5 = do Guix; configuração manual do sshd noutras distribuições). Não é utilizado para início de sessão na consola / PAM.

# posix_new.html - dica de shell (código: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Deve existir no(s) dispositivo(s) que servem esta conta;
admin-posix-new-shell-hint-part2 = é a predefinição segura entre distribuições (o Guix não tem
admin-posix-new-shell-hint-part3 = ). O diretório home deriva do prefixo home + nome de utilizador.

# saml_list.html - bloco de não configurado (código: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = não está configurado
admin-saml-not-configured-part2 = adicione as definições da ponte Jackson a
admin-saml-not-configured-part3 = para ativar o SSO SAML. Consulte
admin-saml-not-configured-part4 = .

# Mensagens flash da administração (mostradas como banner após um redirecionamento)
flash-identity-disabled = Identidade desativada.
flash-identity-enabled = Identidade ativada.
flash-session-revoked = Sessão revogada.
flash-client-create-failed = Falha ao criar o cliente: { $error }
flash-client-account-deletion-url-rejected = URL de eliminação de conta rejeitado: { $error }
flash-client-secret-stage-failed = Cliente criado, mas não foi possível preparar o segredo para exibição única. Rode o segredo para obter um valor novo.
