# Página de erro
error-reference-id = ID de referência:
error-cta-back-to-sign-in = Voltar ao início de sessão

# Confirmação de terminar sessão OAuth
logout-card-title = Terminar sessão em todas as aplicações?
logout-card-subtitle = Isto encerrará a sua sessão com o { $brand } e notificará todas as aplicações onde iniciou sessão.
logout-body-text = A aplicação que lhe pediu para terminar sessão será informada de que o pedido foi concluído. Algumas aplicações podem manter dados locais em cache durante algum tempo; terminar sessão aqui encerra a sessão no { $brand }.
logout-action-sign-out = Terminar sessão
logout-action-cancel = Cancelar

# Títulos e textos de diálogo de administração usados por render_admin_error nas chamadas que têm um locale.
# As chamadas sem locale (funções auxiliares, limites de erro) mantêm os seus literais em inglês.
dialog-identity-unavailable-title = Identidade indisponível
dialog-identity-unavailable-body = Não foi possível carregar essa identidade. Pode ter sido eliminada.
dialog-recovery-code-failed-title = Falha no código de recuperação
dialog-recovery-code-failed-body = Gerámos o código de recuperação mas não foi possível prepará-lo para exibição única. Gere um código novo para tentar novamente.
dialog-disable-failed-title = Falha ao desativar
dialog-enable-failed-title = Falha ao ativar
dialog-delete-failed-title = Falha ao eliminar
dialog-revoke-failed-title = Falha ao revogar

# Limite de erro (error_boundary.html), título/corpo/cta definidos nos handlers em Rust.
error-boundary-auth-unavailable-title = Autenticação indisponível
error-boundary-auth-unavailable-body = Não foi possível contactar o serviço de autenticação. Tente novamente dentro de instantes.
error-boundary-cta-try-again = Tentar novamente
error-boundary-cta-sign-in = Iniciar sessão
error-boundary-cta-back-to-settings = Voltar às definições
error-boundary-cta-back-to-dashboard = Voltar ao painel
error-boundary-cta-back-to-account = Voltar à conta
error-boundary-signin-title = Início de sessão indisponível
error-boundary-signup-title = Registo indisponível
error-boundary-recovery-title = Recuperação indisponível
error-boundary-verification-title = Verificação indisponível
error-boundary-settings-title = Definições indisponíveis
error-boundary-logout-title = Terminar sessão indisponível
error-boundary-logout-body = Não foi possível concluir o encerramento da sessão porque o serviço de autenticação está inacessível. A sua sessão continua ativa, por isso tente novamente dentro de instantes.
error-boundary-sessions-title = Sessões indisponíveis
error-boundary-sessions-body = Não foi possível listar as suas sessões ativas. Tente novamente dentro de instantes.
error-boundary-authorized-apps-title = Aplicações autorizadas indisponíveis
error-boundary-authorized-apps-no-session-body = Não foi possível ler a sua sessão. Inicie sessão novamente.
error-boundary-authorized-apps-service-body = Não foi possível contactar o serviço OAuth. Tente novamente dentro de instantes.
error-boundary-account-deletion-title = Falha na eliminação da conta
error-boundary-account-delete-bad-session = A sua sessão está num estado inesperado. Inicie sessão novamente e tente de novo.
error-boundary-account-delete-sole-owner = É o único proprietário de { $names }. Transfira a propriedade para outro membro antes de eliminar a sua conta.
error-boundary-account-delete-ownership-check-failed = Não foi possível verificar a sua propriedade da organização. Nada foi alterado; tente novamente dentro de instantes.
error-boundary-account-delete-consent-unreachable = Não foi possível contactar o serviço de consentimento para notificar as suas aplicações ligadas. Nada foi alterado; tente novamente dentro de instantes.
error-boundary-account-delete-notifications-failed = Não foi possível preparar as notificações de eliminação. Nada foi alterado; tente novamente.
error-boundary-account-delete-failed = Não foi possível eliminar a sua conta. Tente novamente dentro de instantes.

# Limite de erro SAML (apresentado no locale predefinido; o callback ACS não transporta o locale do pedido).
error-boundary-sso-unavailable-title = Início de sessão único indisponível
error-boundary-sso-unavailable-body = O início de sessão único não está disponível para este endereço. Verifique a ligação que o seu administrador lhe deu ou inicie sessão com o seu método habitual.
error-boundary-sso-failed-title = Falha no início de sessão único
error-boundary-sso-validation-failed-body = Não foi possível validar esta tentativa de início de sessão. Comece de novo a partir da ligação de SSO da sua organização.
error-boundary-sso-upstream-failed-body = O serviço de início de sessão está temporariamente indisponível. Tente novamente.
error-boundary-sso-no-email-body = O fornecedor de identidade não indicou um endereço de e-mail. Peça ao seu administrador para mapear o atributo de e-mail na ligação SAML.

# Página de erro self-service do Kratos (error.html), alternativas definidas em Rust.
error-page-generic-title = Algo correu mal
error-page-generic-body = Não foi possível carregar a página solicitada. A ligação pode ter expirado ou já ter sido utilizada.
error-page-link-expired-title = Ligação expirada
error-page-link-expired-body = Esta ligação já não é válida. Comece de novo a partir do início de sessão.
error-page-security-title = Falha na verificação de segurança
error-page-already-signed-in-title = Sessão já iniciada
error-page-default-message = Não foi possível concluir esse pedido.

# Página de acesso proibido da administração (admin/forbidden.html), definida em Rust.
error-admin-access-denied-title = Acesso negado
error-admin-access-denied-body = A sua conta não está autorizada a utilizar as ferramentas de administração.
error-admin-access-denied-forseti-body = A sua conta não está autorizada a utilizar as ferramentas de administração globais do Forseti.
error-admin-access-denied-org-body = Não tem acesso de administração a essa organização.

# SAML bloqueado
error-saml-blocked-page-title = Início de sessão bloqueado
error-saml-blocked-card-title = Não foi possível iniciar a sua sessão
error-saml-unverified-prefix = Já existe uma conta para
error-saml-unverified-suffix = mas o seu endereço de e-mail não foi verificado, pelo que o início de sessão único não se pode associar a ela em segurança. Verifique o endereço a partir do e-mail original do seu registo ou peça ajuda ao seu administrador.
error-saml-cross-org-not-member = A sua conta ainda não é membro desta organização. Peça ao seu administrador para o adicionar e tente novamente.
error-saml-conflict = Não foi possível iniciar a sua sessão. Contacte o seu administrador.
error-saml-blocked-cta = Ir para o início de sessão
