# Página de início de sessão
auth-login-page-title = Iniciar sessão
auth-login-card-title = Inicie sessão na sua conta
auth-login-card-subtitle = Bem-vindo de volta ao { $brand }.
auth-login-aal2-body = Esta área exige autenticação de dois fatores, mas a sua conta ainda não tem um segundo fator configurado.
auth-login-aal2-hint = Configure uma aplicação de autenticação, uma chave de segurança ou códigos de recuperação nas definições e depois volte.
auth-login-aal2-setup-link = Configurar a autenticação de dois fatores
auth-login-forgot-password = Esqueceu-se da palavra-passe?
auth-login-no-account = Não tem conta?
auth-login-create-account = Criar conta

# Separador partilhado (início de sessão + registo)
auth-or-continue-with = Ou continue com
auth-oidc-signin = Iniciar sessão com { $provider }

# Página de registo
auth-registration-page-title = Criar conta
auth-registration-card-title = Crie uma conta
auth-registration-card-subtitle = Registe-se para gerir a sua identidade em segurança.
auth-registration-have-account = Já tem conta?
auth-registration-sign-in-link = Iniciar sessão
auth-registration-claim-body = Se este é o seu e-mail e nunca concluiu o registo,
auth-registration-claim-link = reivindique-o

# Página de recuperação
auth-recovery-page-title = Recuperação de conta
auth-recovery-card-title-sent = Verifique o seu e-mail
auth-recovery-card-title-default = Esqueceu-se da palavra-passe?
auth-recovery-card-subtitle-sent = Enviámos um código de recuperação para a sua caixa de entrada. Introduza-o abaixo para continuar.
auth-recovery-card-subtitle-default = Introduza o seu e-mail e enviar-lhe-emos uma ligação para a repor.
auth-recovery-back-to-sign-in = Voltar ao início de sessão

# Página de verificação
auth-verification-page-title = Verifique o seu e-mail
auth-verification-card-title-passed = E-mail verificado
auth-verification-card-title-sent = Verifique o seu e-mail
auth-verification-card-title-default = Verifique o seu e-mail
auth-verification-card-subtitle-passed = O seu e-mail foi confirmado. Pode fechar este separador ou continuar.
auth-verification-card-subtitle-sent = Enviámos um código de verificação para a sua caixa de entrada. Introduza-o abaixo para confirmar.
auth-verification-card-subtitle-default = Introduza o seu e-mail para receber um código de verificação.
auth-verification-sent-email-hint = Utilize o código do e-mail de verificação mais recente ou abra a ligação nesse e-mail em vez de introduzir o código manualmente.
auth-verification-back-to-dashboard = Voltar ao painel
auth-verification-back-to-sign-in = Voltar ao início de sessão

# Strings de navegador para WebAuthn / chaves de acesso (incorporadas via atributos de dados em webauthn_helper.html)
auth-webauthn-no-support = O seu navegador não suporta WebAuthn / chaves de acesso.
auth-passkey-needs-platform = O início de sessão com chave de acesso requer uma credencial de plataforma neste dispositivo (Touch ID, Windows Hello, um dispositivo Android ou uma chave de acesso sincronizada). O seu navegador não tem nenhuma configurada.
auth-webauthn-err-not-allowed = O pedido de credencial foi cancelado, expirou ou não havia nenhuma credencial correspondente disponível.
auth-webauthn-err-security = O seu navegador recusou a operação de segurança. Verifique se o site é carregado a partir de uma origem fidedigna e se o identificador registado corresponde.
auth-webauthn-err-invalid-state = Já existe uma credencial registada com este dispositivo. Experimente iniciar sessão ou utilize outro dispositivo.
auth-webauthn-err-not-supported = O seu navegador não suporta os parâmetros de credencial solicitados.
auth-webauthn-err-abort = O pedido de credencial foi interrompido antes de terminar.
auth-webauthn-err-generic-prefix = Erro do autenticador:

# Etiquetas de campos de fluxo. O Kratos emite os campos de traits com o `title` do
# esquema sob o id de etiqueta genérico 1070002; flow_view.rs substitui estes por nome.
auth-field-email = E-mail
auth-field-first-name = Nome próprio
auth-field-last-name = Apelido
