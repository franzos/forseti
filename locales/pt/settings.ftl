settings-hub-title = Definições
settings-hub-subtitle = Faça a gestão das preferências da sua conta, das definições de segurança e das sessões ativas.
settings-hub-profile-title = Perfil
settings-hub-profile-desc = Atualize o seu endereço de e-mail e o nome a apresentar.
settings-hub-profile-link = Gerir perfil
settings-hub-password-title = Palavra-passe
settings-hub-password-desc = Altere a palavra-passe da sua conta.
settings-hub-password-link = Alterar palavra-passe
settings-hub-2fa-title = Autenticação de dois fatores
settings-hub-2fa-desc = Configure TOTP, códigos de recuperação e chaves de segurança.
settings-hub-2fa-link = Gerir 2FA
settings-hub-sessions-title = Sessões ativas
settings-hub-sessions-desc = Reveja os dispositivos com sessão iniciada na sua conta.
settings-hub-sessions-link = Ver sessões
settings-hub-apps-title = Aplicações autorizadas
settings-hub-apps-desc = Reveja e revogue as aplicações OAuth a que concedeu acesso.
settings-hub-apps-link = Gerir aplicações
settings-hub-providers-title = Fornecedores associados
settings-hub-providers-desc = Associe ou remova fornecedores de início de sessão de terceiros.
settings-hub-providers-link = Gerir fornecedores
settings-hub-account-title = Conta
settings-hub-account-desc = Alterações permanentes: eliminar a sua conta.
settings-hub-account-link = Zona de perigo
settings-nav-general = Geral
settings-nav-security = Segurança
settings-nav-connections = Ligações
settings-nav-overview = Visão geral
settings-nav-profile = Perfil
settings-nav-organization = Organização
settings-nav-password = Palavra-passe
settings-nav-2fa = 2FA
settings-nav-sessions = Sessões
settings-nav-offline = Início de sessão offline
settings-nav-authorized-apps = Aplicações autorizadas
settings-nav-linked-providers = Fornecedores associados
settings-nav-account = Conta

# Subpágina de perfil
settings-profile-heading = Perfil
settings-profile-subtitle = Atualize o seu endereço de e-mail e o nome a apresentar.
settings-profile-email-not-verified = Não verificado
settings-profile-email-send-verification = Enviar e-mail de verificação
settings-profile-public-heading = Perfil público
settings-profile-public-saved = Perfil guardado.
settings-profile-public-label-bio = Biografia
settings-profile-public-label-location = Localização
settings-profile-public-label-pronouns = Pronomes
settings-profile-public-label-website = Site
settings-profile-public-label-avatar = URL do avatar
settings-profile-public-avatar-hint = Opcional. Deixe em branco para utilizar o identicon gerado automaticamente.
settings-profile-public-label-links = Ligações
settings-profile-public-save = Guardar perfil
settings-profile-back = Voltar às definições
settings-profile-language-label = Idioma preferido
settings-profile-language-help = Aplica-se em todos os seus dispositivos.

# Subpágina de palavra-passe
settings-password-heading = Palavra-passe
settings-password-subtitle = Altere a palavra-passe utilizada para iniciar sessão.
settings-password-back = Voltar às definições

# Subpágina de conta
settings-account-heading = Conta
settings-account-subtitle = Alterações permanentes à sua conta.
settings-account-delete-section-heading = Eliminar conta
settings-account-delete-body = Elimine definitivamente a sua conta, todas as sessões ativas e todo o estado de 2FA / recuperação. As aplicações que guardam cópias dos seus dados são notificadas para poderem limpar o seu lado. Isto não pode ser anulado.
settings-account-delete-action = Eliminar a minha conta

# Página de confirmação de eliminação de conta
settings-account-delete-page-title = Confirmar eliminação
settings-account-delete-confirm-heading = Eliminar a sua conta?
settings-account-delete-confirm-subtitle-prefix = Isto remove definitivamente
settings-account-delete-confirm-subtitle-suffix = e todas as sessões, códigos de recuperação e credenciais associados.
settings-account-delete-apps-heading = Estas aplicações serão informadas de que já não está presente
settings-account-delete-apps-note = As aplicações copiam os dados de que necessitam (perfil, definições) e mantêm-nos associados ao ID da sua conta. Notificamo-las através do webhook de eliminação que registaram para que possam limpar a sua cópia.
settings-account-delete-no-apps = Nenhuma aplicação de terceiros tem cópias dos seus dados neste momento. Nada a notificar.
settings-account-delete-confirm-label = Para confirmar, escreva o seu e-mail abaixo:
settings-account-delete-confirm-placeholder = Escreva o seu e-mail para confirmar
settings-account-delete-confirm-submit = Sim, eliminar a minha conta
settings-account-delete-confirm-cancel = Cancelar

# Subpágina de acesso offline
settings-offline-heading = Início de sessão offline no host
settings-offline-subtitle = Defina uma frase-passe dedicada que lhe permite iniciar sessão no terminal de um host Linux inscrito quando este não consegue alcançar este servidor. É separada da palavra-passe da sua conta. Utilize algo de que se lembre mas que não reutilizaria.
settings-offline-status-set-prefix = Está definida uma frase-passe offline
settings-offline-status-set-word = definida
settings-offline-status-set-suffix = . Introduza uma nova abaixo para a alterar ou remova-a por completo.
settings-offline-status-unset = Ainda não está definida nenhuma frase-passe offline. Sem uma, não consegue iniciar sessão num host inscrito enquanto este estiver offline.
settings-offline-label-new-passphrase = Nova frase-passe offline
settings-offline-label-passphrase = Frase-passe offline
settings-offline-passphrase-hint = Pelo menos { $min_len } caracteres. Não reutilize a palavra-passe da sua conta.
settings-offline-action-change = Alterar frase-passe
settings-offline-action-set = Definir frase-passe
settings-offline-remove-heading = Remover acesso offline
settings-offline-remove-body = Elimine a sua frase-passe offline. Os hosts inscritos deixam de a ter na próxima sincronização e deixará de conseguir iniciar sessão neles enquanto estiverem offline.
settings-offline-action-remove = Remover frase-passe
settings-offline-back = Voltar às definições

# Transferência de palavra-passe (recuperação → definir nova palavra-passe)
settings-handoff-heading = Definir uma nova palavra-passe
settings-handoff-subtitle = Tem sessão iniciada através do código de recuperação. Escolha uma nova palavra-passe para concluir.
settings-handoff-countdown-label = Tempo restante para definir a sua nova palavra-passe:
settings-handoff-sign-out = Terminar sessão sem alterar

# Subpágina de 2FA
settings-2fa-heading = Autenticação de dois fatores
settings-2fa-subtitle = Reforce a sua conta com um segundo fator.
settings-2fa-no-recovery-warning-heading = Sem códigos de recuperação: corre o risco de ficar impedido de aceder
settings-2fa-no-recovery-warning-body = A autenticação de dois fatores está ativada, mas não tem códigos de recuperação. Se perder o seu autenticador ou a chave de segurança, os códigos de recuperação são a única forma de voltar a aceder à sua conta. Gere-os agora.
settings-2fa-no-recovery-warning-action = Gerar códigos
settings-2fa-totp-heading = Aplicação de autenticação (TOTP)
settings-2fa-totp-desc = Utilize uma aplicação como o 1Password, o Bitwarden, o Aegis ou o Authy para gerar códigos de 6 dígitos.
settings-2fa-totp-enabled = Ativada
settings-2fa-totp-scan-hint = Leia este código QR com a sua aplicação de autenticação ou introduza o segredo manualmente:
settings-2fa-totp-not-offered = A configuração de aplicação de autenticação não é atualmente disponibilizada pelo seu servidor.
settings-2fa-recovery-heading = Códigos de recuperação
settings-2fa-recovery-desc = Códigos de utilização única que lhe permitem iniciar sessão se perder o acesso ao seu autenticador.
settings-2fa-recovery-active = Ativos
settings-2fa-recovery-save-strong = Guarde-os agora.
settings-2fa-recovery-save-suffix = Não serão mostrados novamente. Guarde-os num local seguro. Um gestor de palavras-passe funciona bem.
settings-2fa-recovery-not-offered = Os códigos de recuperação não são atualmente disponibilizados pelo seu servidor.
settings-2fa-webauthn-heading = Chaves de segurança e chaves de acesso
settings-2fa-webauthn-desc = Utilize uma chave de hardware (YubiKey, Titan) ou uma chave de acesso de plataforma (Touch ID, Windows Hello) como segundo fator.
settings-2fa-webauthn-remove-fallback = Remover chave de segurança
settings-2fa-webauthn-not-enabled = O suporte a chaves de acesso não está ativado pelo seu administrador.
settings-2fa-back = Voltar às definições

# Subpágina de sessões
settings-sessions-heading = Sessões ativas
settings-sessions-subtitle = Dispositivos atualmente com sessão iniciada na sua conta. Revogue qualquer um que não reconheça.
settings-sessions-revoke-action = Terminar sessão
settings-sessions-revoke-others-heading = Terminar sessão em todos os outros dispositivos
settings-sessions-revoke-others-desc = Mantém esta sessão ativa e revoga todas as outras.
settings-sessions-revoke-others-action = Terminar as outras sessões
settings-sessions-back = Voltar às definições

# Subpágina de aplicações autorizadas
settings-apps-heading = Aplicações autorizadas
settings-apps-subtitle = Aplicações a que concedeu acesso à sua conta. Revogue qualquer uma que já não utilize. Terão de pedir permissão novamente na próxima vez que iniciar sessão.
settings-apps-empty = Ainda não foi concedido acesso à sua conta a nenhuma aplicação.
settings-apps-verified-label = Verificada
settings-apps-access-granted-prefix = Acesso concedido
settings-apps-revoke-action = Revogar acesso
settings-apps-back = Voltar às definições
settings-apps-reviewed-title = Analisada pelo seu administrador

# Restantes de 2FA
settings-2fa-qr-alt = Código QR TOTP

# Expiração da contagem decrescente da transferência de palavra-passe (renderizada em JS)
settings-handoff-expired-lead = A sua janela de recuperação expirou.
settings-handoff-expired-link = Começar de novo

# Subpágina de fornecedores associados
settings-providers-heading = Fornecedores associados
settings-providers-subtitle = Inicie sessão na sua conta utilizando um fornecedor de identidade de terceiros.
settings-providers-empty-heading = Nenhum fornecedor upstream configurado pelo seu administrador.
settings-providers-empty-desc = Contacte o seu administrador para ativar o Google, o GitHub ou outros fornecedores de início de sessão.
settings-providers-back = Voltar às definições

# Divisões de código inline (item 8: 2+ elementos de código por string)

# settings_profile.html - descrição do perfil público (código: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Visível para colegas de organização na sua
settings-profile-public-desc-part2 = e para as aplicações a que conceder os âmbitos OAuth
settings-profile-public-desc-part3 = ou
settings-profile-public-desc-part4 = . Deixe qualquer campo em branco para o ocultar.

# settings_profile.html - dica de ligações (código: Label|https://url)
settings-profile-links-hint-part1 = Uma por linha, no formato
settings-profile-links-hint-part2 = .

# Mensagens flash e corpos de erro inline definidos nos handlers em Rust.
flash-session-signed-out = Sessão terminada.
flash-session-signout-failed = Não foi possível terminar essa sessão.
flash-sessions-signed-out-others =
    { $count ->
        [one] Terminada { $count } outra sessão.
       *[other] Terminadas { $count } outras sessões.
    }
flash-sessions-signout-others-failed = Não foi possível terminar as outras sessões.
flash-app-access-revoked = Acesso revogado.
flash-app-access-revoke-failed = Não foi possível revogar o acesso a essa aplicação.
flash-offline-passphrase-saved = Frase-passe offline guardada. Os hosts inscritos irão obtê-la na próxima sincronização.
flash-offline-passphrase-save-failed = Não foi possível guardar a sua frase-passe offline. Tente novamente.
flash-offline-passphrase-too-short = A sua frase-passe offline deve ter pelo menos { $min_len } caracteres.
flash-offline-passphrase-removed = Frase-passe offline removida. Os hosts deixam de a ter na próxima sincronização.
flash-offline-passphrase-none = Não tem nenhuma frase-passe offline definida.
flash-offline-passphrase-remove-failed = Não foi possível remover a sua frase-passe offline. Tente novamente.
settings-profile-url-invalid = O URL do site e do avatar devem ser URLs http:// ou https:// válidos.
settings-profile-link-url-invalid = Cada URL de ligação deve ser um URL http:// ou https:// válido.
settings-save-failed = Não foi possível guardar as suas alterações. Tente novamente.
