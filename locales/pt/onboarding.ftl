# Superfície de integração (modelos claim_email e invite)

# E-mail de reivindicação (claim_email.html)
claim-page-title = Reivindicar e-mail
claim-card-title = Reivindicar endereço de e-mail
claim-subtitle = Se alguém registou o seu e-mail mas nunca o verificou, pode assumir a propriedade confirmando que recebe correio neste endereço.
claim-email-label = E-mail
claim-send-code = Enviar código
claim-changed-mind = Mudou de ideias?
claim-back-to-signup = Voltar ao registo

# Confirmar reivindicação (claim_email_confirm.html)
claim-confirm-page-title = Confirmar reivindicação
claim-confirm-card-title = Confirme o seu código
claim-confirm-subtitle = Introduza o código de 6 dígitos que acabámos de enviar. Os códigos expiram após 15 minutos.
claim-confirm-code-label = Código
claim-confirm-button = Confirmar
claim-confirm-no-code = Não recebeu um código?
claim-confirm-start-over = Começar de novo

# Aceitar convite (invite/accept.html)
invite-accept-page-title = Aceitar convite
invite-accept-heading = Juntar-se a { $org }
invite-accept-body = Foi convidado para se juntar a { $org } como { $role }. O convite foi enviado para { $email }.

# Convite indisponível (invite/invalid.html)
invite-invalid-page-title = Convite indisponível
invite-invalid-heading = Convite indisponível
invite-invalid-contact = Contacte a pessoa que o convidou para solicitar uma nova ligação.
invite-invalid-back = Voltar ao painel

# Erros do fluxo de reivindicação de e-mail (definidos em Rust)
claim-error-invalid-email = Introduza um endereço de e-mail válido.
claim-error-code-expired = O código expirou. Comece de novo.
claim-error-invalid-token = Token inválido. Comece de novo.
claim-error-service-unavailable = Serviço temporariamente indisponível. Tente novamente dentro de instantes.
claim-error-too-many-attempts = Demasiados códigos incorretos. Comece de novo.
claim-error-code-mismatch = O código não corresponde. Tente novamente.
claim-error-no-longer-claimable = Este e-mail já não pode ser reivindicado.
claim-error-release-failed = Não foi possível libertar o e-mail. Contacte o apoio.

# Finalização do convite (definido em Rust)
invite-error-corrupt = O convite está corrompido. Contacte o seu administrador.
