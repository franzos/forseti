# Superficie de incorporación (plantillas claim_email e invite)

# Reclamar correo electrónico (claim_email.html)
claim-page-title = Reclamar correo electrónico
claim-card-title = Reclamar dirección de correo electrónico
claim-subtitle = Si alguien registró su correo electrónico pero nunca lo verificó, puede tomar posesión de él confirmando que recibe mensajes en esta dirección.
claim-email-label = Correo electrónico
claim-send-code = Enviar código
claim-changed-mind = ¿Cambió de opinión?
claim-back-to-signup = Volver al registro

# Confirmar reclamación (claim_email_confirm.html)
claim-confirm-page-title = Confirmar reclamación
claim-confirm-card-title = Confirme su código
claim-confirm-subtitle = Introduzca el código de 6 dígitos que acabamos de enviar. Los códigos caducan a los 15 minutos.
claim-confirm-code-label = Código
claim-confirm-button = Confirmar
claim-confirm-no-code = ¿No recibió un código?
claim-confirm-start-over = Empezar de nuevo

# Aceptar invitación (invite/accept.html)
invite-accept-page-title = Aceptar invitación
invite-accept-heading = Unirse a { $org }
invite-accept-body = Se le ha invitado a unirse a { $org } como { $role }. La invitación se envió a { $email }.

# Invitación no disponible (invite/invalid.html)
invite-invalid-page-title = Invitación no disponible
invite-invalid-heading = Invitación no disponible
invite-invalid-contact = Póngase en contacto con la persona que le invitó para solicitar un enlace nuevo.
invite-invalid-back = Volver al panel

# Errores del flujo de reclamación de correo electrónico (establecidos en Rust)
claim-error-invalid-email = Introduzca una dirección de correo electrónico válida.
claim-error-code-expired = El código ha caducado. Empiece de nuevo.
claim-error-invalid-token = Token no válido. Empiece de nuevo.
claim-error-service-unavailable = Servicio no disponible temporalmente. Vuelva a intentarlo en un momento.
claim-error-too-many-attempts = Demasiados códigos incorrectos. Empiece de nuevo.
claim-error-code-mismatch = El código no coincide. Vuelva a intentarlo.
claim-error-no-longer-claimable = Este correo electrónico ya no se puede reclamar.
claim-error-release-failed = No pudimos liberar el correo electrónico. Póngase en contacto con el soporte.

# Finalización de la invitación (establecido en Rust)
invite-error-corrupt = La invitación está dañada. Póngase en contacto con su administrador.
