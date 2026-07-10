# Página de inicio de sesión
auth-login-page-title = Iniciar sesión
auth-login-card-title = Inicie sesión en su cuenta
auth-login-card-subtitle = Bienvenido de nuevo a { $brand }.
auth-login-aal2-body = Esta área requiere autenticación de dos factores, pero su cuenta aún no tiene configurado un segundo factor.
auth-login-aal2-hint = Configure una aplicación de autenticación, una llave de seguridad o códigos de recuperación en la configuración y vuelva luego.
auth-login-aal2-setup-link = Configurar la autenticación de dos factores
auth-login-forgot-password = ¿Olvidó su contraseña?
auth-login-no-account = ¿No tiene una cuenta?
auth-login-create-account = Crear cuenta

# Separador compartido (inicio de sesión + registro)
auth-or-continue-with = O continúe con
auth-oidc-signin = Iniciar sesión con { $provider }

# Página de registro
auth-registration-page-title = Crear cuenta
auth-registration-card-title = Crear una cuenta
auth-registration-card-subtitle = Regístrese para gestionar su identidad de forma segura.
auth-registration-have-account = ¿Ya tiene una cuenta?
auth-registration-sign-in-link = Iniciar sesión
auth-registration-claim-body = Si este es su correo electrónico y nunca terminó de registrarse,
auth-registration-claim-link = reclámelo

# Página de recuperación
auth-recovery-page-title = Recuperación de cuenta
auth-recovery-card-title-sent = Revise su correo electrónico
auth-recovery-card-title-default = ¿Olvidó su contraseña?
auth-recovery-card-subtitle-sent = Enviamos un código de recuperación a su bandeja de entrada. Introdúzcalo abajo para continuar.
auth-recovery-card-subtitle-default = Introduzca su correo electrónico y le enviaremos un enlace para restablecerla.
auth-recovery-back-to-sign-in = Volver al inicio de sesión

# Página de verificación
auth-verification-page-title = Verifique su correo electrónico
auth-verification-card-title-passed = Correo electrónico verificado
auth-verification-card-title-sent = Revise su correo electrónico
auth-verification-card-title-default = Verifique su correo electrónico
auth-verification-card-subtitle-passed = Su correo electrónico ha sido confirmado. Puede cerrar esta pestaña o continuar.
auth-verification-card-subtitle-sent = Enviamos un código de verificación a su bandeja de entrada. Introdúzcalo abajo para confirmar.
auth-verification-card-subtitle-default = Introduzca su correo electrónico para recibir un código de verificación.
auth-verification-sent-email-hint = Use el código del correo de verificación más reciente, o abra el enlace de ese correo en lugar de escribir el código a mano.
auth-verification-back-to-dashboard = Volver al panel
auth-verification-back-to-sign-in = Volver al inicio de sesión

# Textos del lado del navegador para WebAuthn / passkey (incrustados mediante atributos data en webauthn_helper.html)
auth-webauthn-no-support = Su navegador no admite WebAuthn / passkeys.
auth-passkey-needs-platform = El inicio de sesión con passkey necesita una credencial de plataforma en este dispositivo (Touch ID, Windows Hello, un dispositivo Android o un passkey sincronizado). Su navegador no tiene ninguna configurada.
auth-webauthn-err-not-allowed = La solicitud de credencial se canceló, agotó el tiempo de espera o no había ninguna credencial coincidente disponible.
auth-webauthn-err-security = Su navegador rechazó la operación de seguridad. Compruebe que el sitio se cargue desde un origen de confianza y que el identificador registrado coincida.
auth-webauthn-err-invalid-state = Ya hay una credencial registrada con este dispositivo. Intente iniciar sesión en su lugar, o use un dispositivo diferente.
auth-webauthn-err-not-supported = Su navegador no admite los parámetros de credencial solicitados.
auth-webauthn-err-abort = La solicitud de credencial se abortó antes de completarse.
auth-webauthn-err-generic-prefix = Error del autenticador:

# Etiquetas de campos de formulario. Kratos emite los campos de trait con el `title` del esquema
# bajo el id de etiqueta genérico de paso 1070002; flow_view.rs los sobrescribe por nombre.
auth-field-email = Correo electrónico
auth-field-first-name = Nombre
auth-field-last-name = Apellidos
