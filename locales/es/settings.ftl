settings-hub-title = Configuración
settings-hub-subtitle = Gestione las preferencias de su cuenta, la configuración de seguridad y las sesiones activas.
settings-hub-profile-title = Perfil
settings-hub-profile-desc = Actualice su dirección de correo electrónico y su nombre para mostrar.
settings-hub-profile-link = Gestionar perfil
settings-hub-password-title = Contraseña
settings-hub-password-desc = Cambie la contraseña de su cuenta.
settings-hub-password-link = Cambiar contraseña
settings-hub-2fa-title = Autenticación de dos factores
settings-hub-2fa-desc = Configure TOTP, códigos de recuperación y llaves de seguridad.
settings-hub-2fa-link = Gestionar 2FA
settings-hub-sessions-title = Sesiones activas
settings-hub-sessions-desc = Revise los dispositivos que han iniciado sesión en su cuenta.
settings-hub-sessions-link = Ver sesiones
settings-hub-apps-title = Aplicaciones autorizadas
settings-hub-apps-desc = Revise y revoque las aplicaciones OAuth a las que ha concedido acceso.
settings-hub-apps-link = Gestionar aplicaciones
settings-hub-providers-title = Proveedores vinculados
settings-hub-providers-desc = Conecte o elimine proveedores de inicio de sesión de terceros.
settings-hub-providers-link = Gestionar proveedores
settings-hub-account-title = Cuenta
settings-hub-account-desc = Cambios permanentes: eliminar su cuenta.
settings-hub-account-link = Zona de peligro
settings-nav-general = General
settings-nav-security = Seguridad
settings-nav-connections = Conexiones
settings-nav-overview = Resumen
settings-nav-profile = Perfil
settings-nav-organization = Organización
settings-nav-password = Contraseña
settings-nav-2fa = 2FA
settings-nav-sessions = Sesiones
settings-nav-offline = Inicio de sesión sin conexión
settings-nav-authorized-apps = Aplicaciones autorizadas
settings-nav-linked-providers = Proveedores vinculados
settings-nav-account = Cuenta

# Subpágina de perfil
settings-profile-heading = Perfil
settings-profile-subtitle = Actualice su dirección de correo electrónico y su nombre para mostrar.
settings-profile-email-not-verified = No verificado
settings-profile-email-send-verification = Enviar correo de verificación
settings-profile-public-heading = Perfil público
settings-profile-public-saved = Perfil guardado.
settings-profile-public-label-bio = Biografía
settings-profile-public-label-location = Ubicación
settings-profile-public-label-pronouns = Pronombres
settings-profile-public-label-website = Sitio web
settings-profile-public-label-avatar = URL del avatar
settings-profile-public-avatar-hint = Opcional. Déjelo en blanco para usar el identicon generado automáticamente.
settings-profile-public-label-links = Enlaces
settings-profile-public-save = Guardar perfil
settings-profile-back = Volver a la configuración
settings-profile-language-label = Idioma preferido
settings-profile-language-help = Se aplica en todos sus dispositivos.

# Subpágina de contraseña
settings-password-heading = Contraseña
settings-password-subtitle = Cambie la contraseña usada para iniciar sesión.
settings-password-back = Volver a la configuración

# Subpágina de cuenta
settings-account-heading = Cuenta
settings-account-subtitle = Cambios permanentes en su cuenta.
settings-account-delete-section-heading = Eliminar cuenta
settings-account-delete-body = Elimine de forma permanente su cuenta, todas las sesiones activas y todo el estado de 2FA / recuperación. Se notifica a las aplicaciones que tienen copias de sus datos para que puedan borrar su parte. Esto no se puede deshacer.
settings-account-delete-action = Eliminar mi cuenta

# Página de confirmación de eliminación de cuenta
settings-account-delete-page-title = Confirmar eliminación
settings-account-delete-confirm-heading = ¿Eliminar su cuenta?
settings-account-delete-confirm-subtitle-prefix = Esto elimina de forma permanente
settings-account-delete-confirm-subtitle-suffix = y todas las sesiones, códigos de recuperación y credenciales asociados a ella.
settings-account-delete-apps-heading = A estas aplicaciones se les notificará que ya no está
settings-account-delete-apps-note = Las aplicaciones copian los datos que necesitan (perfil, configuración) y los mantienen vinculados al ID de su cuenta. Les notificamos mediante el webhook de eliminación que registraron para que puedan borrar su copia.
settings-account-delete-no-apps = Ninguna aplicación de terceros tiene copias de sus datos en este momento. No hay a quién notificar.
settings-account-delete-confirm-label = Para confirmar, escriba su correo electrónico a continuación:
settings-account-delete-confirm-placeholder = Escriba su correo electrónico para confirmar
settings-account-delete-confirm-submit = Sí, eliminar mi cuenta
settings-account-delete-confirm-cancel = Cancelar

# Subpágina de acceso sin conexión
settings-offline-heading = Inicio de sesión sin conexión en el host
settings-offline-subtitle = Establezca una frase de contraseña dedicada que le permita iniciar sesión en el terminal de un host Linux inscrito cuando no pueda alcanzar este servidor. Es independiente de la contraseña de su cuenta. Use algo que recuerde pero que no reutilizaría.
settings-offline-status-set-prefix = Una frase de contraseña sin conexión está
settings-offline-status-set-word = establecida
settings-offline-status-set-suffix = . Introduzca una nueva a continuación para cambiarla, o elimínela por completo.
settings-offline-status-unset = Aún no se ha establecido ninguna frase de contraseña sin conexión. Sin una, no puede iniciar sesión en un host inscrito mientras está sin conexión.
settings-offline-label-new-passphrase = Nueva frase de contraseña sin conexión
settings-offline-label-passphrase = Frase de contraseña sin conexión
settings-offline-passphrase-hint = Al menos { $min_len } caracteres. No reutilice la contraseña de su cuenta.
settings-offline-action-change = Cambiar frase de contraseña
settings-offline-action-set = Establecer frase de contraseña
settings-offline-remove-heading = Eliminar acceso sin conexión
settings-offline-remove-body = Elimine su frase de contraseña sin conexión. Los hosts inscritos la descartan en su próxima sincronización, y ya no podrá iniciar sesión en ellos mientras están sin conexión.
settings-offline-action-remove = Eliminar frase de contraseña
settings-offline-back = Volver a la configuración

# Traspaso de contraseña (recuperación → establecer nueva contraseña)
settings-handoff-heading = Establecer una nueva contraseña
settings-handoff-subtitle = Ha iniciado sesión mediante el código de recuperación. Elija una nueva contraseña para finalizar.
settings-handoff-countdown-label = Tiempo restante para establecer su nueva contraseña:
settings-handoff-sign-out = Cerrar sesión sin cambiar

# Subpágina de 2FA
settings-2fa-heading = Autenticación de dos factores
settings-2fa-subtitle = Refuerce su cuenta con un segundo factor.
settings-2fa-no-recovery-warning-heading = Sin códigos de recuperación: corre el riesgo de quedar bloqueado
settings-2fa-no-recovery-warning-body = La autenticación de dos factores está activada, pero no tiene códigos de recuperación. Si pierde su aplicación de autenticación o su llave de seguridad, los códigos de recuperación son la única forma de volver a entrar en su cuenta. Genérelos ahora.
settings-2fa-no-recovery-warning-action = Generar códigos
settings-2fa-totp-heading = Aplicación de autenticación (TOTP)
settings-2fa-totp-desc = Use una aplicación como 1Password, Bitwarden, Aegis o Authy para generar códigos de 6 dígitos.
settings-2fa-totp-enabled = Activado
settings-2fa-totp-scan-hint = Escanee este código QR con su aplicación de autenticación, o introduzca el secreto manualmente:
settings-2fa-totp-not-offered = La configuración de la aplicación de autenticación no está disponible actualmente en su servidor.
settings-2fa-recovery-heading = Códigos de recuperación
settings-2fa-recovery-desc = Códigos de un solo uso que le permiten iniciar sesión si pierde el acceso a su aplicación de autenticación.
settings-2fa-recovery-active = Activo
settings-2fa-recovery-save-strong = Guárdelos ahora.
settings-2fa-recovery-save-suffix = No se volverán a mostrar. Guárdelos en un lugar seguro. Un gestor de contraseñas funciona bien.
settings-2fa-recovery-not-offered = Los códigos de recuperación no están disponibles actualmente en su servidor.
settings-2fa-webauthn-heading = Llaves de seguridad y passkeys
settings-2fa-webauthn-desc = Use una llave de hardware (YubiKey, Titan) o un passkey de plataforma (Touch ID, Windows Hello) como segundo factor.
settings-2fa-webauthn-remove-fallback = Eliminar llave de seguridad
settings-2fa-webauthn-not-enabled = Su administrador no ha activado la compatibilidad con passkey.
settings-2fa-back = Volver a la configuración

# Subpágina de sesiones
settings-sessions-heading = Sesiones activas
settings-sessions-subtitle = Dispositivos que actualmente tienen la sesión iniciada en su cuenta. Revoque cualquiera que no reconozca.
settings-sessions-revoke-action = Cerrar sesión
settings-sessions-revoke-others-heading = Cerrar sesión en todos los demás dispositivos
settings-sessions-revoke-others-desc = Mantiene esta sesión activa y revoca todas las demás.
settings-sessions-revoke-others-action = Cerrar las demás
settings-sessions-back = Volver a la configuración

# Subpágina de aplicaciones autorizadas
settings-apps-heading = Aplicaciones autorizadas
settings-apps-subtitle = Aplicaciones a las que ha concedido acceso a su cuenta. Revoque cualquiera que ya no use. Tendrán que pedir permiso de nuevo la próxima vez que inicie sesión.
settings-apps-empty = Aún no se ha concedido acceso a ninguna aplicación a su cuenta.
settings-apps-verified-label = Verificado
settings-apps-access-granted-prefix = Acceso concedido
settings-apps-revoke-action = Revocar acceso
settings-apps-back = Volver a la configuración
settings-apps-reviewed-title = Revisado por su administrador

# Restos de 2FA
settings-2fa-qr-alt = Código QR de TOTP

# Traspaso de contraseña: caducidad de la cuenta atrás (renderizado en JS)
settings-handoff-expired-lead = Su ventana de recuperación caducó.
settings-handoff-expired-link = Empezar de nuevo

# Subpágina de proveedores vinculados
settings-providers-heading = Proveedores vinculados
settings-providers-subtitle = Inicie sesión en su cuenta usando un proveedor de identidad de terceros.
settings-providers-empty-heading = Su administrador no ha configurado ningún proveedor upstream.
settings-providers-empty-desc = Contacte a su administrador para activar Google, GitHub u otros proveedores de inicio de sesión.
settings-providers-back = Volver a la configuración
settings-providers-status-connected = Conectado el { $date }
settings-providers-status-connected-plain = Conectado
settings-providers-status-not-connected = No conectado
settings-providers-link = Vincular
settings-providers-unlink = Desvincular
settings-providers-unlink-blocked = Este es su único método de inicio de sesión. Añada una contraseña o una clave de acceso antes de poder desvincularlo.
settings-providers-confirm-unlink = ¿Desvincular { $provider }? Ya no podrá iniciar sesión con él.

# Divisiones de código en línea (elemento 8: 2+ elementos de código por cadena)

# settings_profile.html - descripción del perfil público (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Visible para los miembros de su organización en su página
settings-profile-public-desc-part2 = y para las aplicaciones a las que concede el ámbito
settings-profile-public-desc-part3 = o
settings-profile-public-desc-part4 = de OAuth. Deje cualquier campo en blanco para ocultarlo.

# settings_profile.html - sugerencia de enlaces (code: Label|https://url)
settings-profile-links-hint-part1 = Uno por línea, en el formato
settings-profile-links-hint-part2 = .

# Mensajes flash y cuerpos de error en línea establecidos en los handlers de Rust.
flash-session-signed-out = Sesión cerrada.
flash-session-signout-failed = No se pudo cerrar esa sesión.
flash-sessions-signed-out-others =
    { $count ->
        [one] Se cerró { $count } otra sesión.
       *[other] Se cerraron { $count } otras sesiones.
    }
flash-sessions-signout-others-failed = No se pudieron cerrar las otras sesiones.
flash-app-access-revoked = Acceso revocado.
flash-app-access-revoke-failed = No se pudo revocar el acceso para esa aplicación.
flash-offline-passphrase-saved = Frase de contraseña sin conexión guardada. Los hosts inscritos la adoptarán en su próxima sincronización.
flash-offline-passphrase-save-failed = No se pudo guardar su frase de contraseña sin conexión. Inténtelo de nuevo.
flash-offline-passphrase-too-short = Su frase de contraseña sin conexión debe tener al menos { $min_len } caracteres.
flash-offline-passphrase-removed = Frase de contraseña sin conexión eliminada. Los hosts la descartarán en su próxima sincronización.
flash-offline-passphrase-none = No tiene establecida ninguna frase de contraseña sin conexión.
flash-offline-passphrase-remove-failed = No se pudo eliminar su frase de contraseña sin conexión. Inténtelo de nuevo.
settings-profile-url-invalid = El sitio web y la URL del avatar deben ser URLs http:// o https:// válidas.
settings-profile-link-url-invalid = La URL de cada enlace debe ser una URL http:// o https:// válida.
settings-save-failed = No pudimos guardar sus cambios. Inténtelo de nuevo.
