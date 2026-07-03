# Página de error
error-reference-id = ID de referencia:
error-cta-back-to-sign-in = Volver al inicio de sesión

# Confirmación de cierre de sesión de OAuth
logout-card-title = ¿Cerrar sesión en todas las aplicaciones?
logout-card-subtitle = Esto finalizará su sesión con { $brand } y notificará a todas las aplicaciones en las que inició sesión.
logout-body-text = Se informará a la aplicación que le pidió cerrar sesión de que la solicitud se ha completado. Algunas aplicaciones pueden conservar datos en caché durante un breve tiempo; cerrar sesión aquí finaliza la sesión en { $brand }.
logout-action-sign-out = Cerrar sesión
logout-action-cancel = Cancelar

# Títulos y textos de los diálogos de administración usados por render_admin_error en los puntos de llamada que tienen una configuración regional.
# Los puntos de llamada sin configuración regional (funciones auxiliares, límites de error) conservan sus literales en inglés.
dialog-identity-unavailable-title = Identidad no disponible
dialog-identity-unavailable-body = No pudimos cargar esa identidad. Es posible que se haya eliminado.
dialog-recovery-code-failed-title = Error en el código de recuperación
dialog-recovery-code-failed-body = Generamos el código de recuperación, pero no pudimos prepararlo para mostrarlo una sola vez. Genere un código nuevo para volver a intentarlo.
dialog-disable-failed-title = Error al desactivar
dialog-enable-failed-title = Error al activar
dialog-delete-failed-title = Error al eliminar
dialog-revoke-failed-title = Error al revocar

# Límite de error (error_boundary.html), título/texto/CTA establecidos en los controladores de Rust.
error-boundary-auth-unavailable-title = Autenticación no disponible
error-boundary-auth-unavailable-body = No pudimos contactar con el servicio de autenticación. Vuelva a intentarlo en un momento.
error-boundary-cta-try-again = Volver a intentarlo
error-boundary-cta-sign-in = Iniciar sesión
error-boundary-cta-back-to-settings = Volver a la configuración
error-boundary-cta-back-to-dashboard = Volver al panel
error-boundary-cta-back-to-account = Volver a la cuenta
error-boundary-signin-title = Inicio de sesión no disponible
error-boundary-signup-title = Registro no disponible
error-boundary-recovery-title = Recuperación no disponible
error-boundary-verification-title = Verificación no disponible
error-boundary-settings-title = Configuración no disponible
error-boundary-logout-title = Cierre de sesión no disponible
error-boundary-logout-body = No pudimos completar su cierre de sesión porque el servicio de autenticación no está disponible. Su sesión sigue activa, así que vuelva a intentarlo en un momento.
error-boundary-sessions-title = Sesiones no disponibles
error-boundary-sessions-body = No pudimos enumerar sus sesiones activas. Vuelva a intentarlo en un momento.
error-boundary-authorized-apps-title = Aplicaciones autorizadas no disponibles
error-boundary-authorized-apps-no-session-body = No pudimos leer su sesión. Inicie sesión de nuevo.
error-boundary-authorized-apps-service-body = No pudimos contactar con el servicio de OAuth. Vuelva a intentarlo en un momento.
error-boundary-account-deletion-title = Error al eliminar la cuenta
error-boundary-account-delete-bad-session = Su sesión se encuentra en un estado inesperado. Inicie sesión de nuevo y vuelva a intentarlo.
error-boundary-account-delete-sole-owner = Usted es el único propietario de { $names }. Transfiera la propiedad a otro miembro antes de eliminar su cuenta.
error-boundary-account-delete-ownership-check-failed = No pudimos verificar la propiedad de su organización. No se cambió nada; vuelva a intentarlo en un momento.
error-boundary-account-delete-consent-unreachable = No pudimos contactar con el servicio de consentimiento para notificar a sus aplicaciones conectadas. No se cambió nada; vuelva a intentarlo en un momento.
error-boundary-account-delete-notifications-failed = No pudimos preparar las notificaciones de eliminación. No se cambió nada; vuelva a intentarlo.
error-boundary-account-delete-failed = No pudimos eliminar su cuenta. Vuelva a intentarlo en un momento.

# Límite de error de SAML (se renderiza con la configuración regional predeterminada; la devolución de llamada ACS no lleva la configuración regional de la solicitud).
error-boundary-sso-unavailable-title = Inicio de sesión único no disponible
error-boundary-sso-unavailable-body = El inicio de sesión único no está disponible para esta dirección. Compruebe el enlace que le dio su administrador o inicie sesión con su método habitual.
error-boundary-sso-failed-title = Error en el inicio de sesión único
error-boundary-sso-validation-failed-body = No se pudo validar este intento de inicio de sesión. Comience de nuevo desde el enlace de SSO de su organización.
error-boundary-sso-upstream-failed-body = El servicio de inicio de sesión no está disponible temporalmente. Vuelva a intentarlo.
error-boundary-sso-no-email-body = El proveedor de identidad no proporcionó una dirección de correo electrónico. Pida a su administrador que asigne el atributo de correo electrónico en la conexión SAML.

# Página de error de autoservicio de Kratos (error.html), alternativas establecidas en Rust.
error-page-generic-title = Algo salió mal
error-page-generic-body = No pudimos cargar la página solicitada. Es posible que el enlace haya caducado o ya se haya utilizado.
error-page-link-expired-title = Enlace caducado
error-page-link-expired-body = Este enlace ya no es válido. Comience de nuevo desde el inicio de sesión.
error-page-security-title = Error en la comprobación de seguridad
error-page-already-signed-in-title = Ya inició sesión
error-page-default-message = No pudimos completar esa solicitud.

# Página de acceso denegado del control de administración (admin/forbidden.html), establecida en Rust.
error-admin-access-denied-title = Acceso denegado
error-admin-access-denied-body = Su cuenta no está autorizada para usar las herramientas de administración.
error-admin-access-denied-forseti-body = Su cuenta no está autorizada para usar las herramientas de administración de todo Forseti.
error-admin-access-denied-org-body = No tiene acceso de administración a esa organización.

# SAML bloqueado
error-saml-blocked-page-title = Inicio de sesión bloqueado
error-saml-blocked-card-title = No pudimos iniciar su sesión
error-saml-unverified-prefix = Ya existe una cuenta para
error-saml-unverified-suffix = pero su dirección de correo electrónico no se ha verificado, por lo que el inicio de sesión único no puede vincularse a ella de forma segura. Verifique la dirección desde el correo original de su registro o pida ayuda a su administrador.
error-saml-cross-org-not-member = Su cuenta aún no es miembro de esta organización. Pida a su administrador que lo agregue y luego vuelva a intentarlo.
error-saml-conflict = No pudimos iniciar su sesión. Póngase en contacto con su administrador.
error-saml-blocked-cta = Ir al inicio de sesión
