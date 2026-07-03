# Banner de administración (admin_shell.html)
admin-banner-label = ADMINISTRACIÓN
admin-banner-body = Se encuentra en una superficie con privilegios. Todas las acciones aquí quedan registradas en la auditoría.

# Encabezado de la barra lateral de navegación de administración (admin_nav.html)
admin-nav-heading = Administración
admin-nav-subtitle = Herramientas de operador

# Encabezados de sección de la navegación de administración
admin-nav-section-system = Sistema
admin-nav-section-access = Acceso
admin-nav-section-linux = Linux

# Etiquetas de los elementos de navegación de administración
admin-nav-status = Estado
admin-nav-configuration = Configuración
admin-nav-audit = Auditoría
admin-nav-webhooks = Webhooks
admin-nav-license = Licencia
admin-nav-identities = Identidades
admin-nav-sessions = Sesiones
admin-nav-clients = Clientes OAuth2
admin-nav-dcr-tokens = Tokens DCR
admin-nav-saml = SSO SAML
admin-nav-hosts = Hosts
admin-nav-accounts = Cuentas

# Lista de identidades (identities_list.html)
admin-identities-page-title = Identidades
admin-identities-subtitle = Identidades gestionadas por Kratos y su estado.
admin-identities-search-placeholder = Buscar por ID o correo electrónico
admin-identities-search-button = Buscar
admin-identities-col-email = Correo electrónico
admin-identities-col-state = Estado
admin-identities-col-created = Creada
admin-identities-empty = No se encontraron identidades.
admin-identities-prev = Volver al inicio
admin-identities-next = Página siguiente

# Detalle de identidad (identity_show.html)
admin-identity-status-active = activa
admin-identity-recovery-code-heading = Código de recuperación (mostrado una sola vez)
admin-identity-recovery-link-heading = Enlace de recuperación
admin-identity-recovery-note = Compártalo con el usuario a través de un canal de confianza. No se volverá a mostrar.
admin-identity-section-actions = Acciones
admin-identity-action-generate-recovery = Generar código de recuperación
admin-identity-action-disable = Desactivar
admin-identity-action-enable = Activar
admin-identity-action-delete = Eliminar
admin-identity-section-traits = Traits
admin-identity-section-addresses = Direcciones verificables
admin-identity-addresses-empty = Esta identidad no tiene direcciones verificables.
admin-identity-status-verified = verificada
admin-identity-status-pending = pendiente
admin-identity-section-credentials = Credenciales
admin-identity-credentials-empty = No hay credenciales configuradas.
admin-identity-section-sessions = Sesiones recientes
admin-identity-sessions-empty = Sin historial de sesiones.
admin-identity-action-revoke-session = Revocar sesión

# Selector de identidad (identity_picker.html)
admin-identity-picker-page-title = Seleccionar usuario
admin-identity-picker-subtitle = Elija una identidad para continuar.
admin-identity-picker-invalid-return = Destino de retorno no válido.
admin-identity-picker-search-placeholder = Buscar por ID o correo electrónico
admin-identity-picker-search-button = Buscar
admin-identity-picker-col-email = Correo electrónico
admin-identity-picker-col-state = Estado
admin-identity-picker-col-created = Creada
admin-identity-picker-empty = No se encontraron identidades.
admin-identity-picker-action-select = Seleccionar
admin-identity-picker-prev = Volver al inicio
admin-identity-picker-next = Página siguiente

# Lista de sesiones (sessions_list.html)
admin-sessions-page-title = Sesiones
admin-sessions-subtitle = Todas las sesiones conocidas por Kratos, en todas las identidades.
admin-sessions-filter-active-only = Solo sesiones activas
admin-sessions-col-identity = Identidad
admin-sessions-col-authenticated = Autenticada
admin-sessions-col-expires = Expira
admin-sessions-col-device = Dispositivo
admin-sessions-empty = No hay sesiones para mostrar.
admin-sessions-action-revoke = Revocar
admin-sessions-prev = Volver al inicio
admin-sessions-next = Página siguiente

# Diálogo de confirmación genérico (confirm.html)
admin-confirm-cancel = Cancelar

# Página de acceso denegado (forbidden.html)
admin-forbidden-back = Volver al panel

# Página de error de administración (error.html)
admin-error-back = Volver al estado de administración

# Lista de clientes (clients_list.html)
admin-clients-page-title = Clientes OAuth2
admin-clients-subtitle = Partes confiantes registradas en Hydra.
admin-clients-action-new = Nuevo cliente
admin-clients-search-placeholder = Buscar por nombre o ID de cliente
admin-clients-filter-all-types = Todos los tipos
admin-clients-filter-all-verifications = Todos los estados de verificación
admin-clients-filter-verified = Verificados
admin-clients-filter-unverified = No verificados
admin-clients-search-button = Buscar
admin-clients-col-name = Nombre
admin-clients-col-type = Tipo
admin-clients-col-grants = Concesiones
admin-clients-col-created = Creado
admin-clients-badge-unverified-title = No revisado por un administrador
admin-clients-badge-self-registered = Autorregistrado
admin-clients-badge-self-registered-title = Registrado mediante /oauth2/register (RFC 7591)
admin-clients-empty = No hay clientes registrados.
admin-clients-prev = Volver al inicio
admin-clients-next = Página siguiente

# Insignias compartidas de cliente (clients_list.html, client_show.html)
admin-client-badge-verified = Verificado
admin-client-badge-unverified = No verificado
admin-client-badge-unverified-title = Un administrador no ha revisado este cliente. La pantalla de consentimiento advierte a los usuarios finales.

# Encabezados de página del formulario de cliente (client_form.html)
admin-client-form-title-new = Nuevo cliente
admin-client-form-title-edit = Editar cliente
admin-client-form-heading-new = Nuevo cliente OAuth2
admin-client-form-heading-edit = Editar cliente
admin-client-form-preset-note = Los valores predeterminados para este tipo ya están rellenados.
admin-client-form-preset-change = Cambiar tipo

# Campos de formulario compartidos (client_form.html, formulario de edición de client_show.html)
admin-client-field-name = Nombre del cliente
admin-client-field-grant-types = Tipos de concesión
admin-client-grant-auth-code-hint = (inicio de sesión iniciado por el usuario)
admin-client-grant-refresh-hint = (sesiones de larga duración)
admin-client-grant-client-creds-hint = (servicio a servicio)
admin-client-field-response-types = Tipos de respuesta
admin-client-field-scope = Scope
admin-client-field-scope-hint = Scopes OAuth2 separados por espacios.
admin-client-field-redirect-uris = URI de redirección
admin-client-field-redirect-uris-hint = Una por línea (o separadas por comas).
admin-client-field-post-logout-uris = URI de redirección posteriores al cierre de sesión
admin-client-section-logout-fanout = Propagación de cierre de sesión OIDC
admin-client-section-logout-fanout-desc = Cuando el usuario finaliza su sesión a través de Forseti, Hydra notifica a los clientes en estas URI para que cada aplicación pueda borrar su sesión local. Deje en blanco para excluir a este cliente de la propagación.
admin-client-field-backchannel-uri = URI de cierre de sesión back-channel
admin-client-field-backchannel-uri-hint = Hydra envía por POST un token de cierre de sesión firmado a esta dirección (servidor a servidor). Normalmente solo tiene sentido para aplicaciones web renderizadas en el servidor y BFF.
admin-client-field-backchannel-sid-prefix = Requerir el claim
admin-client-field-backchannel-sid-suffix = en el token de cierre de sesión back-channel
admin-client-field-backchannel-sid-short = claim requerido
admin-client-field-frontchannel-uri = URI de cierre de sesión front-channel
admin-client-field-frontchannel-uri-hint = Hydra carga esta URL en un iframe durante el cierre de sesión para que cada aplicación pueda borrar sus cookies de sesión en el navegador.
admin-client-field-frontchannel-sid-prefix = Requerir los parámetros de consulta
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = en el cierre de sesión front-channel
admin-client-field-frontchannel-sid-short = parámetros de consulta requeridos
admin-client-field-token-auth = Método de autenticación del endpoint de token
admin-client-token-auth-post-hint = (secreto en el cuerpo del POST)
admin-client-token-auth-basic-hint = (secreto en el encabezado Authorization)
admin-client-token-auth-none-hint = (cliente público, PKCE)
admin-client-token-auth-none-short = none (público + PKCE)
admin-client-field-audience = Lista de permitidos de audiencia
admin-client-field-audience-hint-short = Una por línea. Hydra exige que los valores de audiencia se registren aquí previamente.
admin-client-field-require-pkce = Requerir PKCE (informativo)
admin-client-field-skip-consent = Cliente de confianza (omitir pantalla de consentimiento)
admin-client-field-webhook-url = URL del webhook de eliminación de cuenta
admin-client-action-cancel = Cancelar

# Página de detalle del cliente (client_show.html)
admin-client-action-revoke-verification = Revocar verificación
admin-client-action-mark-verified = Marcar como verificado
admin-client-action-rotate-secret = Rotar secreto
admin-client-action-delete = Eliminar
admin-client-credentials-heading = Credenciales: mostradas una sola vez
admin-client-credentials-note = Cópielas ahora. No se volverán a mostrar; recargue para descartarlas. El ID de cliente y los endpoints de arriba no son secretos y permanecen visibles.
admin-client-credentials-secret-label = Secreto del cliente
admin-client-credentials-rat-label = Token de acceso de registro
admin-client-credentials-rat-note = Según RFC 7592: permite al cliente gestionar su propio registro (leer/actualizar/eliminar) a través de la API de registro dinámico de clientes de Hydra. No se puede volver a emitir, así que, en caso de duda, consérvelo.
admin-client-undoc-scopes-heading = Scopes no documentados
admin-client-section-connection = Detalles de conexión
admin-client-connection-intro = Pegue estos valores en la configuración del cliente OIDC/OAuth del lado de la aplicación.
admin-client-conn-client-id = ID de cliente
admin-client-conn-issuer = Emisor
admin-client-conn-discovery-url = URL de descubrimiento
admin-client-conn-auth-endpoint = Endpoint de autorización
admin-client-conn-token-endpoint = Endpoint de token
admin-client-conn-userinfo-endpoint = Endpoint de userinfo
admin-client-conn-jwks-uri = URI de JWKS
admin-client-conn-end-session-endpoint = Endpoint de fin de sesión
admin-client-section-config = Configuración
admin-client-config-sid-required = (sid requerido)
admin-client-config-iss-sid-required = (iss+sid requeridos)
admin-client-not-configured = no configurado
admin-client-audience-none = ninguna
admin-client-config-token-auth = Autenticación del endpoint de token
admin-client-config-require-pkce = Requerir PKCE
admin-client-bool-yes = sí
admin-client-bool-no = no
admin-client-config-trusted = De confianza (omitir consentimiento)
admin-client-config-created = Creado
admin-client-config-provenance-audience = Audiencia
admin-client-config-provenance-audience-note = (declarada por el llamador DCR)
admin-client-config-provenance-url = Usado en
admin-client-config-provenance-url-note = (observado por primera vez en el consentimiento)
admin-client-config-webhook = Webhook de eliminación de cuenta
admin-client-section-edit = Editar
admin-client-action-save = Guardar cambios
admin-client-action-back = Volver a la lista

# Selector de tipo de cliente (client_type_picker.html)
admin-client-type-page-title = Nuevo cliente
admin-client-type-heading = Nuevo cliente OAuth2
admin-client-type-subtitle = Elija el tipo de aplicación. La página siguiente es el mismo formulario, con los valores predeterminados correctos ya rellenados, para que no llegue por accidente a una combinación inválida.
admin-client-type-popular-heading = Aplicaciones conocidas
admin-client-type-action-cancel = Cancelar

# Lista de tokens DCR (dcr_tokens_list.html)
admin-dcr-page-title = Tokens de acceso inicial DCR
admin-dcr-action-issue = Emitir token
admin-dcr-token-revealed-heading = Token de acceso inicial (mostrado una sola vez)
admin-dcr-col-status = Estado
admin-dcr-col-note = Nota
admin-dcr-col-created-by = Creado por
admin-dcr-col-created = Creado
admin-dcr-col-expires = Expira
admin-dcr-col-uses-left = Usos restantes
admin-dcr-status-active = Activo
admin-dcr-status-revoked = Revocado
admin-dcr-status-expired = Expirado
admin-dcr-status-exhausted = Agotado
admin-dcr-empty-prefix = No se han emitido tokens.
admin-dcr-empty-link = Emitir uno
admin-dcr-empty-suffix = para habilitar el autorregistro.
admin-dcr-action-revoke = Revocar

# Nuevo token DCR (dcr_token_new.html)
admin-dcr-new-page-title = Emitir token DCR
admin-dcr-new-heading = Emitir un token de acceso inicial DCR
admin-dcr-new-field-note = Nota
admin-dcr-new-field-note-placeholder = ¿Para qué es este token? (p. ej. 'Claude Desktop para formshive')
admin-dcr-new-field-note-hint = Opcional, solo para sus registros. El autor del cliente nunca lo ve.
admin-dcr-new-field-ttl = TTL (horas)
admin-dcr-new-field-ttl-hint = Deje en blanco para que no caduque.
admin-dcr-new-field-max-uses = Usos máximos
admin-dcr-new-action-cancel = Cancelar

# Página de estado (status.html)
admin-status-page-title = Estado
admin-status-heading = Estado del sistema
admin-status-subtitle = Estado en tiempo real de los componentes del IdP, la cola de Courier y las versiones de compilación.
admin-status-issuer-label = Emisor
admin-status-issuer-config-link = Ver configuración →
admin-status-warning-db-label = Base de datos
admin-status-warning-db-body = sqlite con una implementación de aspecto productivo. Las configuraciones multiinstancia corromperán la base de datos. Cambie a Postgres para alta disponibilidad.
admin-status-warning-webhook-label = Propagación de webhooks
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } fila de webhook de eliminación de cuenta fallida
       *[other] { $count } filas de webhook de eliminación de cuenta fallidas
    }
admin-status-dead-webhook-middle = (los receptores no están siendo notificados).
admin-status-dead-webhook-open = Abrir /admin/webhooks
admin-status-dead-webhook-action = para reencolarlas o descartarlas.
admin-status-section-services = Servicios
admin-status-col-service = Servicio
admin-status-col-state = Estado
admin-status-col-detail = Detalle
admin-status-state-up = activo
admin-status-state-down = inactivo
admin-status-section-courier = Cola de Courier
admin-status-courier-pending = Pendientes (en cola)
admin-status-courier-failed = Fallidos (abandonados)
admin-status-courier-last-webhook = Último webhook de auditoría
admin-status-courier-never = nunca
admin-status-section-audit = Auditoría
admin-status-audit-write-failures = Errores de escritura de auditoría (desde el arranque)
admin-status-audit-write-failures-note-prefix = Las filas se pueden recuperar de las líneas estructuradas
admin-status-audit-write-failures-note-suffix = de stderr que Forseti emitió en el momento del error.
admin-status-audit-webhook-rejected = Webhooks de auditoría rechazados (desde el arranque)
admin-status-audit-webhook-rejected-note-prefix = Payloads malformados o acciones desconocidas, probablemente una discrepancia de hook/configuración de Kratos. Revise los
admin-status-audit-webhook-rejected-note-suffix = registros de advertencia.
admin-status-audit-freshness = Anomalías de frescura de webhooks de auditoría (desde el arranque)
admin-status-audit-freshness-note = Payloads marcados como obsoletos o con fecha futura, normalmente por un flujo lento o desfase de reloj. Las filas se siguen registrando y marcando.
admin-status-section-license = Licencia
admin-status-license-oss-prefix = Implementación de nivel OSS.
admin-status-license-oss-link = Active una licencia
admin-status-license-oss-suffix = para desbloquear las funciones premium.
admin-status-section-build = Versiones de compilación
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = Base de datos

# Página de configuración (configuration.html)
admin-config-page-title = Configuración
admin-config-subtitle = Cómo está configurado este proveedor de identidad: endpoints y capacidades OIDC, claves de firma y esquemas de identidad de Kratos.
admin-config-discovery-warning-label = Descubrimiento OIDC
admin-config-discovery-warning-body = No se pudo acceder al documento de descubrimiento de Hydra. Los endpoints y las capacidades permanecen ocultos hasta que vuelva a estar accesible.
admin-config-section-oidc = Endpoints OIDC
admin-config-field-issuer = Emisor
admin-config-field-discovery-url = URL de descubrimiento
admin-config-field-authorization = Autorización
admin-config-field-token = Token
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = Fin de sesión
admin-config-field-registration = Registro (DCR)
admin-config-field-revocation = Revocación
admin-config-section-capabilities = Capacidades
admin-config-cap-scopes = Scopes
admin-config-cap-grant-types = Tipos de concesión
admin-config-cap-response-types = Tipos de respuesta
admin-config-cap-token-auth-methods = Métodos de autenticación del endpoint de token
admin-config-cap-pkce-methods = Métodos PKCE
admin-config-cap-id-token-signing-algs = Algoritmos de firma del token de ID
admin-config-cap-subject-types = Tipos de sujeto
admin-config-cap-backchannel-logout = Cierre de sesión back-channel
admin-config-cap-frontchannel-logout = Cierre de sesión front-channel
admin-config-cap-yes = Sí
admin-config-cap-no = No
admin-config-section-signing-keys = Claves de firma (JWKS)
admin-config-signing-keys-unavailable = No disponible: no se pudieron obtener las claves públicas de Hydra.
admin-config-signing-keys-empty = Hydra no anunció ninguna clave de firma.
admin-config-col-key-id = ID de clave
admin-config-col-alg = Alg
admin-config-col-type = Tipo
admin-config-col-use = Uso
admin-config-section-schemas = Esquemas de identidad de Kratos
admin-config-schemas-unavailable = No disponible: no se pudieron obtener los esquemas de identidad de Kratos.
admin-config-schemas-empty = No hay esquemas de identidad registrados.

# Lista de auditoría (audit.html)
admin-audit-page-title = Auditoría
admin-audit-subtitle = Registro de eventos de solo anexado. Registra las acciones de administración del lado de Forseti, las concesiones OAuth, los cambios de sesión y las finalizaciones de flujos de Kratos entregadas por webhook. La retención la configura el operador (`[audit].audit_retention_days`); la depuración es un subcomando de CLI, no automática.
admin-audit-filter-email = El correo electrónico contiene
admin-audit-filter-action = Prefijo de acción
admin-audit-filter-severity = Gravedad
admin-audit-filter-since = Desde
admin-audit-severity-any = Cualquiera
admin-audit-severity-info = Info
admin-audit-severity-warning = Advertencia
admin-audit-severity-error = Error
admin-audit-severity-critical = Crítico
admin-audit-filter-button = Filtrar
admin-audit-col-target = Objetivo
admin-audit-col-severity = Gravedad
admin-audit-col-when = Cuándo
admin-audit-col-actor = Actor
admin-audit-col-action = Acción
admin-audit-col-actions = Acciones
admin-audit-empty = Ningún evento coincide con los filtros actuales.
admin-audit-badge-critical = crítico
admin-audit-badge-error = error
admin-audit-badge-warning = advertencia
admin-audit-action-view = Ver
admin-audit-prev = ‹ Anterior
admin-audit-next = Siguiente ›

# Detalle de auditoría (audit_show.html)
admin-audit-back = ← Volver a la auditoría
admin-audit-show-section-event = Evento
admin-audit-show-outcome = Resultado
admin-audit-show-success = éxito
admin-audit-show-failure = fallo
admin-audit-show-section-actor = Actor
admin-audit-show-field-kind = Tipo
admin-audit-show-field-email = Correo electrónico
admin-audit-show-none = ninguno
admin-audit-show-field-identity-id = ID de identidad
admin-audit-show-section-target = Objetivo
admin-audit-show-field-label = Etiqueta
admin-audit-show-deleted = (eliminado)
admin-audit-show-field-target-id = ID del objetivo
admin-audit-show-section-metadata = Metadatos
admin-audit-show-section-request-context = Contexto de la solicitud
admin-audit-show-field-ip-hash = Hash de IP
admin-audit-show-field-user-agent = Agente de usuario
admin-audit-show-field-request-id = ID de solicitud
admin-audit-show-field-org-id = ID de organización

# Lista de webhooks (webhooks.html)
admin-webhooks-page-title = Webhooks
admin-webhooks-heading = Webhooks fallidos
admin-webhooks-subtitle = Notificaciones de eliminación de cuenta que agotaron los reintentos (12 intentos o 72 horas, lo que ocurra primero). Haga clic en una fila para ver el payload completo y el último error, o reencólela desde el resumen si sabe que el receptor vuelve a estar operativo.
admin-webhooks-empty = No hay filas fallidas. Todo se está entregando.
admin-webhooks-col-client = Cliente
admin-webhooks-col-event = Evento
admin-webhooks-col-attempts = Intentos
admin-webhooks-col-age = Antigüedad
admin-webhooks-col-actions = Acciones
admin-webhooks-deleted = (eliminado)
admin-webhooks-action-view = Ver
admin-webhooks-action-requeue = Reencolar

# Detalle de webhook (webhook_show.html)
admin-webhook-back = ← Volver a webhooks
admin-webhook-heading = Webhook fallido
admin-webhook-action-requeue = Reencolar
admin-webhook-action-discard = Descartar
admin-webhook-section-delivery = Entrega
admin-webhook-field-client = Cliente
admin-webhook-deleted = (eliminado)
admin-webhook-field-state = Estado
admin-webhook-field-url = URL
admin-webhook-field-attempts = Intentos
admin-webhook-field-created = Creado
admin-webhook-field-next-attempt = Próximo intento
admin-webhook-section-last-error = Último error
admin-webhook-section-payload = Payload firmado

# Lista de cuentas POSIX (posix_list.html)
admin-posix-page-title = Cuentas POSIX
admin-posix-subtitle = Identidades de Kratos materializadas en cuentas Linux (uid/gid + claves SSH) para el resolutor NSS.
admin-posix-seats-label = Plazas en uso:
admin-posix-license-note = Una licencia comercial de autenticación Linux aumenta el límite.
admin-posix-action-provision = Aprovisionar cuenta
admin-posix-col-username = Nombre de usuario
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Estado
admin-posix-col-created = Creada
admin-posix-empty-prefix = No hay cuentas POSIX activas.
admin-posix-empty-link = Aprovisionar una
admin-posix-empty-suffix = a partir de una identidad de Kratos.
admin-posix-status-enabled = activada
admin-posix-status-disabled = desactivada
admin-posix-action-manage = Gestionar

# Detalle de cuenta POSIX (posix_account.html)
admin-posix-action-disable = Desactivar
admin-posix-action-enable = Activar
admin-posix-action-delete = Eliminar
admin-posix-ssh-keys-heading = Claves SSH
admin-posix-ssh-empty = Aún no hay claves SSH.
admin-posix-ssh-key-added-prefix = añadida
admin-posix-ssh-action-remove = Eliminar
admin-posix-ssh-field-public-key = Clave pública
admin-posix-ssh-field-comment = Comentario (opcional)
admin-posix-ssh-action-add = Añadir clave
admin-posix-teams-heading = Equipos
admin-posix-hosts-heading = Hosts accesibles
admin-posix-back = ← Todas las cuentas POSIX

# Nueva cuenta POSIX (posix_new.html)
admin-posix-new-page-title = Aprovisionar cuenta POSIX
admin-posix-new-heading = Aprovisionar una cuenta POSIX
admin-posix-new-choose-identity = Elija la identidad que se va a aprovisionar.
admin-posix-new-action-select-user = Seleccionar usuario
admin-posix-new-or-enter-directly = O introdúzcala directamente
admin-posix-new-placeholder-id = UUID o correo electrónico
admin-posix-new-action-continue = Continuar
admin-posix-new-provision-intro = Materialice una identidad de Kratos en una cuenta Linux. Se asigna automáticamente un uid/gid y se crea un grupo primario.
admin-posix-new-selected-prefix = Seleccionada:
admin-posix-new-action-change = Cambiar
admin-posix-new-field-username = Nombre de usuario
admin-posix-new-username-hint = Sugerido a partir del correo electrónico; edítelo si lo desea. 1–32 caracteres, minúsculas, empezando por una letra o guion bajo. Este será el nombre de inicio de sesión POSIX.
admin-posix-new-field-shell = Shell de inicio de sesión
admin-posix-new-action-cancel = Cancelar

# Lista de hosts (hosts_list.html)
admin-hosts-page-title = Hosts
admin-hosts-subtitle = Máquinas Linux inscritas en el resolutor POSIX/NSS de Forseti. Cada host se autentica con un secreto de un solo uso que se revela durante la inscripción.
admin-hosts-action-enroll = Inscribir host
admin-hosts-credential-heading = Credencial del host (mostrada una sola vez)
admin-hosts-credential-note-prefix = El formato es
admin-hosts-credential-note-suffix = . Configure ahora el agente del host con esta credencial. No almacenamos el secreto en bruto, solo su SHA-256.
admin-hosts-col-hostname = Nombre de host
admin-hosts-col-teams = Equipos
admin-hosts-col-force-mfa = Forzar MFA
admin-hosts-col-enrolled = Inscrito
admin-hosts-col-last-seen = Visto por última vez
admin-hosts-empty-prefix = No hay hosts inscritos.
admin-hosts-empty-link = Inscribir uno
admin-hosts-empty-suffix = para que pueda resolver cuentas POSIX.
admin-hosts-status-mfa-pending = MFA (pendiente)
admin-hosts-mfa-pending-title = Registrado pero aún no aplicado; la aplicación llega con el inicio de sesión interactivo (PAM).
admin-hosts-action-edit = Editar
admin-hosts-action-rotate = Rotar
admin-hosts-action-revoke = Revocar

# Editar host (hosts_edit.html)
admin-hosts-edit-page-title = Editar host
admin-hosts-edit-intro = Actualice la etiqueta del host, su indicador de MFA y los equipos a los que está restringido. El secreto no se muestra aquí; rótelo desde la lista de hosts si necesita uno nuevo.
admin-hosts-field-hostname = Nombre de host
admin-hosts-hostname-hint = Una etiqueta para sus registros. No tiene que coincidir con el nombre de host real de la máquina.
admin-hosts-field-org = Organización
admin-hosts-org-fixed-note = La organización de un host se fija en la inscripción y no se puede cambiar aquí.
admin-hosts-field-allowed-teams = Equipos permitidos
admin-hosts-teams-empty = Aún no existen equipos. Este host permite a cualquier miembro de la organización. Restringir un host a equipos específicos requiere la función de Organizaciones.
admin-hosts-teams-hint = Restrinja este host a los miembros de los equipos seleccionados. No seleccione ninguno para permitir a cualquier miembro de la organización.
admin-hosts-field-force-mfa = Forzar MFA en este host
admin-hosts-force-mfa-hint = Registrado ahora; se aplicará cuando llegue el inicio de sesión interactivo (PAM).
admin-hosts-action-cancel = Cancelar

# Nuevo host (hosts_new.html)
admin-hosts-new-heading = Inscribir un host Linux
admin-hosts-new-intro-prefix = En la página siguiente se revela una sola vez un secreto de un solo uso. Configure el agente del host con la credencial
admin-hosts-new-intro-suffix = que muestra.
admin-hosts-org-belongs-hint = El host pertenece a esta organización. Fijado tras la inscripción.
admin-hosts-new-teams-empty = Aún no existen equipos. Este host permitirá a cualquier miembro de la organización. Restringir un host a equipos específicos requiere la función de Organizaciones.
admin-hosts-new-teams-scope-hint = Restrinja este host a los miembros de los equipos seleccionados. Solo se aplican los equipos de la organización elegida; no seleccione ninguno para permitir a cualquier miembro de la organización.

# Lista de SSO SAML (saml_list.html)
admin-saml-page-title = SSO SAML
admin-saml-subtitle = Conexiones SAML empresariales, una por organización. Los metadatos y certificados del IdP residen en Jackson; Forseti conserva la fila ancla y el interruptor de activación.
admin-saml-action-new = Nueva conexión
admin-saml-grace-notice = Licencia en periodo de gracia. Las conexiones SAML son de solo lectura hasta que se renueve la licencia. Los inicios de sesión SSO siguen funcionando.
admin-saml-col-org = Organización
admin-saml-col-connection = Conexión
admin-saml-col-sso-url = URL de SSO
admin-saml-col-enabled = Activada
admin-saml-empty-prefix = Aún no hay conexiones SAML.
admin-saml-empty-link = Crear una
admin-saml-empty-suffix = para habilitar el SSO en una organización.
admin-saml-status-enabled = Activada
admin-saml-status-disabled = Desactivada
admin-saml-action-disable = Desactivar
admin-saml-action-enable = Activar
admin-saml-action-delete = Eliminar
admin-saml-idp-values-heading = Valores para el administrador del IdP del cliente
admin-saml-idp-values-intro = Entregue estos valores a quien configure la aplicación SAML del lado del proveedor de identidad. Son los mismos para cada conexión.
admin-saml-idp-acs-url = URL de ACS
admin-saml-idp-entity-id = ID de entidad del SP

# Paginación de auditoría
admin-audit-range = Mostrando { $from }–{ $to } de { $total } filas.
admin-audit-page = Página { $page }
admin-saml-entity-id-note-prefix = El ID de entidad sigue el ajuste
admin-saml-entity-id-note-suffix = de Jackson; cámbielo allí si anula el valor predeterminado.

# Nueva conexión SSO SAML (saml_new.html)
admin-saml-new-page-title = Nueva conexión SAML
admin-saml-new-intro = Conecte una organización con su proveedor de identidad. Pegue el XML de metadatos del IdP, o indique una URL de metadatos que Jackson obtiene por sí mismo: exactamente una de las dos opciones.
admin-saml-new-field-org = Organización
admin-saml-new-org-hint = Una conexión por organización.
admin-saml-new-field-name = Nombre de la conexión
admin-saml-new-name-hint = Solo para sus registros; los miembros nunca lo ven.
admin-saml-new-field-metadata-url = URL de metadatos
admin-saml-new-metadata-url-hint = Deje en blanco al pegar el XML en bruto abajo.
admin-saml-new-metadata-url-https-note = Jackson solo obtiene URL de metadatos HTTPS (o localhost). Para metadatos de IdP en HTTP plano, pegue el XML abajo en su lugar.
admin-saml-new-field-metadata-xml = XML de metadatos
admin-saml-new-metadata-xml-hint = Deje en blanco al usar una URL de metadatos arriba.
admin-saml-new-action-create = Crear conexión
admin-saml-new-action-cancel = Cancelar

# Divisiones de código en línea (punto 8: 2+ elementos de código por cadena)

# client_form.html - sugerencia de tipos de respuesta (code: code, token)
admin-client-field-response-types-hint-part1 = Separados por comas, p. ej.
admin-client-field-response-types-hint-part2 = (código de autorización) o
admin-client-field-response-types-hint-part3 = (client credentials).

# client_form.html - sugerencia de audiencia (code: audience=<value>)
admin-client-field-audience-hint-part1 = Una por línea. Hydra exige que los valores de audiencia se registren aquí previamente (aún no admite RFC 8707). Los clientes pasan
admin-client-field-audience-hint-part2 = en la solicitud de autorización.

# client_form.html - sugerencia de PKCE (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = La aplicación global reside en
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). Este indicador refleja la intención del operador.

# client_form.html + client_show.html - sugerencia de webhook (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = Cuando un usuario se autoelimina, Forseti envía por POST un Security Event Token de RFC 8417 (RISC
admin-client-field-webhook-hint-part2 = ) a esta dirección. Deje en blanco para excluirse. Los receptores verifican la JWS contra el JWKS de Forseti en
admin-client-field-webhook-hint-part3 = .

# client_show.html - descripción de scopes no documentados (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = Estos scopes están registrados en este cliente pero no tienen entrada en
admin-client-undoc-scopes-desc-part2 = en
admin-client-undoc-scopes-desc-part3 = . La pantalla de consentimiento recurre para ellos al nombre de scope en bruto.

# client_show.html - error de descubrimiento (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = No se pudo acceder al endpoint de descubrimiento de Hydra, por lo que el emisor y los endpoints están ocultos para evitar mostrar un valor erróneo. Obténgalos usted mismo desde
admin-client-discovery-error-part2 = .

# client_show.html - introducción de la sección de edición (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Actualice los campos del cliente a continuación. Los cambios se envían mediante el
admin-client-edit-intro-part2 = de Hydra; los campos no relacionados se conservan.

# dcr_tokens_list.html - subtítulo (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Tokens Bearer que autorizan
admin-dcr-subtitle-part2 = . Entregue uno al autor de un cliente MCP para que pueda autorregistrarse sin que usted lo haga manualmente.

# dcr_tokens_list.html - descripción del token revelado (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Compártalo con el autor del cliente. Él lo envía como
admin-dcr-revealed-desc-part2 = al llamar a
admin-dcr-revealed-desc-part3 = . No almacenamos el valor en bruto, solo su SHA-256.

# dcr_token_new.html - subtítulo (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = El token se revela una sola vez en la página siguiente. Entrégueselo al autor del cliente. Él lo envía como
admin-dcr-new-subtitle-part2 = en una única llamada
admin-dcr-new-subtitle-part3 = .

# dcr_token_new.html - sugerencia de usos máximos (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = Deje en blanco para uso ilimitado. Un solo uso (
admin-dcr-new-field-max-uses-hint-part2 = ) es el valor predeterminado más seguro.

# client_type_picker.html - descripción de aplicaciones conocidas (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Rellenado para una aplicación conocida. Las URL usan marcadores
admin-client-type-popular-desc-part2 = (y a veces
admin-client-type-popular-desc-part3 = ). Sustitúyalos por los valores de su aplicación tras llegar al formulario.

# posix_account.html - párrafo de claves SSH (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = Las claves públicas añadidas aquí se sirven al sshd del dispositivo (
admin-posix-ssh-keys-desc-part2 = ) para que este usuario pueda
admin-posix-ssh-keys-desc-part3 = con su clave, sin necesidad de un archivo
admin-posix-ssh-keys-desc-part4 = por host. Requiere el hook de sshd del host (configurado automáticamente por el servicio
admin-posix-ssh-keys-desc-part5 = de Guix; configuración manual de sshd en otras distribuciones). No se usa para el inicio de sesión de consola / PAM.

# posix_new.html - sugerencia de shell (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Debe existir en los dispositivos que sirven esta cuenta;
admin-posix-new-shell-hint-part2 = es el valor predeterminado seguro entre distribuciones (Guix no tiene
admin-posix-new-shell-hint-part3 = ). El directorio home se deriva del prefijo home + nombre de usuario.

# saml_list.html - bloque no-configurado (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = no está configurado
admin-saml-not-configured-part2 = añada los ajustes del puente Jackson a
admin-saml-not-configured-part3 = para habilitar el SSO SAML. Consulte
admin-saml-not-configured-part4 = .

# Mensajes flash de administración (mostrados como banner tras una redirección)
flash-identity-disabled = Identidad desactivada.
flash-identity-enabled = Identidad activada.
flash-session-revoked = Sesión revocada.
flash-client-create-failed = No se pudo crear el cliente: { $error }
flash-client-account-deletion-url-rejected = URL de eliminación de cuenta rechazada: { $error }
flash-client-secret-stage-failed = Cliente creado, pero no pudimos preparar el secreto para su visualización única. Rote el secreto para obtener un valor nuevo.
