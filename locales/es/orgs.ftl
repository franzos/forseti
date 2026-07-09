# Etiquetas de campo compartidas usadas en las páginas de organización
orgs-field-name = Nombre
orgs-field-slug = Slug
orgs-field-email = Correo electrónico
orgs-field-role = Rol

# Selector de organización (menú desplegable de la navegación superior)
orgs-switcher-label = Cambiar de organización
orgs-switcher-manage-link = Gestionar organizaciones

# Lista de organizaciones (list.html)
orgs-list-title = Organizaciones
orgs-list-heading = Sus organizaciones
orgs-list-create-heading = Crear una nueva organización
orgs-list-field-slug-optional = Slug (opcional)
orgs-list-action-create = Crear
orgs-list-field-access-mode = Modo de acceso
orgs-list-mode-internal-title = Interno
orgs-list-mode-internal-body = Solo por invitación. Los miembros se unen por invitación (y, más adelante, mediante un dominio corporativo verificado).
orgs-list-mode-external-title = Externo
orgs-list-mode-external-body = Registro público de autoservicio. El directorio de miembros está restringido a los administradores.
orgs-list-tier-gate-heading = Tener varias organizaciones es una función de { $tier }
orgs-list-license-missing = Su licencia actual no incluye la función de Organizaciones.
orgs-list-unlicensed = Esta instalación de { $brand } se ejecuta sin licencia, por lo que las organizaciones adicionales más allá de la predeterminada están bloqueadas.
orgs-list-license-upgrade = Active o actualice una licencia para crear más.
orgs-list-link-get-license = Obtener una licencia
orgs-list-link-activate-license = Activar una licencia existente

# Vista general de la organización - vista del propietario (overview.html)
orgs-overview-subtitle-default = Esta es la organización predeterminada de esta instalación de { $brand }. Todo el que se registra se une a ella automáticamente.
orgs-overview-subtitle = Gestione la configuración, la personalización de marca y la membresía de esta organización.
orgs-overview-identity-heading = Identidad
orgs-overview-quicklinks-heading = Enlaces rápidos
orgs-link-branding = Personalización de marca
orgs-link-members = Miembros
orgs-link-teams = Equipos
orgs-link-domains = Dominios
orgs-sso-heading = SSO empresarial
orgs-sso-status-enabled = activado
orgs-sso-status-disabled = desactivado
orgs-sso-operator-note = Las conexiones de SSO las gestiona el operador.
orgs-access-mode-heading = Modo de acceso
orgs-access-mode-label = Modo
orgs-access-mode-internal = Interno
orgs-access-mode-external = Externo
orgs-access-mode-note-default = La organización predeterminada siempre es interna.
orgs-access-mode-note-internal = Los miembros se unen por invitación. Cambiar a externo habilita el registro público.
orgs-access-mode-note-external = El registro público está habilitado. El directorio de miembros está restringido a administradores mientras esté en modo externo.
orgs-access-mode-action-switch-external = Cambiar a externo
orgs-access-mode-action-switch-internal = Cambiar a interno
orgs-confirm-switch-external = ¿Cambiar a externo? Esto habilita la página de registro público y restringe el directorio de miembros solo a administradores.
orgs-confirm-switch-internal = ¿Cambiar a interno? Esto deshabilita la página de registro público. Los miembros existentes conservan su membresía.
orgs-danger-heading = Zona de peligro
orgs-danger-delete-body = Eliminar de forma permanente esta organización. Forseti lo rechaza si todavía hay clientes de OAuth2 asociados.
orgs-danger-delete-action = Eliminar organización
orgs-confirm-delete-org = ¿Eliminar { $name }? Esto no se puede deshacer.

# Vista general de la organización - vista de no propietario (overview_info.html)
orgs-info-subtitle-default = Esta es la organización predeterminada de esta instalación de { $brand }. Usted es miembro.
orgs-info-subtitle = Usted es miembro de esta organización.
orgs-info-org-heading = Organización
orgs-info-members-label = Miembros
orgs-info-managed-by-heading = Gestionada por
orgs-info-managed-by-note = Póngase en contacto con un propietario para cambiar el nombre, la personalización de marca o la membresía de la organización.

# Página de miembros (members.html)
orgs-members-page-heading = Miembros
orgs-members-subtitle = Los propietarios pueden ascender / degradar a los miembros y eliminar a cualquiera excepto al último propietario.
orgs-members-visibility-note-admins-only = Solo los administradores pueden ver la lista completa de miembros.
orgs-members-visibility-note-same-group = Usted ve a los miembros que comparten un equipo con usted.
orgs-members-visibility-note-all = Todos los miembros son visibles.
orgs-members-invite-heading = Invitar por correo electrónico
orgs-members-role-member = Miembro
orgs-members-role-owner = Propietario
orgs-members-action-invite = Enviar invitación
orgs-members-visibility-heading = Visibilidad del directorio
orgs-members-visibility-label = Quién puede ver la lista de miembros
orgs-members-visibility-opt-all = Todos los miembros
orgs-members-visibility-opt-same-group = Solo el mismo equipo
orgs-members-visibility-opt-admins-only = Solo administradores
orgs-members-visibility-hint = "Solo el mismo equipo" requiere que exista al menos un equipo primero.
orgs-members-col-joined = Se unió
orgs-members-badge-you = usted
orgs-members-badge-hidden = Oculto
orgs-members-action-show = Mostrar
orgs-members-action-hide = Ocultar
orgs-members-action-update = Actualizar
orgs-members-action-remove = Eliminar
orgs-confirm-remove-member = ¿Eliminar a { $email }?
orgs-members-invites-heading = Invitaciones pendientes
orgs-members-invites-col-sent = Enviada
orgs-members-invites-col-expires = Vence

# Página de equipos (teams.html)
orgs-teams-page-heading = Equipos
orgs-teams-subtitle = Agrupe a los miembros en equipos. Los equipos delimitan el acceso a los hosts e impulsan la visibilidad del directorio dentro del mismo equipo.
orgs-teams-create-heading = Crear un equipo
orgs-teams-action-create = Crear equipo
orgs-teams-col-team = Equipo
orgs-teams-col-members = Miembros
orgs-teams-action-rename = Cambiar nombre
orgs-teams-action-manage-members = Gestionar miembros
orgs-teams-action-delete = Eliminar
orgs-confirm-delete-team = ¿Eliminar { $name }? Esto elimina el equipo y sus membresías.
orgs-teams-selected-heading = Miembros de { $team }
orgs-teams-add-member-label = Agregar miembro
orgs-teams-action-add = Agregar

# Página de dominios (domains.html)
orgs-domains-page-heading = Dominios permitidos
orgs-domains-subtitle = Los usuarios con un correo verificado en un dominio comprobado se unen automáticamente a esta organización.
orgs-domains-add-heading = Agregar un dominio
orgs-domains-field-domain = Dominio
orgs-domains-field-method = Método de verificación
orgs-domains-method-http_file = Archivo HTTP
orgs-domains-method-dns_txt = Registro TXT de DNS
orgs-domains-method-email = Correo electrónico
orgs-domains-action-add = Agregar dominio
orgs-domains-col-domain = Dominio
orgs-domains-col-method = Método
orgs-domains-col-status = Estado
orgs-domains-status-verified = Verificado
orgs-domains-status-pending = Pendiente
orgs-domains-instructions-http_file = Sirve { $token } en https://{ $domain }/.well-known/forseti-domain-verify
orgs-domains-instructions-dns_txt = Crea un registro TXT en _forseti-verify.{ $domain } con el valor: { $token }
orgs-domains-instructions-email = Se envió un código a admin@{ $domain } y postmaster@{ $domain }. Pégalo abajo.
orgs-domains-action-verify = Verificar
orgs-domains-action-confirm = Confirmar código
orgs-domains-field-token = Código de confirmación
orgs-domains-action-remove = Eliminar
orgs-confirm-remove-domain = ¿Eliminar { $domain }? La unión automática para este dominio se detiene de inmediato.
orgs-domains-policy-heading = Política de unión
orgs-domains-policy-subtitle = Elige cómo se unen a esta organización los usuarios con un correo verificado en un dominio probado.
orgs-domains-policy-field = Política
orgs-domains-policy-invite-only = Solo por invitación
orgs-domains-policy-auto-join = Los usuarios de dominios verificados pueden unirse por sí mismos
orgs-domains-policy-save = Guardar política

# Página de personalización de marca (branding.html)
orgs-branding-page-heading = Personalización de marca
orgs-branding-subtitle-prefix = Anule la marca predeterminada de Forseti con el logotipo y el correo electrónico de soporte de esta organización. Recurre a
orgs-branding-subtitle-infix = en
orgs-branding-subtitle-suffix = cuando no está definido.
orgs-branding-field-logo-url = URL del logotipo
orgs-branding-field-logo-file = Imagen del logotipo (PNG, JPEG o WebP; máx. 256 KB)
orgs-branding-logo-remove = Eliminar logotipo
orgs-branding-logo-save = Subir logotipo
orgs-branding-field-support-email = Correo electrónico de soporte
orgs-branding-theme-preset = Preajuste de tema
orgs-branding-primary = Color principal
orgs-branding-on-primary = Texto sobre el color principal
orgs-branding-secondary = Color de acento
orgs-branding-request-public = Activar una página de inicio de sesión pública (/o/su-slug)
orgs-branding-preview = Vista previa

# Página de destino pública (public_landing.html)
orgs-public-landing-note = Para iniciar sesión, abra la aplicación que le proporcionó su equipo. El inicio de sesión se realiza desde allí.
orgs-public-landing-register = Crear una cuenta

# Confirmación de unión (join_confirm.html)
join-confirm-page-title = Unirse a la organización
join-confirm-heading = Unirse a { $org }
join-confirm-body = Te estás uniendo a { $org }. ¿Continuar?
join-confirm-cta = Unirse
join-confirm-register-cta = Regístrate para unirte a { $org }
