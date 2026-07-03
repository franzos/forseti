# Mensajes de flujo de Kratos indexados por ID numérico estable.
# Passthrough (NO en este catálogo): 4000001 (validación genérica: el texto ES la carga útil).
# El texto en inglés coincide con el inglés de Ory Kratos OSS donde Fluent lo permite; los mensajes
# de flujo caducado usan texto simplificado porque Fluent no puede calcular %.2f minutos desde una marca de tiempo unix.

# --- Inicio de sesión (1010xxx) ---
kratos-1010001 = Iniciar sesión
kratos-1010002 = Iniciar sesión con { $provider }
kratos-1010003 = Confirme esta acción verificando que es usted.
kratos-1010004 = Complete el segundo desafío de autenticación.
kratos-1010005 = Verificar
kratos-1010006 = Código de autenticación
kratos-1010007 = Código de recuperación de respaldo
kratos-1010008 = Iniciar sesión con una llave de hardware
kratos-1010009 = Usar la aplicación de autenticación
kratos-1010010 = Usar código de recuperación de respaldo
kratos-1010011 = Iniciar sesión con una llave de hardware
kratos-1010012 = Prepare su dispositivo WebAuthn (por ejemplo, llave de seguridad, escáner biométrico, ...) y presione continuar.
kratos-1010013 = Continuar
kratos-1010014 = Se envió un código a la dirección que proporcionó. Si no lo recibió, verifique la ortografía de la dirección e inténtelo de nuevo.
kratos-1010015 = Enviar código de inicio de sesión
kratos-1010021 = Iniciar sesión con passkey
kratos-1010022 = Iniciar sesión con contraseña

# --- Registro (1040xxx) ---
kratos-1040001 = Registrarse
kratos-1040002 = Registrarse con { $provider }
kratos-1040003 = Continuar
kratos-1040004 = Registrarse con llave de seguridad
kratos-1040005 = Se ha enviado un código a la(s) dirección(es) que proporcionó. Si no ha recibido un correo electrónico, verifique la ortografía de la dirección y asegúrese de usar la dirección con la que se registró.
kratos-1040006 = Enviar código de registro
kratos-1040007 = Registrarse con passkey
kratos-1040008 = Atrás

# --- Configuración (1050xxx) ---
kratos-1050001 = ¡Sus cambios se han guardado!
kratos-1050002 = Vincular { $provider }
kratos-1050003 = Desvincular { $provider }
kratos-1050004 = Desvincular aplicación de autenticación TOTP
kratos-1050007 = Mostrar códigos de recuperación de respaldo
kratos-1050008 = Generar nuevos códigos de recuperación de respaldo
kratos-1050010 = Estos son sus códigos de recuperación de respaldo. ¡Guárdelos en un lugar seguro!
kratos-1050011 = Confirmar códigos de recuperación de respaldo
kratos-1050012 = Agregar llave de seguridad
kratos-1050013 = Nombre de la llave de seguridad
kratos-1050016 = Desactivar este método
kratos-1050017 = Este es el secreto de su aplicación de autenticación. Úselo si no puede escanear el código QR.
kratos-1050018 = Eliminar la llave de seguridad "{ $display_name }"
kratos-1050019 = Agregar passkey
kratos-1050020 = Eliminar el passkey "{ $display_name }"
kratos-1050023 = Su cuenta está gestionada por su organización. Para cambiar esta configuración, contacte al administrador de su organización.

# --- Recuperación (1060xxx) ---
# 1060001: El texto de Ory dice "within the next %.2f minutes" pero el contexto lleva una
# marca de tiempo, no minutos. Simplificado aquí; el respaldo da el inglés exacto de Ory.
kratos-1060001 = Recuperó su cuenta correctamente. Cambie su contraseña o configure pronto un método de inicio de sesión alternativo (por ejemplo, inicio de sesión social).
kratos-1060002 = Se ha enviado un correo electrónico con un enlace de recuperación a la dirección de correo electrónico que proporcionó. Si no ha recibido un correo electrónico, verifique la ortografía de la dirección y asegúrese de usar la dirección con la que se registró.
kratos-1060003 = Se ha enviado un correo electrónico con un código de recuperación a la dirección de correo electrónico que proporcionó. Si no ha recibido un correo electrónico, verifique la ortografía de la dirección y asegúrese de usar la dirección con la que se registró.
kratos-1060004 = Se ha enviado un código de recuperación a { $masked_address }. Si no lo ha recibido, verifique la ortografía de la dirección y asegúrese de usar la dirección con la que se registró.

# --- Etiquetas de nodos (1070xxx) ---
kratos-1070001 = Contraseña
kratos-1070003 = Guardar
kratos-1070004 = ID
kratos-1070005 = Enviar
kratos-1070006 = Verificar código
kratos-1070007 = Correo electrónico
kratos-1070008 = Reenviar código
kratos-1070009 = Continuar
kratos-1070010 = Código de recuperación
kratos-1070011 = Código de verificación
kratos-1070012 = Código de registro
kratos-1070013 = Código de inicio de sesión
kratos-1070016 = Dirección de recuperación

# --- Verificación (1080xxx) ---
kratos-1080001 = Se ha enviado un correo electrónico con un enlace de verificación a la dirección de correo electrónico que proporcionó. Si no ha recibido un correo electrónico, verifique la ortografía de la dirección y asegúrese de usar la dirección con la que se registró.
kratos-1080002 = Verificó correctamente su dirección de correo electrónico.
kratos-1080003 = Se ha enviado un correo electrónico con un código de verificación a la dirección de correo electrónico que proporcionó. Si no ha recibido un correo electrónico, verifique la ortografía de la dirección y asegúrese de usar la dirección con la que se registró.

# --- Errores de validación (4000xxx) ---
# 4000001 es passthrough: el texto ES el motivo de validación dinámico.
kratos-4000002 = Falta la propiedad { $property }.
kratos-4000003 = la longitud debe ser >= { $min_length }, pero se obtuvo { $actual_length }
# 4000005: $reason proviene de la configuración de políticas de Kratos; estará en inglés dentro de una frase traducida.
kratos-4000005 = La contraseña no se puede usar porque { $reason }.
kratos-4000006 = Las credenciales proporcionadas no son válidas, revise si hay errores de ortografía en su contraseña o nombre de usuario, dirección de correo electrónico o número de teléfono.
kratos-4000007 = Ya existe una cuenta con el mismo identificador (correo electrónico, teléfono, nombre de usuario, ...).
kratos-4000008 = El código de autenticación proporcionado no es válido, inténtelo de nuevo.
kratos-4000032 = La contraseña debe tener al menos { $min_length } caracteres, pero se obtuvo { $actual_length }.
kratos-4000035 = Esta cuenta no existe o no ha configurado el inicio de sesión con código.

# --- Errores del flujo de inicio de sesión (4010xxx) ---
# Simplificado: Ory calcula "X.XX minutes ago" desde una marca de tiempo que no podemos formatear en Fluent.
kratos-4010001 = El flujo de inicio de sesión ha caducado, inténtelo de nuevo.
kratos-4010008 = El código de inicio de sesión no es válido o ya se ha usado. Inténtelo de nuevo.

# --- Errores del flujo de registro (4040xxx) ---
kratos-4040001 = El flujo de registro ha caducado, inténtelo de nuevo.
kratos-4040003 = El código de registro no es válido o ya se ha usado. Inténtelo de nuevo.

# --- Errores del flujo de configuración (4050xxx) ---
kratos-4050001 = El flujo de configuración ha caducado, inténtelo de nuevo.

# --- Errores del flujo de recuperación (4060xxx) ---
kratos-4060004 = El token de recuperación no es válido o ya se ha usado. Reintente el flujo.
kratos-4060006 = El código de recuperación no es válido o ya se ha usado. Inténtelo de nuevo.

# --- Errores del flujo de verificación (4070xxx) ---
kratos-4070001 = El token de verificación no es válido o ya se ha usado. Reintente el flujo.
kratos-4070005 = El flujo de verificación ha caducado, inténtelo de nuevo.
kratos-4070006 = El código de verificación no es válido o ya se ha usado. Inténtelo de nuevo.
