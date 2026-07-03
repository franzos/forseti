# Mensagens de fluxo do Kratos indexadas por ID numérico estável.
# Registo formal. Passthrough (NÃO neste catálogo): 4000001 (validação genérica - o texto É o payload).
# O texto em inglês corresponde ao inglês do Ory Kratos OSS quando o Fluent o permite; as mensagens
# de fluxo expirado usam texto simplificado porque o Fluent não consegue calcular minutos com %.2f a partir de um timestamp unix.

# --- Início de sessão (1010xxx) ---
kratos-1010001 = Iniciar sessão
kratos-1010002 = Iniciar sessão com { $provider }
kratos-1010003 = Confirme esta ação verificando que é você.
kratos-1010004 = Conclua o segundo desafio de autenticação.
kratos-1010005 = Verificar
kratos-1010006 = Código de autenticação
kratos-1010007 = Código de recuperação de reserva
kratos-1010008 = Iniciar sessão com uma chave de hardware
kratos-1010009 = Utilizar o Authenticator
kratos-1010010 = Utilizar código de recuperação de reserva
kratos-1010011 = Iniciar sessão com uma chave de hardware
kratos-1010012 = Prepare o seu dispositivo WebAuthn (por exemplo, chave de segurança, scanner biométrico, ...) e prima continuar.
kratos-1010013 = Continuar
kratos-1010014 = Foi enviado um código para o endereço que indicou. Se não o recebeu, verifique a ortografia do endereço e tente novamente.
kratos-1010015 = Enviar código de início de sessão
kratos-1010021 = Iniciar sessão com chave de acesso
kratos-1010022 = Iniciar sessão com palavra-passe

# --- Registo (1040xxx) ---
kratos-1040001 = Registar
kratos-1040002 = Registar com { $provider }
kratos-1040003 = Continuar
kratos-1040004 = Registar com chave de segurança
kratos-1040005 = Foi enviado um código para o(s) endereço(s) que indicou. Se não recebeu um e-mail, verifique a ortografia do endereço e certifique-se de que utiliza o endereço com que se registou.
kratos-1040006 = Enviar código de registo
kratos-1040007 = Registar com chave de acesso
kratos-1040008 = Voltar

# --- Definições (1050xxx) ---
kratos-1050001 = As suas alterações foram guardadas!
kratos-1050002 = Associar { $provider }
kratos-1050003 = Desassociar { $provider }
kratos-1050004 = Desassociar aplicação de autenticação TOTP
kratos-1050007 = Revelar códigos de recuperação de reserva
kratos-1050008 = Gerar novos códigos de recuperação de reserva
kratos-1050010 = Estes são os seus códigos de recuperação de reserva. Guarde-os num local seguro!
kratos-1050011 = Confirmar códigos de recuperação de reserva
kratos-1050012 = Adicionar chave de segurança
kratos-1050013 = Nome da chave de segurança
kratos-1050016 = Desativar este método
kratos-1050017 = Este é o segredo da sua aplicação de autenticação. Utilize-o se não conseguir ler o código QR.
kratos-1050018 = Remover chave de segurança "{ $display_name }"
kratos-1050019 = Adicionar chave de acesso
kratos-1050020 = Remover chave de acesso "{ $display_name }"
kratos-1050023 = A sua conta é gerida pela sua organização. Para alterar estas definições, contacte o administrador da sua organização.

# --- Recuperação (1060xxx) ---
# 1060001: o texto do Ory tem "within the next %.2f minutes" mas o contexto transporta um
# timestamp, não minutos. Simplificado aqui; a alternativa dá o inglês exato do Ory.
kratos-1060001 = Recuperou a sua conta com êxito. Altere a sua palavra-passe ou configure em breve um método de início de sessão alternativo (por exemplo, início de sessão social).
kratos-1060002 = Foi enviado um e-mail com uma ligação de recuperação para o endereço de e-mail que indicou. Se não recebeu um e-mail, verifique a ortografia do endereço e certifique-se de que utiliza o endereço com que se registou.
kratos-1060003 = Foi enviado um e-mail com um código de recuperação para o endereço de e-mail que indicou. Se não recebeu um e-mail, verifique a ortografia do endereço e certifique-se de que utiliza o endereço com que se registou.
kratos-1060004 = Foi enviado um código de recuperação para { $masked_address }. Se não o recebeu, verifique a ortografia do endereço e certifique-se de que utiliza o endereço com que se registou.

# --- Etiquetas de nós (1070xxx) ---
kratos-1070001 = Palavra-passe
kratos-1070003 = Guardar
kratos-1070004 = ID
kratos-1070005 = Submeter
kratos-1070006 = Verificar código
kratos-1070007 = E-mail
kratos-1070008 = Reenviar código
kratos-1070009 = Continuar
kratos-1070010 = Código de recuperação
kratos-1070011 = Código de verificação
kratos-1070012 = Código de registo
kratos-1070013 = Código de início de sessão
kratos-1070016 = Endereço de recuperação

# --- Verificação (1080xxx) ---
kratos-1080001 = Foi enviado um e-mail com uma ligação de verificação para o endereço de e-mail que indicou. Se não recebeu um e-mail, verifique a ortografia do endereço e certifique-se de que utiliza o endereço com que se registou.
kratos-1080002 = Verificou o seu endereço de e-mail com êxito.
kratos-1080003 = Foi enviado um e-mail com um código de verificação para o endereço de e-mail que indicou. Se não recebeu um e-mail, verifique a ortografia do endereço e certifique-se de que utiliza o endereço com que se registou.

# --- Erros de validação (4000xxx) ---
# 4000001 é passthrough: o texto É o motivo de validação dinâmico.
kratos-4000002 = A propriedade { $property } está em falta.
kratos-4000003 = o comprimento deve ser >= { $min_length }, mas foi { $actual_length }
# 4000005: $reason vem da configuração de política do Kratos; estará em inglês dentro de uma frase traduzida.
kratos-4000005 = A palavra-passe não pode ser utilizada porque { $reason }.
kratos-4000006 = As credenciais fornecidas são inválidas, verifique se há erros ortográficos na sua palavra-passe ou nome de utilizador, endereço de e-mail ou número de telefone.
kratos-4000007 = Já existe uma conta com o mesmo identificador (e-mail, telefone, nome de utilizador, ...).
kratos-4000008 = O código de autenticação fornecido é inválido, tente novamente.
kratos-4000032 = A palavra-passe deve ter pelo menos { $min_length } caracteres, mas tem { $actual_length }.
kratos-4000035 = Esta conta não existe ou não configurou o início de sessão com código.

# --- Erros do fluxo de início de sessão (4010xxx) ---
# Simplificado: o Ory calcula "X.XX minutes ago" a partir de um timestamp que não conseguimos formatar em Fluent.
kratos-4010001 = O fluxo de início de sessão expirou, tente novamente.
kratos-4010008 = O código de início de sessão é inválido ou já foi utilizado. Tente novamente.

# --- Erros do fluxo de registo (4040xxx) ---
kratos-4040001 = O fluxo de registo expirou, tente novamente.
kratos-4040003 = O código de registo é inválido ou já foi utilizado. Tente novamente.

# --- Erros do fluxo de definições (4050xxx) ---
kratos-4050001 = O fluxo de definições expirou, tente novamente.

# --- Erros do fluxo de recuperação (4060xxx) ---
kratos-4060004 = O token de recuperação é inválido ou já foi utilizado. Repita o fluxo.
kratos-4060006 = O código de recuperação é inválido ou já foi utilizado. Tente novamente.

# --- Erros do fluxo de verificação (4070xxx) ---
kratos-4070001 = O token de verificação é inválido ou já foi utilizado. Repita o fluxo.
kratos-4070005 = O fluxo de verificação expirou, tente novamente.
kratos-4070006 = O código de verificação é inválido ou já foi utilizado. Tente novamente.
