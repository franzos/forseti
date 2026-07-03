# Apresentação de datas relativas (src/format.rs::humanise_timestamp).
# `{ $n }` é a magnitude do intervalo. O português mantém um sufixo compacto.
format-relative-just-now = agora mesmo
format-relative-in-a-moment = daqui a instantes
format-relative-yesterday = ontem
format-relative-tomorrow = amanhã
format-relative-minutes-ago = há { $n } min
format-relative-minutes-in = em { $n } min
format-relative-hours-ago = há { $n } h
format-relative-hours-in = em { $n } h
format-relative-days-ago = há { $n } d
format-relative-days-in = em { $n } d
format-relative-months-ago = há { $n } meses
format-relative-months-in = em { $n } meses
format-relative-years-ago = há { $n } anos
format-relative-years-in = em { $n } anos

# Apresentação do user-agent (src/format.rs::humanise_user_agent). Os nomes de
# navegador e de sistema operativo são nomes próprios e permanecem literais; só o
# conector e as alternativas de valor desconhecido são traduzidos.
format-ua-on = { $browser } em { $os }
format-ua-unknown-browser = Navegador desconhecido
format-ua-unknown-os = Sistema desconhecido
format-device-unknown = Dispositivo desconhecido
