# Umanizzazione dei timestamp relativi (src/format.rs::humanise_timestamp).
# `{ $n }` è l'entità dell'intervallo. L'italiano mantiene un suffisso di unità compatto.
format-relative-just-now = proprio ora
format-relative-in-a-moment = tra un momento
format-relative-yesterday = ieri
format-relative-tomorrow = domani
format-relative-minutes-ago = { $n } min fa
format-relative-minutes-in = tra { $n } min
format-relative-hours-ago = { $n } h fa
format-relative-hours-in = tra { $n } h
format-relative-days-ago = { $n } gg fa
format-relative-days-in = tra { $n } gg
format-relative-months-ago = { $n } mesi fa
format-relative-months-in = tra { $n } mesi
format-relative-years-ago = { $n } anni fa
format-relative-years-in = tra { $n } anni

# Umanizzazione dello user-agent (src/format.rs::humanise_user_agent). I nomi di
# browser e sistema operativo sono nomi propri e restano invariati; solo il
# connettore e i valori di ripiego per gli sconosciuti vengono localizzati.
format-ua-on = { $browser } su { $os }
format-ua-unknown-browser = Browser sconosciuto
format-ua-unknown-os = Sistema operativo sconosciuto
format-device-unknown = Dispositivo sconosciuto
