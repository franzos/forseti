# Humanización de marcas de tiempo relativas (src/format.rs::humanise_timestamp).
# `{ $n }` es la magnitud del intervalo. El inglés mantiene el sufijo de unidad compacto.
format-relative-just-now = ahora mismo
format-relative-in-a-moment = en un momento
format-relative-yesterday = ayer
format-relative-tomorrow = mañana
format-relative-minutes-ago = hace { $n } min
format-relative-minutes-in = en { $n } min
format-relative-hours-ago = hace { $n } h
format-relative-hours-in = en { $n } h
format-relative-days-ago = hace { $n } d
format-relative-days-in = en { $n } d
format-relative-months-ago = hace { $n } mes
format-relative-months-in = en { $n } mes
format-relative-years-ago = hace { $n } a
format-relative-years-in = en { $n } a

# Humanización del user-agent (src/format.rs::humanise_user_agent). Los nombres de
# navegador y de sistema operativo son nombres propios y se mantienen literales; solo se
# localizan el conector y los textos de reserva para valores desconocidos.
format-ua-on = { $browser } en { $os }
format-ua-unknown-browser = Navegador desconocido
format-ua-unknown-os = Sistema operativo desconocido
format-device-unknown = Dispositivo desconocido
