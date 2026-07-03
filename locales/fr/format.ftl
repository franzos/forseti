# Mise en forme des horodatages relatifs (src/format.rs::humanise_timestamp).
# `{ $n }` est l'ampleur de l'intervalle. Le français conserve des suffixes d'unité compacts.
format-relative-just-now = à l'instant
format-relative-in-a-moment = dans un instant
format-relative-yesterday = hier
format-relative-tomorrow = demain
format-relative-minutes-ago = il y a { $n } min
format-relative-minutes-in = dans { $n } min
format-relative-hours-ago = il y a { $n } h
format-relative-hours-in = dans { $n } h
format-relative-days-ago = il y a { $n } j
format-relative-days-in = dans { $n } j
format-relative-months-ago = il y a { $n } mois
format-relative-months-in = dans { $n } mois
format-relative-years-ago = il y a { $n } an
format-relative-years-in = dans { $n } an

# Mise en forme du user-agent (src/format.rs::humanise_user_agent). Les noms de
# navigateur et de système sont des noms propres et restent littéraux ; seuls le
# connecteur et les valeurs de repli inconnues sont localisés.
format-ua-on = { $browser } sur { $os }
format-ua-unknown-browser = Navigateur inconnu
format-ua-unknown-os = Système inconnu
format-device-unknown = Appareil inconnu
