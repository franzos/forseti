# Относительные метки времени (src/format.rs::humanise_timestamp).
# `{ $n }` — величина интервала. В русском используются компактные сокращения единиц.
format-relative-just-now = только что
format-relative-in-a-moment = через мгновение
format-relative-yesterday = вчера
format-relative-tomorrow = завтра
format-relative-minutes-ago = { $n } мин назад
format-relative-minutes-in = через { $n } мин
format-relative-hours-ago = { $n } ч назад
format-relative-hours-in = через { $n } ч
format-relative-days-ago = { $n } дн назад
format-relative-days-in = через { $n } дн
format-relative-months-ago = { $n } мес назад
format-relative-months-in = через { $n } мес
format-relative-years-ago = { $n } г назад
format-relative-years-in = через { $n } г

# Аппаратно-программная строка user-agent (src/format.rs::humanise_user_agent). Названия
# браузеров и ОС — имена собственные и остаются без перевода; локализуются только связка
# и запасные значения для неизвестных случаев.
format-ua-on = { $browser } на { $os }
format-ua-unknown-browser = Неизвестный браузер
format-ua-unknown-os = Неизвестная ОС
format-device-unknown = Неизвестное устройство
