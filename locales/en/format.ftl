# Relative timestamp humanization (src/format.rs::humanise_timestamp).
# `{ $n }` is the bucket magnitude. English keeps the compact unit suffix.
format-relative-just-now = just now
format-relative-in-a-moment = in a moment
format-relative-yesterday = yesterday
format-relative-tomorrow = tomorrow
format-relative-minutes-ago = { $n }m ago
format-relative-minutes-in = in { $n }m
format-relative-hours-ago = { $n }h ago
format-relative-hours-in = in { $n }h
format-relative-days-ago = { $n }d ago
format-relative-days-in = in { $n }d
format-relative-months-ago = { $n }mo ago
format-relative-months-in = in { $n }mo
format-relative-years-ago = { $n }y ago
format-relative-years-in = in { $n }y

# User-agent humanization (src/format.rs::humanise_user_agent). Browser and OS
# names are proper nouns and stay literal; only the connector and the unknown
# fallbacks localize.
format-ua-on = { $browser } on { $os }
format-ua-unknown-browser = Unknown browser
format-ua-unknown-os = Unknown OS
format-device-unknown = Unknown device
