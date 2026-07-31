# Relative timestamp humanization (src/format.rs::humanise_timestamp).
# `{ $n }` is the bucket magnitude. Chinese uses the full unit word; the
# before/after marker is a suffix, so no leading preposition is needed.
format-relative-just-now = 刚刚
format-relative-in-a-moment = 稍后
format-relative-yesterday = 昨天
format-relative-tomorrow = 明天
format-relative-minutes-ago = { $n } 分钟前
format-relative-minutes-in = { $n } 分钟后
format-relative-hours-ago = { $n } 小时前
format-relative-hours-in = { $n } 小时后
format-relative-days-ago = { $n } 天前
format-relative-days-in = { $n } 天后
format-relative-months-ago = { $n } 个月前
format-relative-months-in = { $n } 个月后
format-relative-years-ago = { $n } 年前
format-relative-years-in = { $n } 年后

# User-agent humanization (src/format.rs::humanise_user_agent). Browser and OS
# names are proper nouns and stay literal; only the connector and the unknown
# fallbacks localize.
format-ua-on = { $os } 上的 { $browser }
format-ua-unknown-browser = 未知浏览器
format-ua-unknown-os = 未知操作系统
format-device-unknown = 未知设备
