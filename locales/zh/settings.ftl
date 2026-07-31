settings-hub-title = 设置
settings-hub-subtitle = 管理你的账号偏好、安全设置和活跃会话。
settings-hub-profile-title = 个人资料
settings-hub-profile-desc = 更新你的邮箱地址和显示名称。
settings-hub-profile-link = 管理资料
settings-hub-password-title = 密码
settings-hub-password-desc = 修改你的账号密码。
settings-hub-password-link = 修改密码
settings-hub-2fa-title = 两步验证
settings-hub-2fa-desc = 设置 TOTP、恢复代码和安全密钥。
settings-hub-2fa-link = 管理两步验证
settings-hub-sessions-title = 活跃会话
settings-hub-sessions-desc = 查看已登录你账号的设备。
settings-hub-sessions-link = 查看会话
settings-hub-apps-title = 已授权应用
settings-hub-apps-desc = 查看并撤销你已授权访问的 OAuth 应用。
settings-hub-apps-link = 管理应用
settings-hub-providers-title = 已关联的登录方式
settings-hub-providers-desc = 连接或移除第三方登录提供方。
settings-hub-providers-link = 管理登录方式
settings-hub-account-title = 账号
settings-hub-account-desc = 不可逆更改：删除你的账号。
settings-hub-account-link = 危险操作
settings-nav-general = 通用
settings-nav-security = 安全
settings-nav-connections = 连接
settings-nav-overview = 概览
settings-nav-profile = 个人资料
settings-nav-organization = 组织
settings-nav-password = 密码
settings-nav-2fa = 两步验证
settings-nav-sessions = 会话
settings-nav-offline = 离线登录
settings-nav-authorized-apps = 已授权应用
settings-nav-linked-providers = 已关联的登录方式
settings-nav-account = 账号

# Profile sub-page
settings-profile-heading = 个人资料
settings-profile-subtitle = 更新你的邮箱地址和显示名称。
settings-profile-email-not-verified = 未验证
settings-profile-email-send-verification = 发送验证邮件
settings-profile-public-heading = 公开资料
settings-profile-public-saved = 资料已保存。
settings-profile-public-label-username = 用户名
settings-profile-username-hint = 可使用字母、数字、点、下划线和连字符。为你创建账号的应用可能会用它作为你在那里的用户名。留空则不共享用户名。每 30 天只能修改一次，且释放的用户名不会再被他人占用。
settings-profile-public-label-bio = 简介
settings-profile-public-label-location = 所在地
settings-profile-public-label-pronouns = 人称代词
settings-profile-public-label-website = 网站
settings-profile-public-label-avatar = 头像 URL
settings-profile-public-avatar-hint = 可选。留空则使用自动生成的图案头像。
settings-profile-public-label-links = 链接
settings-profile-public-save = 保存资料
settings-profile-back = 返回设置
settings-profile-language-label = 首选语言
settings-profile-language-help = 在你的所有设备上生效。

# Password sub-page
settings-password-heading = 密码
settings-password-subtitle = 修改用于登录的密码。
settings-password-back = 返回设置

# Account sub-page
settings-account-heading = 账号
settings-account-subtitle = 对你账号的不可逆更改。
settings-account-delete-section-heading = 删除账号
settings-account-delete-body = 永久删除你的账号、所有活跃会话，以及全部两步验证和恢复状态。持有你数据副本的应用会收到通知，以便清除它们那一侧的数据。此操作无法撤销。
settings-account-delete-action = 删除我的账号

# Account delete confirmation page
settings-account-delete-page-title = 确认删除
settings-account-delete-confirm-heading = 要删除你的账号吗？
settings-account-delete-confirm-subtitle-prefix = 这将永久移除
settings-account-delete-confirm-subtitle-suffix = 以及与之关联的每一个会话、恢复代码和凭据。
settings-account-delete-apps-heading = 以下应用会收到你已注销的通知
settings-account-delete-apps-note = 应用会复制它们所需的数据（资料、设置）并与你的账号 ID 关联。我们会通过它们注册的删除 webhook 通知它们，以便清除其副本。
settings-account-delete-no-apps = 目前没有第三方应用持有你的数据副本。无需通知。
settings-account-delete-confirm-label = 请在下方输入你的邮箱以确认：
settings-account-delete-confirm-placeholder = 输入你的邮箱以确认
settings-account-delete-confirm-submit = 是的，删除我的账号
settings-account-delete-confirm-cancel = 取消

# Offline access sub-page
settings-offline-heading = 离线主机登录
settings-offline-subtitle = 设置一个专用口令，让你在已注册的 Linux 主机无法连接本服务器时仍能在终端登录。它与你的账号密码相互独立。请选择你记得住、但不会在别处重复使用的口令。
settings-offline-status-set-prefix = 离线口令
settings-offline-status-set-word = 已设置
settings-offline-status-set-suffix = 。在下方输入新口令即可更改，或将其完全移除。
settings-offline-status-unset = 尚未设置离线口令。没有口令时，你无法在已注册主机离线期间登录。
settings-offline-label-new-passphrase = 新的离线口令
settings-offline-label-passphrase = 离线口令
settings-offline-passphrase-hint = 至少 { $min_len } 个字符。请勿重复使用你的账号密码。
settings-offline-action-change = 更改口令
settings-offline-action-set = 设置口令
settings-offline-remove-heading = 移除离线访问
settings-offline-remove-body = 删除你的离线口令。已注册主机会在下次同步时移除它，之后你将无法在它们离线期间登录。
settings-offline-action-remove = 移除口令
settings-offline-back = 返回设置

# Password handoff (recovery → set-new-password)
settings-handoff-heading = 设置新密码
settings-handoff-subtitle = 你已通过恢复代码登录。请设置新密码以完成操作。
settings-handoff-countdown-label = 设置新密码的剩余时间：
settings-handoff-sign-out = 不修改并退出登录

# 2FA sub-page
settings-2fa-heading = 两步验证
settings-2fa-subtitle = 用第二重身份验证加固你的账号。
settings-2fa-no-recovery-warning-heading = 没有恢复代码：你有被锁在账号之外的风险
settings-2fa-no-recovery-warning-body = 两步验证已开启，但你还没有恢复代码。如果你丢失了身份验证器或安全密钥，恢复代码是重新进入账号的唯一途径。请立即生成。
settings-2fa-no-recovery-warning-action = 生成代码
settings-2fa-totp-heading = 身份验证器应用（TOTP）
settings-2fa-totp-desc = 使用 1Password、Bitwarden、Aegis 或 Authy 等应用生成 6 位验证代码。
settings-2fa-totp-enabled = 已启用
settings-2fa-totp-scan-hint = 用你的身份验证器应用扫描此二维码，或手动输入密钥：
settings-2fa-totp-not-offered = 你的服务器当前未提供身份验证器应用设置。
settings-2fa-recovery-heading = 恢复代码
settings-2fa-recovery-desc = 一次性代码，在你无法使用身份验证器时用于登录。
settings-2fa-recovery-active = 有效
settings-2fa-recovery-save-strong = 请立即保存。
settings-2fa-recovery-save-suffix = 它们不会再次显示。请存放在安全的地方，密码管理器是个不错的选择。
settings-2fa-recovery-not-offered = 你的服务器当前未提供恢复代码。
settings-2fa-webauthn-heading = 安全密钥与通行密钥
settings-2fa-webauthn-desc = 使用硬件密钥（YubiKey、Titan）或平台通行密钥（Touch ID、Windows Hello）作为你的第二重验证。
settings-2fa-webauthn-remove-fallback = 移除安全密钥
settings-2fa-webauthn-not-enabled = 你的管理员未启用通行密钥支持。
settings-2fa-back = 返回设置

# Sessions sub-page
settings-sessions-heading = 活跃会话
settings-sessions-subtitle = 当前已登录你账号的设备。请撤销任何你不认识的设备。
settings-sessions-revoke-action = 退出登录
settings-sessions-revoke-others-heading = 退出所有其他设备
settings-sessions-revoke-others-desc = 保留当前会话，撤销其余所有会话。
settings-sessions-revoke-others-action = 退出其他设备
settings-sessions-back = 返回设置

# Authorized apps sub-page
settings-apps-heading = 已授权应用
settings-apps-subtitle = 你已授权访问账号的应用。撤销任何你不再使用的应用，它们下次在你登录时需要重新请求授权。
settings-apps-empty = 目前还没有应用获得你账号的访问授权。
settings-apps-verified-label = 已验证
settings-apps-access-granted-prefix = 授权于
settings-apps-revoke-action = 撤销访问
settings-apps-back = 返回设置
settings-apps-reviewed-title = 已由你的管理员审核

# 2FA leftovers
settings-2fa-qr-alt = TOTP 二维码

# Password handoff countdown-expiry (rendered into JS)
settings-handoff-expired-lead = 你的恢复时间窗已过期。
settings-handoff-expired-link = 重新开始

# Linked providers sub-page
settings-providers-heading = 已关联的登录方式
settings-providers-subtitle = 使用第三方身份提供方登录你的账号。
# Empty panel: only shown when genuinely zero providers are configured.
settings-providers-empty-heading = 你的管理员未配置任何上游登录提供方。
settings-providers-empty-desc = 请联系你的管理员以启用 Google、GitHub 或其他登录提供方。
settings-providers-back = 返回设置
settings-providers-status-connected = 已于 { $date } 连接
settings-providers-status-connected-plain = 已连接
settings-providers-status-not-connected = 未连接
settings-providers-link = 关联
settings-providers-unlink = 解除关联
settings-providers-unlink-blocked = 这是你唯一的登录方式。请先添加密码或通行密钥，然后才能解除关联。
settings-providers-confirm-unlink = 解除关联 { $provider }？之后你将无法用它登录。

# Inline-code splits (item 8: 2+ code elements per string)

# settings_profile.html - public profile description (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = 在你的
settings-profile-public-desc-part2 = 页面上对同组织成员可见，也对你授予了
settings-profile-public-desc-part3 = 或
settings-profile-public-desc-part4 = OAuth 权限范围的应用可见。留空任一字段即可隐藏它。

# settings_profile.html - links hint (code: Label|https://url)
settings-profile-links-hint-part1 = 每行一条，格式为
settings-profile-links-hint-part2 = 。

# Flash messages and inline error bodies set in Rust handlers.
flash-session-signed-out = 会话已退出。
flash-session-signout-failed = 无法退出该会话。
flash-sessions-signed-out-others =
    { $count ->
       *[other] 已退出 { $count } 个其他会话。
    }
flash-sessions-signout-others-failed = 无法退出其他会话。
flash-app-access-revoked = 访问已撤销。
flash-app-access-revoke-failed = 无法撤销该应用的访问权限。
flash-offline-passphrase-saved = 离线口令已保存。已注册主机会在下次同步时获取。
flash-offline-passphrase-save-failed = 无法保存你的离线口令。请重试。
flash-offline-passphrase-too-short = 你的离线口令至少需要 { $min_len } 个字符。
flash-offline-passphrase-removed = 离线口令已移除。主机会在下次同步时删除它。
flash-offline-passphrase-none = 你尚未设置离线口令。
flash-offline-passphrase-remove-failed = 无法移除你的离线口令。请重试。
settings-profile-username-invalid = 该用户名不被允许。请使用 2 到 39 个字母、数字、点、下划线或连字符，并以字母或数字开头和结尾。
settings-profile-username-taken = 该用户名已被占用。
settings-profile-username-cooldown = 每 30 天只能修改一次用户名。
settings-profile-url-invalid = 网站和头像 URL 必须是有效的 http:// 或 https:// 地址。
settings-profile-link-url-invalid = 每个链接 URL 都必须是有效的 http:// 或 https:// 地址。
settings-save-failed = 无法保存你的更改。请重试。
