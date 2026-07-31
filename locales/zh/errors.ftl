# Error page
error-reference-id = 参考编号：
error-cta-back-to-sign-in = 返回登录

# OAuth logout confirmation
logout-card-title = 要退出所有应用吗？
logout-card-subtitle = 这将结束你在 { $brand } 的会话，并通知你登录过的每个应用。
logout-body-text = 发起退出请求的应用会收到完成通知。部分应用可能会在短时间内保留本地缓存数据；在此退出会结束你在 { $brand } 的会话。
logout-action-sign-out = 退出登录
logout-action-cancel = 取消

# Admin dialog titles and bodies used by render_admin_error at call sites that have a locale.
# Call sites without a locale (helper functions, error boundaries) keep their English literals.
dialog-identity-unavailable-title = 身份不可用
dialog-identity-unavailable-body = 无法加载该身份，它可能已被删除。
dialog-recovery-code-failed-title = 恢复代码失败
dialog-recovery-code-failed-body = 我们已生成恢复代码，但无法暂存以供一次性展示。请生成新代码重试。
dialog-disable-failed-title = 停用失败
dialog-enable-failed-title = 启用失败
dialog-delete-failed-title = 删除失败
dialog-revoke-failed-title = 撤销失败

# Error boundary (error_boundary.html), title/body/cta set in Rust handlers.
error-boundary-auth-unavailable-title = 身份验证不可用
error-boundary-auth-unavailable-body = 无法连接身份验证服务。请稍后重试。
error-boundary-cta-try-again = 重试
error-boundary-cta-sign-in = 登录
error-boundary-cta-back-to-settings = 返回设置
error-boundary-cta-back-to-dashboard = 返回仪表板
error-boundary-cta-back-to-account = 返回账号
error-boundary-signin-title = 登录不可用
error-boundary-signup-title = 注册不可用
error-boundary-recovery-title = 恢复不可用
error-boundary-verification-title = 验证不可用
error-boundary-settings-title = 设置不可用
error-boundary-logout-title = 退出不可用
error-boundary-logout-body = 由于无法连接身份验证服务，退出未能完成。你的会话仍然有效，请稍后重试。
error-boundary-sessions-title = 会话不可用
error-boundary-sessions-body = 无法列出你的活跃会话。请稍后重试。
error-boundary-authorized-apps-title = 已授权应用不可用
error-boundary-authorized-apps-no-session-body = 无法读取你的会话。请重新登录。
error-boundary-authorized-apps-service-body = 无法连接 OAuth 服务。请稍后重试。
error-boundary-account-deletion-title = 账号删除失败
error-boundary-account-delete-bad-session = 你的会话处于异常状态。请重新登录后重试。
error-boundary-account-delete-sole-owner = 你是 { $names } 的唯一所有者。请先将所有权转移给其他成员，再删除账号。
error-boundary-account-delete-ownership-check-failed = 无法核实你的组织所有权。未做任何更改；请稍后重试。
error-boundary-account-delete-consent-unreachable = 无法连接授权服务以通知你已连接的应用。未做任何更改；请稍后重试。
error-boundary-account-delete-notifications-failed = 无法准备删除通知。未做任何更改；请重试。
error-boundary-account-delete-failed = 无法删除你的账号。请稍后重试。

# SAML error boundary (rendered under the default locale; the ACS callback carries no request locale).
error-boundary-sso-unavailable-title = 单点登录不可用
error-boundary-sso-unavailable-body = 该地址无法使用单点登录。请核对管理员给你的链接，或使用你常用的方式登录。
error-boundary-sso-failed-title = 单点登录失败
error-boundary-sso-validation-failed-body = 本次登录尝试无法通过校验。请从你所在组织的 SSO 链接重新开始。
error-boundary-sso-upstream-failed-body = 登录服务暂时不可用。请重试。
error-boundary-sso-no-email-body = 身份提供方未提供邮箱地址。请让管理员在 SAML 连接上映射邮箱属性。

# Kratos self-service error page (error.html), fallbacks set in Rust.
error-page-generic-title = 出错了
error-page-generic-body = 无法加载所请求的页面。链接可能已过期或已被使用。
error-page-link-expired-title = 链接已过期
error-page-link-expired-body = 此链接已失效。请从登录页重新开始。
error-page-security-title = 安全校验失败
error-page-already-signed-in-title = 已登录
error-page-default-message = 无法完成该请求。

# Admin gate forbidden page (admin/forbidden.html), set in Rust.
error-admin-access-denied-title = 访问被拒绝
error-admin-access-denied-body = 你的账号无权使用管理工具。
error-admin-access-denied-forseti-body = 你的账号无权使用 Forseti 全局管理工具。
error-admin-access-denied-org-body = 你没有该组织的管理权限。

# SAML blocked
error-saml-blocked-page-title = 登录被阻止
error-saml-blocked-card-title = 无法为你登录
error-saml-unverified-prefix = 已存在一个属于
error-saml-unverified-suffix = 的账号，但其邮箱地址尚未验证，因此单点登录无法安全地关联到它。请通过最初的注册邮件验证该地址，或向管理员求助。
error-saml-cross-org-not-member = 你的账号还不是该组织的成员。请让管理员将你添加进来，然后重试。
error-saml-conflict = 无法为你登录。请联系你的管理员。
error-saml-blocked-cta = 前往登录
