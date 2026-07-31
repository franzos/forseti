# Login page
auth-login-page-title = 登录
auth-login-card-title = 登录你的账号
auth-login-card-subtitle = 欢迎回到 { $brand }。
auth-login-aal2-body = 此区域需要两步验证，但你的账号尚未设置第二重身份验证。
auth-login-aal2-hint = 请在设置中配置身份验证器应用、安全密钥或恢复代码，然后再回来。
auth-login-aal2-setup-link = 设置两步验证
auth-login-forgot-password = 忘记密码？
auth-login-no-account = 还没有账号？
auth-login-create-account = 创建账号

# Shared divider (login + registration)
auth-or-continue-with = 或使用以下方式继续
auth-oidc-signin = 使用 { $provider } 登录

# Registration page
auth-registration-page-title = 创建账号
auth-registration-card-title = 创建一个账号
auth-registration-card-subtitle = 注册以安全地管理你的身份。
auth-registration-have-account = 已有账号？
auth-registration-sign-in-link = 登录
auth-registration-claim-body = 如果这是你的邮箱而你从未完成注册，
auth-registration-claim-link = 可以认领它

# Recovery page
auth-recovery-page-title = 账号恢复
auth-recovery-card-title-sent = 请查收邮件
auth-recovery-card-title-default = 忘记密码了？
auth-recovery-card-subtitle-sent = 我们已向你的邮箱发送恢复代码。在下方输入以继续。
auth-recovery-card-subtitle-default = 输入你的邮箱，我们会发送重置链接。
auth-recovery-back-to-sign-in = 返回登录

# Verification page
auth-verification-page-title = 验证你的邮箱
auth-verification-card-title-passed = 邮箱已验证
auth-verification-card-title-sent = 请查收邮件
auth-verification-card-title-default = 验证你的邮箱
auth-verification-card-subtitle-passed = 你的邮箱已确认。可以关闭此标签页或继续。
auth-verification-card-subtitle-sent = 我们已向你的邮箱发送验证代码。在下方输入以确认。
auth-verification-card-subtitle-default = 输入你的邮箱以接收验证代码。
auth-verification-sent-email-hint = 请使用最近一封验证邮件中的代码，或直接打开该邮件中的链接，而不必手动输入代码。
auth-verification-back-to-dashboard = 返回仪表板
auth-verification-back-to-sign-in = 返回登录

# WebAuthn / passkey browser-side strings (embedded via data attributes in webauthn_helper.html)
auth-webauthn-no-support = 你的浏览器不支持 WebAuthn / 通行密钥。
auth-passkey-needs-platform = 通行密钥登录需要本设备上的平台凭据（Touch ID、Windows Hello、Android 设备或已同步的通行密钥）。你的浏览器尚未设置。
auth-webauthn-err-not-allowed = 凭据请求已取消、超时，或没有匹配的凭据可用。
auth-webauthn-err-security = 你的浏览器拒绝了该安全操作。请检查站点是否通过受信任的来源加载，以及注册的标识符是否匹配。
auth-webauthn-err-invalid-state = 此设备上已注册了一个凭据。请改为登录，或换一台设备。
auth-webauthn-err-not-supported = 你的浏览器不支持所请求的凭据参数。
auth-webauthn-err-abort = 凭据请求在完成前被中止。
auth-webauthn-err-generic-prefix = 身份验证器错误：

# Flow field labels. Kratos emits trait fields with the schema `title` under the
# generic passthrough label id 1070002; flow_view.rs overrides these by name.
auth-field-email = 电子邮箱
auth-field-first-name = 名字
auth-field-last-name = 姓氏
