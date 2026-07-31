# Onboarding surface (claim_email and invite templates)

# Claim email (claim_email.html)
claim-page-title = 认领邮箱
claim-card-title = 认领邮箱地址
claim-subtitle = 如果有人用你的邮箱注册却从未验证，你可以通过确认能收到该地址的邮件来取得所有权。
claim-email-label = 邮箱
claim-send-code = 发送代码
claim-changed-mind = 改变主意了？
claim-back-to-signup = 返回注册

# Confirm claim (claim_email_confirm.html)
claim-confirm-page-title = 确认认领
claim-confirm-card-title = 确认你的代码
claim-confirm-subtitle = 输入我们刚发送的 6 位代码。代码 15 分钟后失效。
claim-confirm-code-label = 代码
claim-confirm-button = 确认
claim-confirm-no-code = 没收到代码？
claim-confirm-start-over = 重新开始

# Accept invite (invite/accept.html)
invite-accept-page-title = 接受邀请
invite-accept-heading = 加入 { $org }
invite-accept-body = 你受邀以 { $role } 的身份加入 { $org }。邀请已发送至 { $email }。

# Invite unavailable (invite/invalid.html)
invite-invalid-page-title = 邀请不可用
invite-invalid-heading = 邀请不可用
invite-invalid-contact = 请联系邀请你的人，索取新的链接。
invite-invalid-back = 返回仪表板

# Claim-email flow errors (set in Rust)
claim-error-invalid-email = 请输入有效的邮箱地址。
claim-error-code-expired = 代码已过期。请重新开始。
claim-error-invalid-token = 令牌无效。请重新开始。
claim-error-service-unavailable = 服务暂时不可用。请稍后重试。
claim-error-too-many-attempts = 错误代码输入次数过多。请重新开始。
claim-error-code-mismatch = 代码不匹配。请重试。
claim-error-no-longer-claimable = 该邮箱已无法认领。
claim-error-release-failed = 无法释放该邮箱。请联系支持人员。

# Invite finalize (set in Rust)
invite-error-corrupt = 邀请数据已损坏。请联系你的管理员。
