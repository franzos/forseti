# Shared field labels used across organisation pages
orgs-field-name = 名称
orgs-field-slug = 短标识
orgs-field-email = 邮箱
orgs-field-role = 角色

# Organisation switcher (top-nav dropdown)
orgs-switcher-label = 切换组织
orgs-switcher-manage-link = 管理组织

# Organisation list (list.html)
orgs-list-title = 组织
orgs-list-heading = 你的组织
orgs-list-create-heading = 创建新组织
orgs-list-field-slug-optional = 短标识（可选）
orgs-list-action-create = 创建
orgs-list-field-access-mode = 访问模式
orgs-list-mode-internal-title = 内部
orgs-list-mode-internal-body = 仅限邀请。成员通过邀请加入（之后也可通过已验证的公司域名加入）。
orgs-list-mode-external-title = 外部
orgs-list-mode-external-body = 公开自助注册。成员名录仅对管理员可见。
orgs-list-tier-gate-heading = 多组织是 { $tier } 版功能
orgs-list-license-missing = 你当前的许可证不包含组织功能。
orgs-list-unlicensed = 此 { $brand } 实例未激活许可证，因此默认组织之外的组织受限。
orgs-list-license-upgrade = 激活或升级许可证即可创建更多组织。
orgs-list-link-get-license = 获取许可证
orgs-list-link-activate-license = 激活已有许可证

# Organisation overview - owner view (overview.html)
orgs-overview-subtitle-default = 这是此 { $brand } 实例的默认组织。任何注册用户都会自动加入。
orgs-overview-subtitle = 管理此组织的设置、品牌和成员。
orgs-overview-identity-heading = 身份
orgs-overview-quicklinks-heading = 快捷链接
orgs-link-branding = 品牌
orgs-link-members = 成员
orgs-link-teams = 团队
orgs-link-domains = 域名
orgs-sso-heading = 企业单点登录
orgs-sso-status-enabled = 已启用
orgs-sso-status-disabled = 已停用
orgs-sso-operator-note = 单点登录连接由运维人员管理。
orgs-access-mode-heading = 访问模式
orgs-access-mode-label = 模式
orgs-access-mode-internal = 内部
orgs-access-mode-external = 外部
orgs-access-mode-note-default = 默认组织始终为内部模式。
orgs-access-mode-note-internal = 成员通过邀请加入。切换到外部模式将开放公开注册。
orgs-access-mode-note-external = 公开注册已启用。处于外部模式时，成员名录仅对管理员可见。
orgs-access-mode-action-switch-external = 切换到外部
orgs-access-mode-action-switch-internal = 切换到内部
orgs-confirm-switch-external = 切换到外部模式？这将启用公开注册页面，并将成员名录限制为仅管理员可见。
orgs-confirm-switch-internal = 切换到内部模式？这将关闭公开注册页面。现有成员保留其成员身份。
orgs-danger-heading = 危险操作
orgs-danger-delete-body = 彻底删除此组织。若仍有关联的 OAuth2 客户端，Forseti 将拒绝删除。
orgs-danger-delete-action = 删除组织
orgs-confirm-delete-org = 删除 { $name }？此操作无法撤销。

# Organisation overview - non-owner view (overview_info.html)
orgs-info-subtitle-default = 这是此 { $brand } 实例的默认组织。你是其成员。
orgs-info-subtitle = 你是此组织的成员。
orgs-info-org-heading = 组织
orgs-info-members-label = 成员
orgs-info-managed-by-heading = 管理者
orgs-info-managed-by-note = 如需更改组织名称、品牌或成员，请联系所有者。

# Members page (members.html)
orgs-members-page-heading = 成员
orgs-members-subtitle = 所有者可以提升或降低成员权限，并可移除除最后一位所有者之外的任何人。
orgs-members-visibility-note-admins-only = 只有管理员能看到完整的成员列表。
orgs-members-visibility-note-same-group = 你可以看到与你同团队的成员。
orgs-members-visibility-note-all = 所有成员均可见。
orgs-members-invite-heading = 通过邮箱邀请
orgs-members-role-member = 成员
orgs-members-role-owner = 所有者
orgs-members-action-invite = 发送邀请
orgs-members-visibility-heading = 名录可见性
orgs-members-visibility-label = 谁可以查看成员列表
orgs-members-visibility-opt-all = 所有成员
orgs-members-visibility-opt-same-group = 仅同团队
orgs-members-visibility-opt-admins-only = 仅管理员
orgs-members-visibility-hint = 「仅同团队」需要先至少存在一个团队。
orgs-members-col-joined = 加入时间
orgs-members-badge-you = 你
orgs-members-badge-hidden = 已隐藏
orgs-members-action-show = 显示
orgs-members-action-hide = 隐藏
orgs-members-action-update = 更新
orgs-members-action-remove = 移除
orgs-confirm-remove-member = 移除 { $email }？
orgs-members-invites-heading = 待处理邀请
orgs-members-invites-col-sent = 发送时间
orgs-members-invites-col-expires = 过期时间

# Teams page (teams.html)
orgs-teams-page-heading = 团队
orgs-teams-subtitle = 将成员编入团队。团队决定主机访问范围，并驱动同团队名录可见性。
orgs-teams-create-heading = 创建团队
orgs-teams-action-create = 创建团队
orgs-teams-col-team = 团队
orgs-teams-col-members = 成员
orgs-teams-action-rename = 重命名
orgs-teams-action-manage-members = 管理成员
orgs-teams-action-delete = 删除
orgs-confirm-delete-team = 删除 { $name }？这将移除该团队及其成员关系。
orgs-teams-selected-heading = { $team } 的成员
orgs-teams-add-member-label = 添加成员
orgs-teams-action-add = 添加

# Domains page (domains.html)
orgs-domains-page-heading = 允许的域名
orgs-domains-subtitle = 在已验证域名下拥有已验证邮箱的用户会自动加入此组织。
orgs-domains-add-heading = 添加域名
orgs-domains-field-domain = 域名
orgs-domains-field-method = 验证方式
orgs-domains-method-http_file = HTTP 文件
orgs-domains-method-dns_txt = DNS TXT 记录
orgs-domains-method-email = 邮件
orgs-domains-action-add = 添加域名
orgs-domains-col-domain = 域名
orgs-domains-col-method = 方式
orgs-domains-col-status = 状态
orgs-domains-status-verified = 已验证
orgs-domains-status-pending = 待验证
orgs-domains-instructions-http_file = 在 https://{ $domain }/.well-known/forseti-domain-verify 提供 { $token }
orgs-domains-instructions-dns_txt = 在 _forseti-verify.{ $domain } 创建一条 TXT 记录，值为：{ $token }
orgs-domains-instructions-email = 代码已发送至 admin@{ $domain } 和 postmaster@{ $domain }。请粘贴到下方。
orgs-domains-action-verify = 验证
orgs-domains-action-confirm = 确认代码
orgs-domains-field-token = 确认代码
orgs-domains-action-remove = 移除
orgs-confirm-remove-domain = 移除 { $domain }？该域名的自动加入将立即停止。
orgs-domains-policy-heading = 加入策略
orgs-domains-policy-subtitle = 选择在已验证域名下拥有已验证邮箱的用户如何加入此组织。
orgs-domains-policy-field = 策略
orgs-domains-policy-invite-only = 仅限邀请
orgs-domains-policy-auto-join = 已验证域名用户可自助加入
orgs-domains-policy-save = 保存策略

# Branding page (branding.html)
orgs-branding-page-heading = 品牌
orgs-branding-subtitle-prefix = 用此组织的标志和支持邮箱覆盖 Forseti 的默认品牌。未设置时回退到
orgs-branding-subtitle-infix = 于
orgs-branding-subtitle-suffix = 中的设置。
orgs-branding-field-logo-url = 标志 URL
orgs-branding-field-logo-file = 标志图片（PNG、JPEG 或 WebP；最大 256 KB）
orgs-branding-logo-remove = 移除标志
orgs-branding-logo-save = 上传标志
orgs-branding-field-support-email = 支持邮箱
orgs-branding-theme-preset = 主题预设
orgs-branding-primary = 主色
orgs-branding-on-primary = 主色上的文字
orgs-branding-secondary = 强调色
orgs-branding-request-public = 启用公开登录页（/o/your-slug）
orgs-branding-preview = 预览

# Flash notices (post-save banners)
flash-org-updated = 组织已更新。
flash-branding-saved = 品牌设置已保存。
flash-logo-updated = 标志已更新。
flash-logo-removed = 标志已移除。

# Public landing page (public_landing.html)
orgs-public-landing-note = 在下方登录，或创建账号开始使用。
orgs-public-landing-register = 创建账号
orgs-public-landing-signin = 登录

# Join confirm (join_confirm.html)
join-confirm-page-title = 加入组织
join-confirm-heading = 加入 { $org }
join-confirm-body = 你即将加入 { $org }。是否继续？
join-confirm-cta = 加入
join-confirm-register-cta = 注册以加入 { $org }
join-confirm-decline = 不加入，继续
