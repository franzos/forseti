# Admin banner (admin_shell.html)
admin-banner-label = 管理
admin-banner-body = 你正处于特权界面。此处的操作都会记入审计日志。

# Admin nav sidebar heading (admin_nav.html)
admin-nav-heading = 管理
admin-nav-subtitle = 运维工具

# Admin nav section headers
admin-nav-section-system = 系统
admin-nav-section-access = 访问
admin-nav-section-linux = Linux

# Admin nav item labels
admin-nav-status = 状态
admin-nav-configuration = 配置
admin-nav-audit = 审计
admin-nav-webhooks = Webhook
admin-nav-license = 许可证
admin-nav-identities = 身份
admin-nav-sessions = 会话
admin-nav-clients = OAuth2 客户端
admin-nav-dcr-tokens = DCR 令牌
admin-nav-saml = SAML 单点登录
admin-nav-hosts = 主机
admin-nav-accounts = 账户

# Identities list (identities_list.html)
admin-identities-page-title = 身份
admin-identities-subtitle = 由 Kratos 管理的身份及其状态。
admin-identities-search-placeholder = 按 ID 或邮箱搜索
admin-identities-search-button = 搜索
admin-identities-col-email = 邮箱
admin-identities-col-state = 状态
admin-identities-col-created = 创建时间
admin-identities-empty = 未找到身份。
admin-identities-prev = 返回首页
admin-identities-next = 下一页

# Identity detail (identity_show.html)
admin-identity-status-active = 活跃
admin-identity-recovery-code-heading = 恢复代码（仅显示一次）
admin-identity-recovery-link-heading = 恢复链接
admin-identity-recovery-note = 请通过可信渠道分享给用户。它不会再次显示。
admin-identity-section-actions = 操作
admin-identity-action-generate-recovery = 生成恢复代码
admin-identity-action-disable = 停用
admin-identity-action-enable = 启用
admin-identity-action-delete = 删除
admin-identity-section-traits = 属性
admin-identity-section-addresses = 可验证地址
admin-identity-addresses-empty = 该身份没有可验证地址。
admin-identity-status-verified = 已验证
admin-identity-status-pending = 待验证
admin-identity-section-credentials = 凭据
admin-identity-credentials-empty = 未配置凭据。
admin-identity-section-sessions = 近期会话
admin-identity-sessions-empty = 无会话历史。
admin-identity-action-revoke-session = 撤销会话

# Identity picker (identity_picker.html)
admin-identity-picker-page-title = 选择用户
admin-identity-picker-subtitle = 选择一个身份以继续。
admin-identity-picker-invalid-return = 返回目标无效。
admin-identity-picker-search-placeholder = 按 ID 或邮箱搜索
admin-identity-picker-search-button = 搜索
admin-identity-picker-col-email = 邮箱
admin-identity-picker-col-state = 状态
admin-identity-picker-col-created = 创建时间
admin-identity-picker-empty = 未找到身份。
admin-identity-picker-action-select = 选择
admin-identity-picker-prev = 返回首页
admin-identity-picker-next = 下一页

# Sessions list (sessions_list.html)
admin-sessions-page-title = 会话
admin-sessions-subtitle = Kratos 已知的全部会话，覆盖所有身份。
admin-sessions-filter-active-only = 仅显示活跃会话
admin-sessions-col-identity = 身份
admin-sessions-col-authenticated = 认证时间
admin-sessions-col-expires = 过期时间
admin-sessions-col-device = 设备
admin-sessions-empty = 没有可显示的会话。
admin-sessions-action-revoke = 撤销
admin-sessions-prev = 返回首页
admin-sessions-next = 下一页

# Generic confirm dialog (confirm.html)
admin-confirm-cancel = 取消

# Forbidden page (forbidden.html)
admin-forbidden-back = 返回仪表板

# Admin error page (error.html)
admin-error-back = 返回管理状态页

# Clients list (clients_list.html)
admin-clients-page-title = OAuth2 客户端
admin-clients-subtitle = 已在 Hydra 注册的依赖方。
admin-clients-action-new = 新建客户端
admin-clients-search-placeholder = 按客户端名称或 ID 搜索
admin-clients-filter-all-types = 所有类型
admin-clients-filter-all-verifications = 所有审核状态
admin-clients-filter-verified = 已审核
admin-clients-filter-unverified = 未审核
admin-clients-search-button = 搜索
admin-clients-col-name = 名称
admin-clients-col-type = 类型
admin-clients-col-grants = 授权类型
admin-clients-col-created = 创建时间
admin-clients-badge-unverified-title = 未经管理员审核
admin-clients-badge-self-registered = 自助注册
admin-clients-badge-self-registered-title = 通过 /oauth2/register 注册（RFC 7591）
admin-clients-empty = 尚未注册客户端。
admin-clients-prev = 返回首页
admin-clients-next = 下一页

# Client shared badges (clients_list.html, client_show.html)
admin-client-badge-verified = 已审核
admin-client-badge-unverified = 未审核
admin-client-badge-unverified-title = 管理员尚未审核此客户端。授权页面会向最终用户发出提示。

# Client form page headings (client_form.html)
admin-client-form-title-new = 新建客户端
admin-client-form-title-edit = 编辑客户端
admin-client-form-heading-new = 新建 OAuth2 客户端
admin-client-form-heading-edit = 编辑客户端
admin-client-form-preset-note = 已按此类型预填默认值。
admin-client-form-preset-change = 更改类型

# Client shared form fields (client_form.html, client_show.html edit form)
admin-client-field-name = 客户端名称
admin-client-field-grant-types = 授权类型
admin-client-grant-auth-code-hint = （由用户发起的登录）
admin-client-grant-refresh-hint = （长期会话）
admin-client-grant-client-creds-hint = （服务间调用）
admin-client-field-response-types = 响应类型
admin-client-field-scope = 权限范围
admin-client-field-scope-hint = 以空格分隔的 OAuth2 权限范围。
admin-client-field-redirect-uris = 重定向 URI
admin-client-field-redirect-uris-hint = 每行一条（或以逗号分隔）。
admin-client-field-post-logout-uris = 退出后重定向 URI
admin-client-section-logout-fanout = OIDC 退出广播
admin-client-section-logout-fanout-desc = 当用户通过 Forseti 结束会话时，Hydra 会通知这些 URI，以便每个应用清除本地会话。留空即表示此客户端不参与广播。
admin-client-field-backchannel-uri = 后端通道退出 URI
admin-client-field-backchannel-uri-hint = Hydra 会向此处 POST 一个签名的退出令牌（服务器到服务器）。通常只对服务端渲染的 Web 应用和 BFF 有意义。
admin-client-field-backchannel-sid-prefix = 要求后端通道退出令牌中包含
admin-client-field-backchannel-sid-suffix = 声明
admin-client-field-backchannel-sid-short = 声明
admin-client-field-frontchannel-uri = 前端通道退出 URI
admin-client-field-frontchannel-uri-hint = 退出时 Hydra 会以 iframe 加载此 URL，以便每个应用在浏览器内清除其会话 Cookie。
admin-client-field-frontchannel-sid-prefix = 要求前端通道退出时带上
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = 查询参数
admin-client-field-frontchannel-sid-short = 查询参数
admin-client-field-token-auth = 令牌端点认证方式
admin-client-token-auth-post-hint = （密钥放在 POST 正文中）
admin-client-token-auth-basic-hint = （密钥放在 Authorization 头中）
admin-client-token-auth-none-hint = （公开客户端，PKCE）
admin-client-token-auth-none-short = 无（公开 + PKCE）
admin-client-field-audience = Audience 允许列表
admin-client-field-audience-hint-short = 每行一条。Hydra 要求 audience 值必须先在此处注册。
admin-client-field-require-pkce = 要求 PKCE（仅作说明）
admin-client-field-skip-consent = 受信任客户端（跳过授权页面）
admin-client-field-webhook-url = 账号删除 Webhook URL
admin-client-action-cancel = 取消

# Client show page (client_show.html)
admin-client-action-revoke-verification = 撤销审核
admin-client-action-mark-verified = 标记为已审核
admin-client-action-rotate-secret = 轮换密钥
admin-client-action-delete = 删除
admin-client-credentials-heading = 凭据：仅显示一次
admin-client-credentials-note = 请立即复制。它们不会再次显示；刷新即关闭。上方的客户端 ID 和端点并非机密，会持续可见。
admin-client-credentials-secret-label = 客户端密钥
admin-client-credentials-rat-label = 注册访问令牌
admin-client-credentials-rat-note = 依据 RFC 7592：允许客户端通过 Hydra 的动态客户端注册 API 管理自身注册信息（读取／更新／删除）。它无法重新签发，因此如有疑虑请妥善保存。
admin-client-undoc-scopes-heading = 未说明的权限范围
admin-client-section-logo = 授权页面标志
admin-client-logo-intro = 在此应用的授权页面上向用户展示。此处上传的图片会由本服务器提供，而不是取自客户端自己的 logo_uri，因此在用户授权前不会有任何用户 IP 暴露给该应用。
admin-client-logo-file = 标志文件
admin-client-logo-hint = PNG、JPEG 或 WebP，最大 256 KB。方形图片效果最佳。
admin-client-logo-remove = 移除当前标志
admin-client-logo-save = 保存标志
admin-client-section-connection = 连接信息
admin-client-connection-intro = 将这些内容填入应用侧的 OIDC/OAuth 客户端配置。
admin-client-conn-client-id = 客户端 ID
admin-client-conn-issuer = 签发者
admin-client-conn-discovery-url = 发现文档 URL
admin-client-conn-auth-endpoint = 授权端点
admin-client-conn-token-endpoint = 令牌端点
admin-client-conn-userinfo-endpoint = 用户信息端点
admin-client-conn-jwks-uri = JWKS URI
admin-client-conn-end-session-endpoint = 结束会话端点
admin-client-section-config = 配置
admin-client-config-sid-required = （需要 sid）
admin-client-config-iss-sid-required = （需要 iss+sid）
admin-client-not-configured = 未配置
admin-client-audience-none = 无
admin-client-config-token-auth = 令牌端点认证
admin-client-config-require-pkce = 要求 PKCE
admin-client-bool-yes = 是
admin-client-bool-no = 否
admin-client-config-trusted = 受信任（跳过授权）
admin-client-config-created = 创建时间
admin-client-config-provenance-audience = Audience
admin-client-config-provenance-audience-note = （由 DCR 调用方声明）
admin-client-config-provenance-url = 使用于
admin-client-config-provenance-url-note = （首次在授权时观察到）
admin-client-config-webhook = 账号删除 Webhook
admin-client-section-edit = 编辑
admin-client-action-save = 保存更改
admin-client-action-back = 返回列表

# Client type picker (client_type_picker.html)
admin-client-type-page-title = 新建客户端
admin-client-type-heading = 新建 OAuth2 客户端
admin-client-type-subtitle = 选择应用类型。下一页是同一张表单，只是已填好对应的默认值，这样你不会不小心配出无法工作的组合。
admin-client-type-popular-heading = 常见应用
admin-client-type-action-cancel = 取消

# DCR tokens list (dcr_tokens_list.html)
admin-dcr-page-title = DCR 初始访问令牌
admin-dcr-action-issue = 签发令牌
admin-dcr-token-revealed-heading = 初始访问令牌（仅显示一次）
admin-dcr-col-status = 状态
admin-dcr-col-note = 备注
admin-dcr-col-created-by = 创建者
admin-dcr-col-created = 创建时间
admin-dcr-col-expires = 过期时间
admin-dcr-col-uses-left = 剩余次数
admin-dcr-status-active = 有效
admin-dcr-status-revoked = 已撤销
admin-dcr-status-expired = 已过期
admin-dcr-status-exhausted = 已用尽
admin-dcr-empty-prefix = 尚未签发令牌。
admin-dcr-empty-link = 签发一个
admin-dcr-empty-suffix = 以启用自助注册。
admin-dcr-action-revoke = 撤销

# DCR token new (dcr_token_new.html)
admin-dcr-new-page-title = 签发 DCR 令牌
admin-dcr-new-heading = 签发一个 DCR 初始访问令牌
admin-dcr-new-field-note = 备注
admin-dcr-new-field-note-placeholder = 这个令牌是做什么用的？（例如 “Claude Desktop for formshive”）
admin-dcr-new-field-note-hint = 可选，仅供你自己记录。客户端作者永远看不到。
admin-dcr-new-field-ttl = 有效期（小时）
admin-dcr-new-field-ttl-hint = 留空表示永不过期。
admin-dcr-new-field-max-uses = 最大使用次数
admin-dcr-new-action-cancel = 取消

# Status page (status.html)
admin-status-page-title = 状态
admin-status-heading = 系统状态
admin-status-subtitle = IdP 各组件、信使队列和构建版本的实时健康状况。
admin-status-issuer-label = 签发者
admin-status-issuer-config-link = 查看配置 →
admin-status-warning-db-label = 数据库
admin-status-warning-db-body = sqlite 搭配疑似生产环境的部署。多实例部署会损坏数据库。如需高可用请切换到 Postgres。
admin-status-warning-webhook-label = Webhook 广播
admin-status-dead-webhook-count =
    { $count ->
       *[other] { $count } 条进入死信的账号删除 Webhook 记录
    }
admin-status-dead-webhook-middle = （接收方未收到通知）。
admin-status-dead-webhook-open = 打开 /admin/webhooks
admin-status-dead-webhook-action = 以重新入队或丢弃。
admin-status-section-services = 服务
admin-status-col-service = 服务
admin-status-col-state = 状态
admin-status-col-detail = 详情
admin-status-state-up = 正常
admin-status-state-down = 不可用
admin-status-section-courier = 信使队列
admin-status-courier-pending = 待处理（已入队）
admin-status-courier-failed = 失败（已放弃）
admin-status-courier-last-webhook = 最近一次审计 Webhook
admin-status-courier-never = 从未
admin-status-section-audit = 审计
admin-status-audit-write-failures = 审计写入失败次数（自启动以来）
admin-status-audit-write-failures-note-prefix = 可从失败时 Forseti 输出的结构化
admin-status-audit-write-failures-note-suffix = stderr 行中恢复这些记录。
admin-status-audit-webhook-rejected = 审计 Webhook 被拒次数（自启动以来）
admin-status-audit-webhook-rejected-note-prefix = 载荷格式错误或动作未知，很可能是 Kratos 钩子／配置不匹配。请检查
admin-status-audit-webhook-rejected-note-suffix = warn 日志。
admin-status-audit-freshness = 审计 Webhook 时效异常次数（自启动以来）
admin-status-audit-freshness-note = 载荷被标记为过期或日期在未来，通常是流程缓慢或时钟偏差所致。记录仍会写入并加以标记。
admin-status-audit-webhook-accept-list = 审计 Webhook 接受列表条目
admin-status-audit-webhook-last-matched = 最近匹配的审计 Webhook 条目
admin-status-audit-webhook-last-matched-none = 自启动以来无匹配
admin-status-section-license = 许可证
admin-status-license-oss-prefix = 开源版部署。
admin-status-license-oss-link = 激活许可证
admin-status-license-oss-suffix = 以解锁高级功能。
admin-status-section-build = 构建版本
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = 数据库

# Configuration page (configuration.html)
admin-config-page-title = 配置
admin-config-subtitle = 此身份提供方的配置情况：OIDC 端点与能力、签名密钥，以及 Kratos 身份模式。
admin-config-discovery-warning-label = OIDC 发现
admin-config-discovery-warning-body = 无法获取 Hydra 的发现文档。在恢复可用之前，端点和能力将不予显示。
admin-config-section-oidc = OIDC 端点
admin-config-field-issuer = 签发者
admin-config-field-discovery-url = 发现文档 URL
admin-config-field-authorization = 授权
admin-config-field-token = 令牌
admin-config-field-userinfo = 用户信息
admin-config-field-jwks = JWKS
admin-config-field-end-session = 结束会话
admin-config-field-registration = 注册（DCR）
admin-config-field-revocation = 撤销
admin-config-section-capabilities = 能力
admin-config-cap-scopes = 权限范围
admin-config-cap-grant-types = 授权类型
admin-config-cap-response-types = 响应类型
admin-config-cap-token-auth-methods = 令牌端点认证方式
admin-config-cap-pkce-methods = PKCE 方式
admin-config-cap-id-token-signing-algs = ID 令牌签名算法
admin-config-cap-subject-types = 主体类型
admin-config-cap-backchannel-logout = 后端通道退出
admin-config-cap-frontchannel-logout = 前端通道退出
admin-config-cap-yes = 是
admin-config-cap-no = 否
admin-config-section-signing-keys = 签名密钥（JWKS）
admin-config-signing-keys-unavailable = 不可用：无法获取 Hydra 的公钥。
admin-config-signing-keys-empty = Hydra 未公布任何签名密钥。
admin-config-col-key-id = 密钥 ID
admin-config-col-alg = 算法
admin-config-col-type = 类型
admin-config-col-use = 用途
admin-config-section-schemas = Kratos 身份模式
admin-config-schemas-unavailable = 不可用：无法从 Kratos 获取身份模式。
admin-config-schemas-empty = 未注册身份模式。

# Audit list (audit.html)
admin-audit-page-title = 审计
admin-audit-subtitle = 仅可追加的事件日志。记录 Forseti 侧的管理操作、OAuth 授权、会话变更，以及通过 Webhook 送达的 Kratos 流程完成事件。保留期由运维人员配置（`[audit].audit_retention_days`）；清理是一个 CLI 子命令，并非自动执行。
admin-audit-filter-email = 邮箱包含
admin-audit-filter-action = 动作前缀
admin-audit-filter-severity = 严重程度
admin-audit-filter-since = 起始时间
admin-audit-severity-any = 任意
admin-audit-severity-info = 信息
admin-audit-severity-warning = 警告
admin-audit-severity-error = 错误
admin-audit-severity-critical = 严重
admin-audit-filter-button = 筛选
admin-audit-col-target = 目标
admin-audit-col-severity = 严重程度
admin-audit-col-when = 时间
admin-audit-col-actor = 操作者
admin-audit-col-action = 动作
admin-audit-col-actions = 操作
admin-audit-empty = 没有事件符合当前筛选条件。
admin-audit-badge-critical = 严重
admin-audit-badge-error = 错误
admin-audit-badge-warning = 警告
admin-audit-action-view = 查看
admin-audit-prev = ‹ 上一页
admin-audit-next = 下一页 ›

# Audit detail (audit_show.html)
admin-audit-back = ← 返回审计
admin-audit-show-section-event = 事件
admin-audit-show-outcome = 结果
admin-audit-show-success = 成功
admin-audit-show-failure = 失败
admin-audit-show-section-actor = 操作者
admin-audit-show-field-kind = 类别
admin-audit-show-field-email = 邮箱
admin-audit-show-none = 无
admin-audit-show-field-identity-id = 身份 ID
admin-audit-show-section-target = 目标
admin-audit-show-field-label = 标签
admin-audit-show-deleted = （已删除）
admin-audit-show-field-target-id = 目标 ID
admin-audit-show-section-metadata = 元数据
admin-audit-show-section-request-context = 请求上下文
admin-audit-show-field-ip-hash = IP 哈希
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = 请求 ID
admin-audit-show-field-org-id = 组织 ID

# Webhooks list (webhooks.html)
admin-webhooks-page-title = Webhook
admin-webhooks-heading = 进入死信的 Webhook
admin-webhooks-subtitle = 已耗尽重试的账号删除通知（12 次尝试或 72 小时，以先到者为准）。点击某一行可查看完整载荷和最后一次错误；若确认接收方已恢复，也可直接从摘要重新入队。
admin-webhooks-empty = 没有死信记录。一切都已送达。
admin-webhooks-col-client = 客户端
admin-webhooks-col-event = 事件
admin-webhooks-col-attempts = 尝试次数
admin-webhooks-col-age = 存在时长
admin-webhooks-col-actions = 操作
admin-webhooks-deleted = （已删除）
admin-webhooks-action-view = 查看
admin-webhooks-action-requeue = 重新入队

# Webhook detail (webhook_show.html)
admin-webhook-back = ← 返回 Webhook
admin-webhook-heading = 进入死信的 Webhook
admin-webhook-action-requeue = 重新入队
admin-webhook-action-discard = 丢弃
admin-webhook-section-delivery = 投递
admin-webhook-field-client = 客户端
admin-webhook-deleted = （已删除）
admin-webhook-field-state = 状态
admin-webhook-field-url = URL
admin-webhook-field-attempts = 尝试次数
admin-webhook-field-created = 创建时间
admin-webhook-field-next-attempt = 下次尝试
admin-webhook-section-last-error = 最后一次错误
admin-webhook-section-payload = 已签名载荷

# POSIX accounts list (posix_list.html)
admin-posix-page-title = POSIX 账户
admin-posix-subtitle = 已物化为 Linux 账户（uid/gid + SSH 密钥）的 Kratos 身份，供 NSS 解析器使用。
admin-posix-seats-label = 已用席位：
admin-posix-license-note = 商业版 Linux 认证许可证可提高上限。
admin-posix-action-provision = 开通账户
admin-posix-col-username = 用户名
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = 状态
admin-posix-col-created = 创建时间
admin-posix-empty-prefix = 没有已启用的 POSIX 账户。
admin-posix-empty-link = 从 Kratos 身份
admin-posix-empty-suffix = 开通一个。
admin-posix-status-enabled = 已启用
admin-posix-status-disabled = 已停用
admin-posix-action-manage = 管理

# POSIX account detail (posix_account.html)
admin-posix-action-disable = 停用
admin-posix-action-enable = 启用
admin-posix-action-delete = 删除
admin-posix-ssh-keys-heading = SSH 密钥
admin-posix-ssh-empty = 尚无 SSH 密钥。
admin-posix-ssh-key-added-prefix = 添加于
admin-posix-ssh-action-remove = 移除
admin-posix-ssh-field-public-key = 公钥
admin-posix-ssh-field-comment = 备注（可选）
admin-posix-ssh-action-add = 添加密钥
admin-posix-teams-heading = 团队
admin-posix-hosts-heading = 可访问的主机
admin-posix-back = ← 所有 POSIX 账户

# POSIX account new (posix_new.html)
admin-posix-new-page-title = 开通 POSIX 账户
admin-posix-new-heading = 开通一个 POSIX 账户
admin-posix-new-choose-identity = 选择要开通的身份。
admin-posix-new-action-select-user = 选择用户
admin-posix-new-or-enter-directly = 或直接输入
admin-posix-new-placeholder-id = UUID 或邮箱
admin-posix-new-action-continue = 继续
admin-posix-new-provision-intro = 将 Kratos 身份物化为 Linux 账户。系统会自动分配 uid/gid 并创建主组。
admin-posix-new-selected-prefix = 已选择：
admin-posix-new-action-change = 更改
admin-posix-new-field-username = 用户名
admin-posix-new-username-hint = 根据邮箱推荐，可自行修改。1–32 个字符，小写，以字母或下划线开头。这将成为 POSIX 登录名。
admin-posix-new-field-shell = 登录 Shell
admin-posix-new-action-cancel = 取消

# Hosts list (hosts_list.html)
admin-hosts-page-title = 主机
admin-hosts-subtitle = 已向 Forseti 的 POSIX/NSS 解析器注册的 Linux 机器。每台主机使用注册时一次性展示的密钥进行认证。
admin-hosts-action-enroll = 注册主机
admin-hosts-credential-heading = 主机凭据（仅显示一次）
admin-hosts-credential-note-prefix = 格式为
admin-hosts-credential-note-suffix = 。请立即用此凭据配置主机代理。我们不保存原始密钥，只保存其 SHA-256。
admin-hosts-col-hostname = 主机名
admin-hosts-col-teams = 团队
admin-hosts-col-force-mfa = 强制多因素
admin-hosts-col-enrolled = 注册时间
admin-hosts-col-last-seen = 最后在线
admin-hosts-empty-prefix = 尚未注册主机。
admin-hosts-empty-link = 注册一台
admin-hosts-empty-suffix = 以便它解析 POSIX 账户。
admin-hosts-status-mfa-pending = 多因素（待生效）
admin-hosts-mfa-pending-title = 已记录但尚未强制执行；强制执行将随交互式登录（PAM）一同上线。
admin-hosts-action-edit = 编辑
admin-hosts-action-rotate = 轮换
admin-hosts-action-revoke = 撤销

# Host edit (hosts_edit.html)
admin-hosts-edit-page-title = 编辑主机
admin-hosts-edit-intro = 更新主机标签、多因素标记，以及它所限定的团队。此处不显示密钥；如需新密钥，请从主机列表轮换。
admin-hosts-field-hostname = 主机名
admin-hosts-hostname-hint = 仅供你记录的标签，不必与机器的实际主机名一致。
admin-hosts-field-org = 组织
admin-hosts-org-fixed-note = 主机所属组织在注册时即已固定，无法在此更改。
admin-hosts-field-allowed-teams = 允许的团队
admin-hosts-teams-empty = 尚不存在任何团队。此主机允许任意组织成员访问。将主机限定到特定团队需要组织功能。
admin-hosts-teams-hint = 将此主机限制为所选团队的成员。不选则允许任意组织成员。
admin-hosts-field-force-mfa = 在此主机上强制多因素认证
admin-hosts-force-mfa-hint = 现在仅作记录；交互式登录（PAM）上线后即会强制执行。
admin-hosts-action-cancel = 取消

# Host new (hosts_new.html)
admin-hosts-new-heading = 注册一台 Linux 主机
admin-hosts-new-intro-prefix = 一次性密钥将在下一页显示一次。请用它显示的
admin-hosts-new-intro-suffix = 凭据配置主机代理。
admin-hosts-org-belongs-hint = 该主机属于此组织。注册后即固定。
admin-hosts-new-teams-empty = 尚不存在任何团队。此主机将允许任意组织成员访问。将主机限定到特定团队需要组织功能。
admin-hosts-new-teams-scope-hint = 将此主机限制为所选团队的成员。仅所选组织下的团队生效；不选则允许任意组织成员。

# SAML SSO list (saml_list.html)
admin-saml-page-title = SAML 单点登录
admin-saml-subtitle = 企业 SAML 连接，每个组织一条。IdP 元数据和证书存放在 Jackson 中；Forseti 只保留锚点记录和启用开关。
admin-saml-action-new = 新建连接
admin-saml-grace-notice = 许可证处于宽限期。在续期之前，SAML 连接为只读。单点登录仍可正常使用。
admin-saml-col-org = 组织
admin-saml-col-connection = 连接
admin-saml-col-sso-url = SSO URL
admin-saml-col-enabled = 已启用
admin-saml-empty-prefix = 尚无 SAML 连接。
admin-saml-empty-link = 创建一条
admin-saml-empty-suffix = 以为某个组织启用单点登录。
admin-saml-status-enabled = 已启用
admin-saml-status-disabled = 已停用
admin-saml-action-disable = 停用
admin-saml-action-enable = 启用
admin-saml-action-delete = 删除
admin-saml-idp-values-heading = 提供给客户 IdP 管理员的值
admin-saml-idp-values-intro = 请把这些交给在身份提供方一侧配置 SAML 应用的人。它们对每条连接都相同。
admin-saml-idp-acs-url = ACS URL
admin-saml-idp-entity-id = SP 实体 ID

# Audit pagination
admin-audit-range = 显示第 { $from }–{ $to } 条，共 { $total } 条。
admin-audit-page = 第 { $page } 页
admin-saml-entity-id-note-prefix = 实体 ID 取决于 Jackson 的
admin-saml-entity-id-note-suffix = 设置；若你覆盖了默认值，请在那里修改。

# SAML SSO new connection (saml_new.html)
admin-saml-new-page-title = 新建 SAML 连接
admin-saml-new-intro = 将一个组织连接到它的身份提供方。粘贴 IdP 的元数据 XML，或给出一个由 Jackson 自行抓取的元数据 URL：二者只能选其一。
admin-saml-new-field-org = 组织
admin-saml-new-org-hint = 每个组织一条连接。
admin-saml-new-field-name = 连接名称
admin-saml-new-name-hint = 仅供你记录；成员永远看不到。
admin-saml-new-field-metadata-url = 元数据 URL
admin-saml-new-metadata-url-hint = 若在下方粘贴原始 XML，请留空。
admin-saml-new-metadata-url-https-note = Jackson 只抓取 HTTPS（或 localhost）元数据 URL。若 IdP 元数据是纯 HTTP，请改为在下方粘贴 XML。
admin-saml-new-field-metadata-xml = 元数据 XML
admin-saml-new-metadata-xml-hint = 若使用上方的元数据 URL，请留空。
admin-saml-new-action-create = 创建连接
admin-saml-new-action-cancel = 取消

# Inline-code splits (item 8: 2+ code elements per string)

# client_form.html - response-types hint (code: code, token)
admin-client-field-response-types-hint-part1 = 以逗号分隔，例如
admin-client-field-response-types-hint-part2 = （授权码）或
admin-client-field-response-types-hint-part3 = （客户端凭据）。

# client_form.html - audience hint (code: audience=<value>)
admin-client-field-audience-hint-part1 = 每行一条。Hydra 要求 audience 值必须先在此处注册（它尚不支持 RFC 8707）。客户端在授权请求上传递
admin-client-field-audience-hint-part2 = 。

# client_form.html - PKCE hint (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = 全局强制设置位于
admin-client-field-pkce-hint-part2 = （
admin-client-field-pkce-hint-part3 = ）。此标记仅表示运维意图。

# client_form.html + client_show.html - webhook hint (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = 当用户自行删除账号时，Forseti 会向此处 POST 一个符合 RFC 8417 的安全事件令牌（RISC
admin-client-field-webhook-hint-part2 = ）。留空即表示不接收。接收方可用 Forseti 的 JWKS 校验该 JWS，地址为
admin-client-field-webhook-hint-part3 = 。

# client_show.html - undocumented scopes desc (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = 这些权限范围已注册在此客户端上，但在
admin-client-undoc-scopes-desc-part2 = 的
admin-client-undoc-scopes-desc-part3 = 中没有对应条目。授权页面会回退为显示其原始名称。

# client_show.html - discovery error (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = 无法访问 Hydra 的发现端点，因此隐藏了签发者和各端点，以免显示错误的值。你可以自行从以下地址获取
admin-client-discovery-error-part2 = 。

# client_show.html - edit section intro (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = 在下方更新客户端字段。更改通过 Hydra 的
admin-client-edit-intro-part2 = 推送；无关字段会被保留。

# dcr_tokens_list.html - subtitle (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = 用于授权
admin-dcr-subtitle-part2 = 的 Bearer 令牌。把它交给 MCP 客户端作者，他们就能自助注册，无需你手动操作。

# dcr_tokens_list.html - revealed-token desc (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = 请把它分享给客户端作者。他们在调用
admin-dcr-revealed-desc-part2 = 时以
admin-dcr-revealed-desc-part3 = 的形式发送。我们不保存原始值，只保存其 SHA-256。

# dcr_token_new.html - subtitle (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = 令牌将在下一页显示一次。请交给客户端作者。他们会在单次
admin-dcr-new-subtitle-part2 = 调用中以
admin-dcr-new-subtitle-part3 = 的形式发送。

# dcr_token_new.html - max-uses hint (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = 留空表示不限次数。单次使用（
admin-dcr-new-field-max-uses-hint-part2 = ）是最安全的默认值。

# client_type_picker.html - popular-apps desc (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = 已针对已知应用预填。URL 使用
admin-client-type-popular-desc-part2 = （有时还有
admin-client-type-popular-desc-part3 = ）作为占位符。进入表单后请替换为你自己应用的值。

# posix_account.html - SSH keys paragraph (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = 此处添加的公钥会提供给设备的 sshd（
admin-posix-ssh-keys-desc-part2 = ），使该用户可以用自己的密钥
admin-posix-ssh-keys-desc-part3 = 登录，无需每台主机的
admin-posix-ssh-keys-desc-part4 = 文件。这需要主机的 sshd 钩子（由
admin-posix-ssh-keys-desc-part5 = Guix 服务自动配置；其他发行版需手动配置 sshd）。不用于控制台／PAM 登录。

# posix_new.html - shell hint (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = 必须存在于提供该账户的设备上；
admin-posix-new-shell-hint-part2 = 是跨发行版的安全默认值（Guix 没有
admin-posix-new-shell-hint-part3 = ）。主目录由主目录前缀加用户名推导得出。

# saml_list.html - not-configured block (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = 未配置
admin-saml-not-configured-part2 = 请将 Jackson 桥接设置添加到
admin-saml-not-configured-part3 = 以启用 SAML 单点登录。参见
admin-saml-not-configured-part4 = 。

# Admin flash messages (shown as banner after a redirect)
flash-identity-disabled = 身份已停用。
flash-identity-enabled = 身份已启用。
flash-session-revoked = 会话已撤销。
flash-client-create-failed = 创建客户端失败：{ $error }
flash-client-account-deletion-url-rejected = 账号删除 URL 被拒绝：{ $error }
flash-client-secret-stage-failed = 客户端已创建，但无法暂存密钥以供一次性展示。请轮换密钥以获取新值。
