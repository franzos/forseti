# Device authorization (RFC 8628) verify and done screens

device-verify-page-title = 批准 Linux 登录
device-verify-card-title = 批准一次 Linux 登录
device-verify-prompt = 这次登录是你刚刚发起的吗？
device-verify-host = 以 { $user } 身份登录主机 { $host }（主机 { $hostid }）。
device-verify-warning = 只有在你本人于该机器上发起时才批准。如果不是你，请关闭本页面 - 批准会让发起者以 { $user } 的身份登录。
device-verify-approve = 是我本人 - 继续
device-verify-cancel = 不是，取消
device-verify-code-prompt = 输入终端上显示的代码以继续。
device-verify-code-submit = 继续

device-verify-foreign-prompt = 这次登录不属于你的账户。
device-verify-foreign-body = 有人为另一个账户发起了这次登录。如果是你本人，请改用该账户登录后重新打开链接。
device-verify-foreign-cancel = 取消这次登录

device-done-title-cancelled = 登录已取消
device-done-card-title-cancelled = 登录已取消
device-done-body-cancelled = 已通知发起这次登录的终端：请求被拒绝。

device-done-title-error = 登录未获批准
device-done-title-ok = 登录已批准
device-done-card-title-error = 无法批准该登录
device-done-card-title-ok = 已批准
device-done-body-error = 该代码可能已过期或已被使用。请在终端上重新发起登录以获取新代码。
device-done-body-ok = 你可以返回终端，登录将在那里继续。
device-done-body-safe = 现在可以安全关闭本页面。
