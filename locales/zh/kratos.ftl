# Kratos flow messages keyed by stable numeric ID.
# Passthrough (NOT in this catalog): 4000001 (generic validation - text IS the payload).
# En text matches Ory Kratos OSS English where Fluent allows it; expired-flow messages
# use simplified text because Fluent cannot compute %.2f minutes from a unix timestamp.

# --- Login (1010xxx) ---
kratos-1010001 = 登录
kratos-1010002 = 使用 { $provider } 登录
kratos-1010003 = 请验证身份以确认此操作。
kratos-1010004 = 请完成第二重身份验证。
kratos-1010005 = 验证
kratos-1010006 = 验证代码
kratos-1010007 = 备用恢复代码
kratos-1010008 = 使用硬件密钥登录
kratos-1010009 = 使用身份验证器
kratos-1010010 = 使用备用恢复代码
kratos-1010011 = 使用硬件密钥登录
kratos-1010012 = 准备好你的 WebAuthn 设备（如安全密钥、生物识别扫描器等），然后点击继续。
kratos-1010013 = 继续
kratos-1010014 = 代码已发送至你提供的地址。如果没有收到，请检查地址拼写后重试。
kratos-1010015 = 发送登录代码
kratos-1010021 = 使用通行密钥登录
kratos-1010022 = 使用密码登录

# --- Registration (1040xxx) ---
kratos-1040001 = 注册
kratos-1040002 = 使用 { $provider } 注册
kratos-1040003 = 继续
kratos-1040004 = 使用安全密钥注册
kratos-1040005 = 代码已发送至你提供的地址。如果没有收到邮件，请检查地址拼写，并确认使用的是注册时的地址。
kratos-1040006 = 发送注册代码
kratos-1040007 = 使用通行密钥注册
kratos-1040008 = 返回

# --- Settings (1050xxx) ---
kratos-1050001 = 你的更改已保存！
kratos-1050002 = 关联 { $provider }
kratos-1050003 = 解除关联 { $provider }
kratos-1050004 = 解除关联 TOTP 身份验证器应用
kratos-1050007 = 显示备用恢复代码
kratos-1050008 = 生成新的备用恢复代码
kratos-1050010 = 这些是你的备用恢复代码。请妥善保管！
kratos-1050011 = 确认备用恢复代码
kratos-1050012 = 添加安全密钥
kratos-1050013 = 安全密钥名称
kratos-1050016 = 停用此方式
kratos-1050017 = 这是你的身份验证器应用密钥。如果无法扫描二维码，请使用它。
kratos-1050018 = 移除安全密钥“{ $display_name }”
kratos-1050019 = 添加通行密钥
kratos-1050020 = 移除通行密钥“{ $display_name }”
kratos-1050023 = 你的账号由所在组织管理。如需更改这些设置，请联系组织管理员。

# --- Recovery (1060xxx) ---
# 1060001: Ory text has "within the next %.2f minutes" but context carries a
# timestamp, not minutes. Simplified here; fallback gives Ory's exact English.
kratos-1060001 = 你已成功恢复账号。请尽快修改密码或设置其他登录方式（如社交账号登录）。
kratos-1060002 = 包含恢复链接的邮件已发送至你提供的邮箱地址。如果没有收到邮件，请检查地址拼写，并确认使用的是注册时的地址。
kratos-1060003 = 包含恢复代码的邮件已发送至你提供的邮箱地址。如果没有收到邮件，请检查地址拼写，并确认使用的是注册时的地址。
kratos-1060004 = 恢复代码已发送至 { $masked_address }。如果没有收到，请检查地址拼写，并确认使用的是注册时的地址。

# --- Node labels (1070xxx) ---
kratos-1070001 = 密码
kratos-1070003 = 保存
kratos-1070004 = ID
kratos-1070005 = 提交
kratos-1070006 = 验证代码
kratos-1070007 = 邮箱
kratos-1070008 = 重新发送代码
kratos-1070009 = 继续
kratos-1070010 = 恢复代码
kratos-1070011 = 验证代码
kratos-1070012 = 注册代码
kratos-1070013 = 登录代码
kratos-1070016 = 恢复地址

# --- Verification (1080xxx) ---
kratos-1080001 = 包含验证链接的邮件已发送至你提供的邮箱地址。如果没有收到邮件，请检查地址拼写，并确认使用的是注册时的地址。
kratos-1080002 = 你已成功验证邮箱地址。
kratos-1080003 = 包含验证代码的邮件已发送至你提供的邮箱地址。如果没有收到邮件，请检查地址拼写，并确认使用的是注册时的地址。

# --- Validation errors (4000xxx) ---
# 4000001 is passthrough: text IS the dynamic validation reason.
kratos-4000002 = 缺少属性 { $property }。
kratos-4000003 = 长度必须 >= { $min_length }，实际为 { $actual_length }
# 4000005: $reason comes from Kratos policy config; it will be in English within a translated sentence.
kratos-4000005 = 该密码不可用，原因：{ $reason }。
kratos-4000006 = 提供的凭据无效，请检查密码、用户名、邮箱地址或电话号码是否有拼写错误。
kratos-4000007 = 已存在使用相同标识（邮箱、电话、用户名等）的账号。
kratos-4000008 = 提供的验证代码无效，请重试。
kratos-4000032 = 密码长度至少为 { $min_length } 个字符，实际为 { $actual_length }。
kratos-4000035 = 该账号不存在，或未设置代码登录。

# --- Login flow errors (4010xxx) ---
# Simplified: Ory computes "X.XX minutes ago" from a timestamp we cannot format in Fluent.
kratos-4010001 = 登录流程已过期，请重试。
kratos-4010008 = 登录代码无效或已被使用。请重试。

# --- Registration flow errors (4040xxx) ---
kratos-4040001 = 注册流程已过期，请重试。
kratos-4040003 = 注册代码无效或已被使用。请重试。

# --- Settings flow errors (4050xxx) ---
kratos-4050001 = 设置流程已过期，请重试。

# --- Recovery flow errors (4060xxx) ---
kratos-4060004 = 恢复令牌无效或已被使用。请重新开始该流程。
kratos-4060006 = 恢复代码无效或已被使用。请重试。

# --- Verification flow errors (4070xxx) ---
kratos-4070001 = 验证令牌无效或已被使用。请重新开始该流程。
kratos-4070005 = 验证流程已过期，请重试。
kratos-4070006 = 验证代码无效或已被使用。请重试。
