# Поверхность онбординга (шаблоны claim_email и invite)

# Письмо для подтверждения права (claim_email.html)
claim-page-title = Подтверждение права на почту
claim-card-title = Подтвердить право на адрес электронной почты
claim-subtitle = Если кто-то зарегистрировал вашу почту, но так и не подтвердил её, вы можете стать её владельцем, подтвердив, что получаете письма на этот адрес.
claim-email-label = Эл. почта
claim-send-code = Отправить код
claim-changed-mind = Передумали?
claim-back-to-signup = Назад к регистрации

# Подтверждение права (claim_email_confirm.html)
claim-confirm-page-title = Подтверждение права
claim-confirm-card-title = Подтвердите ваш код
claim-confirm-subtitle = Введите 6-значный код, который мы только что отправили. Коды истекают через 15 минут.
claim-confirm-code-label = Код
claim-confirm-button = Подтвердить
claim-confirm-no-code = Не получили код?
claim-confirm-start-over = Начать заново

# Принятие приглашения (invite/accept.html)
invite-accept-page-title = Принять приглашение
invite-accept-heading = Присоединиться к { $org }
invite-accept-body = Вас пригласили присоединиться к { $org } в роли { $role }. Приглашение было отправлено на { $email }.

# Приглашение недоступно (invite/invalid.html)
invite-invalid-page-title = Приглашение недоступно
invite-invalid-heading = Приглашение недоступно
invite-invalid-contact = Свяжитесь с тем, кто вас пригласил, чтобы запросить новую ссылку.
invite-invalid-back = Назад к панели управления

# Ошибки процесса подтверждения права на почту (заданы в Rust)
claim-error-invalid-email = Введите действительный адрес электронной почты.
claim-error-code-expired = Срок действия кода истёк. Начните заново.
claim-error-invalid-token = Недействительный токен. Начните заново.
claim-error-service-unavailable = Служба временно недоступна. Повторите попытку через мгновение.
claim-error-too-many-attempts = Слишком много неверных кодов. Начните заново.
claim-error-code-mismatch = Код не совпал. Попробуйте снова.
claim-error-no-longer-claimable = Право на эту почту больше нельзя подтвердить.
claim-error-release-failed = Не удалось освободить почту. Обратитесь в поддержку.

# Завершение приглашения (задано в Rust)
invite-error-corrupt = Приглашение повреждено. Обратитесь к вашему администратору.
