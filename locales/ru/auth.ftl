# Страница входа
auth-login-page-title = Вход
auth-login-card-title = Вход в ваш аккаунт
auth-login-card-subtitle = С возвращением в { $brand }.
auth-login-aal2-body = Этот раздел требует двухфакторной аутентификации, но в вашем аккаунте ещё не настроен второй фактор.
auth-login-aal2-hint = Настройте приложение-аутентификатор, ключ безопасности или коды восстановления в настройках, а затем вернитесь.
auth-login-aal2-setup-link = Настроить двухфакторную аутентификацию
auth-login-forgot-password = Забыли пароль?
auth-login-no-account = Нет аккаунта?
auth-login-create-account = Создать аккаунт

# Общий разделитель (вход + регистрация)
auth-or-continue-with = Или продолжить через

# Страница регистрации
auth-registration-page-title = Создать аккаунт
auth-registration-card-title = Создание аккаунта
auth-registration-card-subtitle = Зарегистрируйтесь, чтобы безопасно управлять своей учётной записью.
auth-registration-have-account = Уже есть аккаунт?
auth-registration-sign-in-link = Войти
auth-registration-claim-body = Если это ваша почта и вы так и не завершили регистрацию,
auth-registration-claim-link = подтвердите право на неё

# Страница восстановления
auth-recovery-page-title = Восстановление аккаунта
auth-recovery-card-title-sent = Проверьте почту
auth-recovery-card-title-default = Забыли пароль?
auth-recovery-card-subtitle-sent = Мы отправили код восстановления на вашу почту. Введите его ниже, чтобы продолжить.
auth-recovery-card-subtitle-default = Введите адрес электронной почты, и мы отправим вам ссылку для сброса пароля.
auth-recovery-back-to-sign-in = Назад ко входу

# Страница подтверждения
auth-verification-page-title = Подтверждение почты
auth-verification-card-title-passed = Почта подтверждена
auth-verification-card-title-sent = Проверьте почту
auth-verification-card-title-default = Подтвердите почту
auth-verification-card-subtitle-passed = Ваш адрес электронной почты подтверждён. Вы можете закрыть эту вкладку или продолжить.
auth-verification-card-subtitle-sent = Мы отправили код подтверждения на вашу почту. Введите его ниже, чтобы подтвердить.
auth-verification-card-subtitle-default = Введите адрес электронной почты, чтобы получить код подтверждения.
auth-verification-sent-email-hint = Используйте код из последнего письма с подтверждением или откройте ссылку в этом письме вместо ручного ввода кода.
auth-verification-back-to-dashboard = Назад к панели управления
auth-verification-back-to-sign-in = Назад ко входу

# Строки на стороне браузера для WebAuthn / passkey (встроены через data-атрибуты в webauthn_helper.html)
auth-webauthn-no-support = Ваш браузер не поддерживает WebAuthn / passkey.
auth-passkey-needs-platform = Для входа по passkey нужна платформенная учётная запись на этом устройстве (Touch ID, Windows Hello, устройство Android или синхронизированный passkey). В вашем браузере она не настроена.
auth-webauthn-err-not-allowed = Запрос учётных данных был отменён, истёк по времени или подходящих учётных данных не нашлось.
auth-webauthn-err-security = Ваш браузер отклонил операцию безопасности. Убедитесь, что сайт загружен из доверенного источника и зарегистрированный идентификатор совпадает.
auth-webauthn-err-invalid-state = На этом устройстве уже зарегистрированы учётные данные. Попробуйте войти или используйте другое устройство.
auth-webauthn-err-not-supported = Ваш браузер не поддерживает запрошенные параметры учётных данных.
auth-webauthn-err-abort = Запрос учётных данных был прерван до завершения.
auth-webauthn-err-generic-prefix = Ошибка аутентификатора:

# Подписи полей формы. Kratos выдаёт поля trait со схемным `title` под общим
# сквозным идентификатором подписи 1070002; flow_view.rs переопределяет их по имени.
auth-field-email = Эл. почта
auth-field-first-name = Имя
auth-field-last-name = Фамилия
