# Страница ошибки
error-reference-id = Идентификатор ссылки:
error-cta-back-to-sign-in = Назад ко входу

# Подтверждение выхода OAuth
logout-card-title = Выйти из всех приложений?
logout-card-subtitle = Это завершит ваш сеанс в { $brand } и уведомит все приложения, в которые вы вошли.
logout-body-text = Приложение, запросившее ваш выход, получит уведомление о завершении запроса. Некоторые приложения могут ненадолго сохранить данные в кэше; выход здесь завершает сеанс в { $brand }.
logout-action-sign-out = Выйти
logout-action-cancel = Отмена

# Заголовки и тексты диалогов администратора, используемые render_admin_error в местах вызова с локалью.
# Места вызова без локали (вспомогательные функции, границы ошибок) сохраняют свои английские литералы.
dialog-identity-unavailable-title = Личность недоступна
dialog-identity-unavailable-body = Не удалось загрузить эту личность. Возможно, она была удалена.
dialog-recovery-code-failed-title = Ошибка кода восстановления
dialog-recovery-code-failed-body = Мы создали код восстановления, но не смогли подготовить его для одноразового показа. Сгенерируйте новый код и повторите попытку.
dialog-disable-failed-title = Не удалось отключить
dialog-enable-failed-title = Не удалось включить
dialog-delete-failed-title = Не удалось удалить
dialog-revoke-failed-title = Не удалось отозвать

# Граница ошибок (error_boundary.html), заголовок/текст/CTA задаются в обработчиках Rust.
error-boundary-auth-unavailable-title = Аутентификация недоступна
error-boundary-auth-unavailable-body = Не удалось связаться со службой аутентификации. Пожалуйста, повторите попытку через мгновение.
error-boundary-cta-try-again = Повторить попытку
error-boundary-cta-sign-in = Войти
error-boundary-cta-back-to-settings = Назад к настройкам
error-boundary-cta-back-to-dashboard = Назад к панели управления
error-boundary-cta-back-to-account = Назад к аккаунту
error-boundary-signin-title = Вход недоступен
error-boundary-signup-title = Регистрация недоступна
error-boundary-recovery-title = Восстановление недоступно
error-boundary-verification-title = Подтверждение недоступно
error-boundary-settings-title = Настройки недоступны
error-boundary-logout-title = Выход недоступен
error-boundary-logout-body = Не удалось завершить ваш выход, так как служба аутентификации недоступна. Ваш сеанс всё ещё активен, поэтому повторите попытку через мгновение.
error-boundary-sessions-title = Сеансы недоступны
error-boundary-sessions-body = Не удалось получить список ваших активных сеансов. Пожалуйста, повторите попытку через мгновение.
error-boundary-authorized-apps-title = Авторизованные приложения недоступны
error-boundary-authorized-apps-no-session-body = Не удалось прочитать ваш сеанс. Пожалуйста, войдите снова.
error-boundary-authorized-apps-service-body = Не удалось связаться со службой OAuth. Пожалуйста, повторите попытку через мгновение.
error-boundary-account-deletion-title = Не удалось удалить аккаунт
error-boundary-account-delete-bad-session = Ваш сеанс находится в неожиданном состоянии. Пожалуйста, войдите снова и повторите попытку.
error-boundary-account-delete-sole-owner = Вы единственный владелец { $names }. Передайте права владельца другому участнику, прежде чем удалять свой аккаунт.
error-boundary-account-delete-ownership-check-failed = Не удалось проверить ваше право владения организацией. Ничего не изменено; пожалуйста, повторите попытку через мгновение.
error-boundary-account-delete-consent-unreachable = Не удалось связаться со службой согласия, чтобы уведомить ваши подключённые приложения. Ничего не изменено; пожалуйста, повторите попытку через мгновение.
error-boundary-account-delete-notifications-failed = Не удалось подготовить уведомления об удалении. Ничего не изменено; пожалуйста, повторите попытку.
error-boundary-account-delete-failed = Не удалось удалить ваш аккаунт. Пожалуйста, повторите попытку через мгновение.

# Граница ошибок SAML (отображается под локалью по умолчанию; обратный вызов ACS не несёт локали запроса).
error-boundary-sso-unavailable-title = Единый вход недоступен
error-boundary-sso-unavailable-body = Единый вход недоступен для этого адреса. Проверьте ссылку, которую дал вам администратор, или войдите привычным способом.
error-boundary-sso-failed-title = Ошибка единого входа
error-boundary-sso-validation-failed-body = Эту попытку входа не удалось проверить. Начните заново по ссылке единого входа вашей организации.
error-boundary-sso-upstream-failed-body = Служба входа временно недоступна. Пожалуйста, повторите попытку.
error-boundary-sso-no-email-body = Провайдер идентификации не предоставил адрес электронной почты. Попросите администратора сопоставить атрибут email в подключении SAML.

# Страница ошибки самообслуживания Kratos (error.html), запасные значения задаются в Rust.
error-page-generic-title = Что-то пошло не так
error-page-generic-body = Не удалось загрузить запрошенную страницу. Возможно, срок действия ссылки истёк или она уже была использована.
error-page-link-expired-title = Срок действия ссылки истёк
error-page-link-expired-body = Эта ссылка больше недействительна. Пожалуйста, начните заново со входа.
error-page-security-title = Проверка безопасности не пройдена
error-page-already-signed-in-title = Вход уже выполнен
error-page-default-message = Не удалось выполнить этот запрос.

# Страница запрета доступа администратора (admin/forbidden.html), задаётся в Rust.
error-admin-access-denied-title = Доступ запрещён
error-admin-access-denied-body = Ваш аккаунт не имеет прав на использование инструментов администратора.
error-admin-access-denied-forseti-body = Ваш аккаунт не имеет прав на использование общесистемных инструментов администратора Forseti.
error-admin-access-denied-org-body = У вас нет прав администратора в этой организации.

# SAML заблокирован
error-saml-blocked-page-title = Вход заблокирован
error-saml-blocked-card-title = Не удалось выполнить вход
error-saml-unverified-prefix = Аккаунт для
error-saml-unverified-suffix = уже существует, но его адрес электронной почты не подтверждён, поэтому единый вход не может безопасно к нему привязаться. Подтвердите адрес по исходному письму о регистрации или обратитесь за помощью к администратору.
error-saml-cross-org-not-member = Ваш аккаунт пока не является участником этой организации. Попросите администратора добавить вас, затем повторите попытку.
error-saml-conflict = Не удалось выполнить вход. Пожалуйста, обратитесь к вашему администратору.
error-saml-blocked-cta = Перейти ко входу
