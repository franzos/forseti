settings-hub-title = Настройки
settings-hub-subtitle = Управляйте настройками аккаунта, параметрами безопасности и активными сеансами.
settings-hub-profile-title = Профиль
settings-hub-profile-desc = Обновите адрес электронной почты и отображаемое имя.
settings-hub-profile-link = Управление профилем
settings-hub-password-title = Пароль
settings-hub-password-desc = Измените пароль вашего аккаунта.
settings-hub-password-link = Изменить пароль
settings-hub-2fa-title = Двухфакторная аутентификация
settings-hub-2fa-desc = Настройте TOTP, коды восстановления и ключи безопасности.
settings-hub-2fa-link = Управление 2FA
settings-hub-sessions-title = Активные сеансы
settings-hub-sessions-desc = Просмотрите устройства, вошедшие в ваш аккаунт.
settings-hub-sessions-link = Показать сеансы
settings-hub-apps-title = Авторизованные приложения
settings-hub-apps-desc = Просматривайте и отзывайте приложения OAuth, которым вы предоставили доступ.
settings-hub-apps-link = Управление приложениями
settings-hub-providers-title = Связанные провайдеры
settings-hub-providers-desc = Подключайте или удаляйте сторонние провайдеры входа.
settings-hub-providers-link = Управление провайдерами
settings-hub-account-title = Аккаунт
settings-hub-account-desc = Необратимые изменения: удаление аккаунта.
settings-hub-account-link = Опасная зона
settings-nav-general = Общие
settings-nav-security = Безопасность
settings-nav-connections = Подключения
settings-nav-overview = Обзор
settings-nav-profile = Профиль
settings-nav-organization = Организация
settings-nav-password = Пароль
settings-nav-2fa = 2FA
settings-nav-sessions = Сеансы
settings-nav-offline = Автономный вход
settings-nav-authorized-apps = Авторизованные приложения
settings-nav-linked-providers = Связанные провайдеры
settings-nav-account = Аккаунт

# Подстраница профиля
settings-profile-heading = Профиль
settings-profile-subtitle = Обновите адрес электронной почты и отображаемое имя.
settings-profile-email-not-verified = Не подтверждён
settings-profile-email-send-verification = Отправить письмо с подтверждением
settings-profile-public-heading = Публичный профиль
settings-profile-public-saved = Профиль сохранён.
settings-profile-public-label-bio = О себе
settings-profile-public-label-location = Местоположение
settings-profile-public-label-pronouns = Местоимения
settings-profile-public-label-website = Веб-сайт
settings-profile-public-label-avatar = URL аватара
settings-profile-public-avatar-hint = Необязательно. Оставьте пустым, чтобы использовать автоматически сгенерированный идентикон.
settings-profile-public-label-links = Ссылки
settings-profile-public-save = Сохранить профиль
settings-profile-back = Назад к настройкам
settings-profile-language-label = Предпочитаемый язык
settings-profile-language-help = Применяется на всех ваших устройствах.

# Подстраница пароля
settings-password-heading = Пароль
settings-password-subtitle = Измените пароль, используемый для входа.
settings-password-back = Назад к настройкам

# Подстраница аккаунта
settings-account-heading = Аккаунт
settings-account-subtitle = Необратимые изменения вашего аккаунта.
settings-account-delete-section-heading = Удалить аккаунт
settings-account-delete-body = Безвозвратно удалите ваш аккаунт, каждый активный сеанс и все данные 2FA / восстановления. Приложения, хранящие копии ваших данных, будут уведомлены, чтобы очистить их со своей стороны. Это действие нельзя отменить.
settings-account-delete-action = Удалить мой аккаунт

# Страница подтверждения удаления аккаунта
settings-account-delete-page-title = Подтверждение удаления
settings-account-delete-confirm-heading = Удалить ваш аккаунт?
settings-account-delete-confirm-subtitle-prefix = Это безвозвратно удалит
settings-account-delete-confirm-subtitle-suffix = а также все связанные с ним сеансы, коды восстановления и учётные данные.
settings-account-delete-apps-heading = Эти приложения будут уведомлены о вашем удалении
settings-account-delete-apps-note = Приложения копируют нужные им данные (профиль, настройки) и связывают их с ID вашего аккаунта. Мы уведомляем их через зарегистрированный ими веб-хук удаления, чтобы они могли очистить свою копию.
settings-account-delete-no-apps = Сейчас ни у одного стороннего приложения нет копий ваших данных. Уведомлять некого.
settings-account-delete-confirm-label = Для подтверждения введите ваш адрес электронной почты ниже:
settings-account-delete-confirm-placeholder = Введите вашу почту для подтверждения
settings-account-delete-confirm-submit = Да, удалить мой аккаунт
settings-account-delete-confirm-cancel = Отмена

# Подстраница автономного доступа
settings-offline-heading = Автономный вход на хост
settings-offline-subtitle = Задайте отдельную парольную фразу, позволяющую входить в терминал зарегистрированного хоста Linux, когда он не может связаться с этим сервером. Она отделена от пароля вашего аккаунта. Используйте что-то, что запомните, но не стали бы использовать повторно.
settings-offline-status-set-prefix = Автономная парольная фраза
settings-offline-status-set-word = задана
settings-offline-status-set-suffix = . Введите новую ниже, чтобы изменить её, или удалите её полностью.
settings-offline-status-unset = Автономная парольная фраза ещё не задана. Без неё вы не сможете войти на зарегистрированный хост, пока он не в сети.
settings-offline-label-new-passphrase = Новая автономная парольная фраза
settings-offline-label-passphrase = Автономная парольная фраза
settings-offline-passphrase-hint = Не менее { $min_len } символов. Не используйте повторно пароль вашего аккаунта.
settings-offline-action-change = Изменить парольную фразу
settings-offline-action-set = Задать парольную фразу
settings-offline-remove-heading = Удалить автономный доступ
settings-offline-remove-body = Удалите вашу автономную парольную фразу. Зарегистрированные хосты удалят её при следующей синхронизации, и вы больше не сможете входить на них, пока они не в сети.
settings-offline-action-remove = Удалить парольную фразу
settings-offline-back = Назад к настройкам

# Передача пароля (восстановление → установка нового пароля)
settings-handoff-heading = Задать новый пароль
settings-handoff-subtitle = Вы вошли по коду восстановления. Выберите новый пароль, чтобы завершить.
settings-handoff-countdown-label = Оставшееся время для установки нового пароля:
settings-handoff-sign-out = Выйти без изменения

# Подстраница 2FA
settings-2fa-heading = Двухфакторная аутентификация
settings-2fa-subtitle = Усильте защиту вашего аккаунта вторым фактором.
settings-2fa-no-recovery-warning-heading = Нет кодов восстановления: вы рискуете потерять доступ
settings-2fa-no-recovery-warning-body = Двухфакторная аутентификация включена, но у вас нет кодов восстановления. Если вы потеряете аутентификатор или ключ безопасности, коды восстановления — единственный способ вернуться в аккаунт. Сгенерируйте их сейчас.
settings-2fa-no-recovery-warning-action = Сгенерировать коды
settings-2fa-totp-heading = Приложение-аутентификатор (TOTP)
settings-2fa-totp-desc = Используйте приложение вроде 1Password, Bitwarden, Aegis или Authy для генерации 6-значных кодов.
settings-2fa-totp-enabled = Включено
settings-2fa-totp-scan-hint = Отсканируйте этот QR-код приложением-аутентификатором или введите секретный ключ вручную:
settings-2fa-totp-not-offered = Настройка приложения-аутентификатора сейчас не предлагается вашим сервером.
settings-2fa-recovery-heading = Коды восстановления
settings-2fa-recovery-desc = Одноразовые коды, позволяющие войти, если вы потеряете доступ к аутентификатору.
settings-2fa-recovery-active = Активны
settings-2fa-recovery-save-strong = Сохраните их сейчас.
settings-2fa-recovery-save-suffix = Они больше не будут показаны. Храните их в надёжном месте. Хорошо подойдёт менеджер паролей.
settings-2fa-recovery-not-offered = Коды восстановления сейчас не предлагаются вашим сервером.
settings-2fa-webauthn-heading = Ключи безопасности и passkey
settings-2fa-webauthn-desc = Используйте аппаратный ключ (YubiKey, Titan) или платформенный passkey (Touch ID, Windows Hello) в качестве второго фактора.
settings-2fa-webauthn-remove-fallback = Удалить ключ безопасности
settings-2fa-webauthn-not-enabled = Поддержка passkey не включена вашим администратором.
settings-2fa-back = Назад к настройкам

# Подстраница сеансов
settings-sessions-heading = Активные сеансы
settings-sessions-subtitle = Устройства, в данный момент вошедшие в ваш аккаунт. Отзовите те, которые вы не узнаёте.
settings-sessions-revoke-action = Выйти
settings-sessions-revoke-others-heading = Выйти на всех других устройствах
settings-sessions-revoke-others-desc = Сохраняет этот сеанс активным и отзывает все остальные.
settings-sessions-revoke-others-action = Выйти на других
settings-sessions-back = Назад к настройкам

# Подстраница авторизованных приложений
settings-apps-heading = Авторизованные приложения
settings-apps-subtitle = Приложения, которым вы предоставили доступ к аккаунту. Отзовите те, которыми больше не пользуетесь. При следующем входе им придётся снова запросить разрешение.
settings-apps-empty = Пока ни одному приложению не предоставлен доступ к вашему аккаунту.
settings-apps-verified-label = Проверено
settings-apps-access-granted-prefix = Доступ предоставлен
settings-apps-revoke-action = Отозвать доступ
settings-apps-back = Назад к настройкам
settings-apps-reviewed-title = Проверено вашим администратором

# Остатки 2FA
settings-2fa-qr-alt = QR-код TOTP

# Передача пароля: истечение обратного отсчёта (отображается в JS)
settings-handoff-expired-lead = Ваше окно восстановления истекло.
settings-handoff-expired-link = Начать заново

# Подстраница связанных провайдеров
settings-providers-heading = Связанные провайдеры
settings-providers-subtitle = Входите в аккаунт с помощью стороннего провайдера идентификации.
settings-providers-empty-heading = Ваш администратор не настроил внешних провайдеров.
settings-providers-empty-desc = Обратитесь к администратору, чтобы включить Google, GitHub или других провайдеров входа.
settings-providers-back = Назад к настройкам
settings-providers-status-connected = Подключено { $date }
settings-providers-status-connected-plain = Подключено
settings-providers-status-not-connected = Не подключено
settings-providers-link = Привязать
settings-providers-unlink = Отвязать
settings-providers-unlink-blocked = Это ваш единственный способ входа. Добавьте пароль или ключ доступа, прежде чем отвязать его.
settings-providers-confirm-unlink = Отвязать { $provider }? Вы больше не сможете входить с его помощью.

# Разбиение строк со встроенным кодом (пункт 8: 2+ элемента кода в строке)

# settings_profile.html - описание публичного профиля (code: /users/{id}, profile, extended_profile)
settings-profile-public-desc-part1 = Видно коллегам по организации на вашей
settings-profile-public-desc-part2 = странице и приложениям, которым вы предоставляете области доступа OAuth
settings-profile-public-desc-part3 = или
settings-profile-public-desc-part4 = . Оставьте любое поле пустым, чтобы скрыть его.

# settings_profile.html - подсказка по ссылкам (code: Label|https://url)
settings-profile-links-hint-part1 = По одной на строку, в формате
settings-profile-links-hint-part2 = .

# Всплывающие сообщения и тексты встроенных ошибок, заданные в обработчиках Rust.
flash-session-signed-out = Из сеанса выполнен выход.
flash-session-signout-failed = Не удалось выйти из этого сеанса.
flash-sessions-signed-out-others =
    { $count ->
        [one] Выполнен выход из { $count } другого сеанса.
        [few] Выполнен выход из { $count } других сеансов.
        [many] Выполнен выход из { $count } других сеансов.
       *[other] Выполнен выход из { $count } других сеансов.
    }
flash-sessions-signout-others-failed = Не удалось выйти из других сеансов.
flash-app-access-revoked = Доступ отозван.
flash-app-access-revoke-failed = Не удалось отозвать доступ для этого приложения.
flash-offline-passphrase-saved = Автономная парольная фраза сохранена. Зарегистрированные хосты подхватят её при следующей синхронизации.
flash-offline-passphrase-save-failed = Не удалось сохранить вашу автономную парольную фразу. Пожалуйста, попробуйте снова.
flash-offline-passphrase-too-short = Ваша автономная парольная фраза должна содержать не менее { $min_len } символов.
flash-offline-passphrase-removed = Автономная парольная фраза удалена. Хосты удалят её при следующей синхронизации.
flash-offline-passphrase-none = У вас не задана автономная парольная фраза.
flash-offline-passphrase-remove-failed = Не удалось удалить вашу автономную парольную фразу. Пожалуйста, попробуйте снова.
settings-profile-url-invalid = Веб-сайт и URL аватара должны быть действительными адресами http:// или https://.
settings-profile-link-url-invalid = Каждый URL ссылки должен быть действительным адресом http:// или https://.
settings-save-failed = Не удалось сохранить ваши изменения. Пожалуйста, попробуйте снова.
