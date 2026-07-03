# Баннер администратора (admin_shell.html)
admin-banner-label = АДМИН
admin-banner-body = Вы на привилегированной поверхности. Действия здесь записываются в журнал аудита.

# Заголовок боковой панели навигации администратора (admin_nav.html)
admin-nav-heading = Администрирование
admin-nav-subtitle = Инструменты оператора

# Заголовки разделов навигации администратора
admin-nav-section-system = Система
admin-nav-section-access = Доступ
admin-nav-section-linux = Linux

# Подписи пунктов навигации администратора
admin-nav-status = Статус
admin-nav-configuration = Конфигурация
admin-nav-audit = Аудит
admin-nav-webhooks = Веб-хуки
admin-nav-license = Лицензия
admin-nav-identities = Личности
admin-nav-sessions = Сеансы
admin-nav-clients = Клиенты OAuth2
admin-nav-dcr-tokens = Токены DCR
admin-nav-saml = SAML SSO
admin-nav-hosts = Хосты
admin-nav-accounts = Учётные записи

# Список личностей (identities_list.html)
admin-identities-page-title = Личности
admin-identities-subtitle = Личности под управлением Kratos и их состояние.
admin-identities-search-placeholder = Поиск по ID или почте
admin-identities-search-button = Найти
admin-identities-col-email = Эл. почта
admin-identities-col-state = Состояние
admin-identities-col-created = Создана
admin-identities-empty = Личности не найдены.
admin-identities-prev = К началу
admin-identities-next = Следующая страница

# Сведения о личности (identity_show.html)
admin-identity-status-active = активна
admin-identity-recovery-code-heading = Код восстановления (показан один раз)
admin-identity-recovery-link-heading = Ссылка для восстановления
admin-identity-recovery-note = Передайте это пользователю по доверенному каналу. Повторно это не будет показано.
admin-identity-section-actions = Действия
admin-identity-action-generate-recovery = Сгенерировать код восстановления
admin-identity-action-disable = Отключить
admin-identity-action-enable = Включить
admin-identity-action-delete = Удалить
admin-identity-section-traits = Атрибуты
admin-identity-section-addresses = Подтверждаемые адреса
admin-identity-addresses-empty = У этой личности нет подтверждаемых адресов.
admin-identity-status-verified = подтверждён
admin-identity-status-pending = ожидает
admin-identity-section-credentials = Учётные данные
admin-identity-credentials-empty = Учётные данные не настроены.
admin-identity-section-sessions = Недавние сеансы
admin-identity-sessions-empty = Истории сеансов нет.
admin-identity-action-revoke-session = Отозвать сеанс

# Выбор личности (identity_picker.html)
admin-identity-picker-page-title = Выбрать пользователя
admin-identity-picker-subtitle = Выберите личность, чтобы продолжить.
admin-identity-picker-invalid-return = Недопустимая цель возврата.
admin-identity-picker-search-placeholder = Поиск по ID или почте
admin-identity-picker-search-button = Найти
admin-identity-picker-col-email = Эл. почта
admin-identity-picker-col-state = Состояние
admin-identity-picker-col-created = Создана
admin-identity-picker-empty = Личности не найдены.
admin-identity-picker-action-select = Выбрать
admin-identity-picker-prev = К началу
admin-identity-picker-next = Следующая страница

# Список сеансов (sessions_list.html)
admin-sessions-page-title = Сеансы
admin-sessions-subtitle = Все сеансы, известные Kratos, по всем личностям.
admin-sessions-filter-active-only = Только активные сеансы
admin-sessions-col-identity = Личность
admin-sessions-col-authenticated = Аутентифицирован
admin-sessions-col-expires = Истекает
admin-sessions-col-device = Устройство
admin-sessions-empty = Нет сеансов для показа.
admin-sessions-action-revoke = Отозвать
admin-sessions-prev = К началу
admin-sessions-next = Следующая страница

# Универсальный диалог подтверждения (confirm.html)
admin-confirm-cancel = Отмена

# Страница запрета доступа (forbidden.html)
admin-forbidden-back = Назад к панели управления

# Страница ошибки администратора (error.html)
admin-error-back = Назад к статусу администратора

# Список клиентов (clients_list.html)
admin-clients-page-title = Клиенты OAuth2
admin-clients-subtitle = Доверяющие стороны, зарегистрированные в Hydra.
admin-clients-action-new = Новый клиент
admin-clients-search-placeholder = Поиск по имени или ID клиента
admin-clients-filter-all-types = Все типы
admin-clients-filter-all-verifications = Все статусы проверки
admin-clients-filter-verified = Проверенные
admin-clients-filter-unverified = Непроверенные
admin-clients-search-button = Найти
admin-clients-col-name = Имя
admin-clients-col-type = Тип
admin-clients-col-grants = Разрешения
admin-clients-col-created = Создан
admin-clients-badge-unverified-title = Не проверен администратором
admin-clients-badge-self-registered = Саморегистрация
admin-clients-badge-self-registered-title = Зарегистрирован через /oauth2/register (RFC 7591)
admin-clients-empty = Нет зарегистрированных клиентов.
admin-clients-prev = К началу
admin-clients-next = Следующая страница

# Общие значки клиентов (clients_list.html, client_show.html)
admin-client-badge-verified = Проверен
admin-client-badge-unverified = Не проверен
admin-client-badge-unverified-title = Администратор не проверил этого клиента. Экран согласия предупреждает конечных пользователей.

# Заголовки страницы формы клиента (client_form.html)
admin-client-form-title-new = Новый клиент
admin-client-form-title-edit = Изменить клиента
admin-client-form-heading-new = Новый клиент OAuth2
admin-client-form-heading-edit = Изменить клиента
admin-client-form-preset-note = Для этого типа значения по умолчанию заполнены заранее.
admin-client-form-preset-change = Изменить тип

# Общие поля формы клиента (client_form.html, форма редактирования client_show.html)
admin-client-field-name = Имя клиента
admin-client-field-grant-types = Типы предоставления
admin-client-grant-auth-code-hint = (вход по инициативе пользователя)
admin-client-grant-refresh-hint = (долгоживущие сеансы)
admin-client-grant-client-creds-hint = (между сервисами)
admin-client-field-response-types = Типы ответа
admin-client-field-scope = Область доступа
admin-client-field-scope-hint = Области доступа OAuth2, разделённые пробелами.
admin-client-field-redirect-uris = URI перенаправления
admin-client-field-redirect-uris-hint = По одному на строку (или через запятую).
admin-client-field-post-logout-uris = URI перенаправления после выхода
admin-client-section-logout-fanout = Рассылка выхода OIDC
admin-client-section-logout-fanout-desc = Когда пользователь завершает сеанс через Forseti, Hydra уведомляет клиентов по этим URI, чтобы каждое приложение очистило свой локальный сеанс. Оставьте пустым, чтобы исключить этого клиента из рассылки.
admin-client-field-backchannel-uri = URI выхода по обратному каналу
admin-client-field-backchannel-uri-hint = Hydra отправляет сюда POST с подписанным токеном выхода (сервер-серверу). Обычно имеет смысл только для веб-приложений с серверным рендерингом и BFF.
admin-client-field-backchannel-sid-prefix = Требовать
admin-client-field-backchannel-sid-suffix = утверждение в токене выхода по обратному каналу
admin-client-field-backchannel-sid-short = утверждение
admin-client-field-frontchannel-uri = URI выхода по прямому каналу
admin-client-field-frontchannel-uri-hint = Hydra загружает этот URL во фрейм при выходе, чтобы каждое приложение очистило свои cookie сеанса в браузере.
admin-client-field-frontchannel-sid-prefix = Требовать
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = параметры запроса при выходе по прямому каналу
admin-client-field-frontchannel-sid-short = параметры запроса
admin-client-field-token-auth = Метод аутентификации на конечной точке токена
admin-client-token-auth-post-hint = (секрет в теле POST)
admin-client-token-auth-basic-hint = (секрет в заголовке Authorization)
admin-client-token-auth-none-hint = (публичный клиент, PKCE)
admin-client-token-auth-none-short = нет (публичный + PKCE)
admin-client-field-audience = Список разрешённых аудиторий
admin-client-field-audience-hint-short = По одному на строку. Hydra требует, чтобы значения аудитории были заранее зарегистрированы здесь.
admin-client-field-require-pkce = Требовать PKCE (информационно)
admin-client-field-skip-consent = Доверенный клиент (пропускать экран согласия)
admin-client-field-webhook-url = URL веб-хука удаления аккаунта
admin-client-action-cancel = Отмена

# Страница просмотра клиента (client_show.html)
admin-client-action-revoke-verification = Отозвать проверку
admin-client-action-mark-verified = Отметить как проверенного
admin-client-action-rotate-secret = Сменить секрет
admin-client-action-delete = Удалить
admin-client-credentials-heading = Учётные данные: показаны один раз
admin-client-credentials-note = Скопируйте их сейчас. Повторно они не будут показаны; перезагрузите страницу, чтобы скрыть. ID клиента и конечные точки выше не являются секретными и остаются видимыми.
admin-client-credentials-secret-label = Секрет клиента
admin-client-credentials-rat-label = Токен доступа для регистрации
admin-client-credentials-rat-note = Согласно RFC 7592: позволяет клиенту управлять собственной регистрацией (чтение/обновление/удаление) через API динамической регистрации клиентов Hydra. Его нельзя выпустить повторно, поэтому при сомнениях сохраните его.
admin-client-undoc-scopes-heading = Недокументированные области доступа
admin-client-section-connection = Сведения о подключении
admin-client-connection-intro = Вставьте это в конфигурацию клиента OIDC/OAuth на стороне приложения.
admin-client-conn-client-id = ID клиента
admin-client-conn-issuer = Издатель
admin-client-conn-discovery-url = URL обнаружения
admin-client-conn-auth-endpoint = Конечная точка авторизации
admin-client-conn-token-endpoint = Конечная точка токена
admin-client-conn-userinfo-endpoint = Конечная точка userinfo
admin-client-conn-jwks-uri = URI JWKS
admin-client-conn-end-session-endpoint = Конечная точка завершения сеанса
admin-client-section-config = Конфигурация
admin-client-config-sid-required = (требуется sid)
admin-client-config-iss-sid-required = (требуются iss+sid)
admin-client-not-configured = не настроено
admin-client-audience-none = нет
admin-client-config-token-auth = Аутентификация на конечной точке токена
admin-client-config-require-pkce = Требовать PKCE
admin-client-bool-yes = да
admin-client-bool-no = нет
admin-client-config-trusted = Доверенный (пропуск согласия)
admin-client-config-created = Создан
admin-client-config-provenance-audience = Аудитория
admin-client-config-provenance-audience-note = (заявлено вызывающей стороной DCR)
admin-client-config-provenance-url = Используется на
admin-client-config-provenance-url-note = (впервые замечено при согласии)
admin-client-config-webhook = Веб-хук удаления аккаунта
admin-client-section-edit = Редактирование
admin-client-action-save = Сохранить изменения
admin-client-action-back = Назад к списку

# Выбор типа клиента (client_type_picker.html)
admin-client-type-page-title = Новый клиент
admin-client-type-heading = Новый клиент OAuth2
admin-client-type-subtitle = Выберите тип приложения. Следующая страница — та же форма с уже заполненными правильными значениями по умолчанию, поэтому вы не сможете случайно получить нерабочую комбинацию.
admin-client-type-popular-heading = Популярные приложения
admin-client-type-action-cancel = Отмена

# Список токенов DCR (dcr_tokens_list.html)
admin-dcr-page-title = Начальные токены доступа DCR
admin-dcr-action-issue = Выпустить токен
admin-dcr-token-revealed-heading = Начальный токен доступа (показан один раз)
admin-dcr-col-status = Статус
admin-dcr-col-note = Заметка
admin-dcr-col-created-by = Кем создан
admin-dcr-col-created = Создан
admin-dcr-col-expires = Истекает
admin-dcr-col-uses-left = Осталось использований
admin-dcr-status-active = Активен
admin-dcr-status-revoked = Отозван
admin-dcr-status-expired = Истёк
admin-dcr-status-exhausted = Исчерпан
admin-dcr-empty-prefix = Токены не выпущены.
admin-dcr-empty-link = Выпустите токен
admin-dcr-empty-suffix = чтобы включить саморегистрацию.
admin-dcr-action-revoke = Отозвать

# Новый токен DCR (dcr_token_new.html)
admin-dcr-new-page-title = Выпустить токен DCR
admin-dcr-new-heading = Выпустить начальный токен доступа DCR
admin-dcr-new-field-note = Заметка
admin-dcr-new-field-note-placeholder = Для чего этот токен? (например, «Claude Desktop для formshive»)
admin-dcr-new-field-note-hint = Необязательно, только для ваших записей. Автор клиента этого никогда не видит.
admin-dcr-new-field-ttl = TTL (часы)
admin-dcr-new-field-ttl-hint = Оставьте пустым для бессрочного действия.
admin-dcr-new-field-max-uses = Максимум использований
admin-dcr-new-action-cancel = Отмена

# Страница статуса (status.html)
admin-status-page-title = Статус
admin-status-heading = Состояние системы
admin-status-subtitle = Актуальное состояние компонентов IdP, очереди курьера и версий сборки.
admin-status-issuer-label = Издатель
admin-status-issuer-config-link = Показать конфигурацию →
admin-status-warning-db-label = База данных
admin-status-warning-db-body = sqlite + развёртывание, похожее на продакшн. Конфигурации с несколькими экземплярами повредят базу данных. Для высокой доступности перейдите на Postgres.
admin-status-warning-webhook-label = Рассылка веб-хуков
admin-status-dead-webhook-count =
    { $count ->
        [one] { $count } недоставленная строка веб-хука удаления аккаунта
        [few] { $count } недоставленные строки веб-хука удаления аккаунта
        [many] { $count } недоставленных строк веб-хука удаления аккаунта
       *[other] { $count } недоставленных строк веб-хука удаления аккаунта
    }
admin-status-dead-webhook-middle = (получатели не уведомляются).
admin-status-dead-webhook-open = Открыть /admin/webhooks
admin-status-dead-webhook-action = чтобы поставить в очередь заново или отклонить.
admin-status-section-services = Сервисы
admin-status-col-service = Сервис
admin-status-col-state = Состояние
admin-status-col-detail = Подробности
admin-status-state-up = работает
admin-status-state-down = недоступен
admin-status-section-courier = Очередь курьера
admin-status-courier-pending = В ожидании (в очереди)
admin-status-courier-failed = С ошибкой (заброшено)
admin-status-courier-last-webhook = Последний веб-хук аудита
admin-status-courier-never = никогда
admin-status-section-audit = Аудит
admin-status-audit-write-failures = Ошибки записи аудита (с момента запуска)
admin-status-audit-write-failures-note-prefix = Строки можно восстановить из структурированных
admin-status-audit-write-failures-note-suffix = строк stderr, выводимых Forseti в момент сбоя.
admin-status-audit-webhook-rejected = Веб-хук аудита отклонён (с момента запуска)
admin-status-audit-webhook-rejected-note-prefix = Некорректные полезные нагрузки или неизвестные действия, вероятно, несоответствие хука/конфигурации Kratos. Проверьте
admin-status-audit-webhook-rejected-note-suffix = предупреждающие журналы.
admin-status-audit-freshness = Аномалии актуальности веб-хука аудита (с момента запуска)
admin-status-audit-freshness-note = Полезные нагрузки помечены как устаревшие или с будущей датой, обычно из-за медленного потока или расхождения часов. Строки всё равно записываются и помечаются.
admin-status-section-license = Лицензия
admin-status-license-oss-prefix = Развёртывание уровня OSS.
admin-status-license-oss-link = Активируйте лицензию
admin-status-license-oss-suffix = чтобы открыть премиум-возможности.
admin-status-section-build = Версии сборки
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = База данных

# Страница конфигурации (configuration.html)
admin-config-page-title = Конфигурация
admin-config-subtitle = Как настроен этот провайдер идентификации: конечные точки и возможности OIDC, ключи подписи и схемы личностей Kratos.
admin-config-discovery-warning-label = Обнаружение OIDC
admin-config-discovery-warning-body = Не удалось получить документ обнаружения Hydra. Конечные точки и возможности скрыты, пока он снова не станет доступен.
admin-config-section-oidc = Конечные точки OIDC
admin-config-field-issuer = Издатель
admin-config-field-discovery-url = URL обнаружения
admin-config-field-authorization = Авторизация
admin-config-field-token = Токен
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = Завершение сеанса
admin-config-field-registration = Регистрация (DCR)
admin-config-field-revocation = Отзыв
admin-config-section-capabilities = Возможности
admin-config-cap-scopes = Области доступа
admin-config-cap-grant-types = Типы предоставления
admin-config-cap-response-types = Типы ответа
admin-config-cap-token-auth-methods = Методы аутентификации на конечной точке токена
admin-config-cap-pkce-methods = Методы PKCE
admin-config-cap-id-token-signing-algs = Алгоритмы подписи ID-токена
admin-config-cap-subject-types = Типы субъекта
admin-config-cap-backchannel-logout = Выход по обратному каналу
admin-config-cap-frontchannel-logout = Выход по прямому каналу
admin-config-cap-yes = Да
admin-config-cap-no = Нет
admin-config-section-signing-keys = Ключи подписи (JWKS)
admin-config-signing-keys-unavailable = Недоступно: не удалось получить открытые ключи Hydra.
admin-config-signing-keys-empty = Hydra не объявила ключей подписи.
admin-config-col-key-id = ID ключа
admin-config-col-alg = Алгоритм
admin-config-col-type = Тип
admin-config-col-use = Назначение
admin-config-section-schemas = Схемы личностей Kratos
admin-config-schemas-unavailable = Недоступно: не удалось получить схемы личностей из Kratos.
admin-config-schemas-empty = Схемы личностей не зарегистрированы.

# Список аудита (audit.html)
admin-audit-page-title = Аудит
admin-audit-subtitle = Журнал событий только для добавления. Записывает действия администратора на стороне Forseti, предоставления OAuth, изменения сеансов и завершения потоков Kratos, доставленные через веб-хук. Срок хранения настраивается оператором (`[audit].audit_retention_days`); очистка — это подкоманда CLI, а не автоматический процесс.
admin-audit-filter-email = Почта содержит
admin-audit-filter-action = Префикс действия
admin-audit-filter-severity = Важность
admin-audit-filter-since = С момента
admin-audit-severity-any = Любая
admin-audit-severity-info = Инфо
admin-audit-severity-warning = Предупреждение
admin-audit-severity-error = Ошибка
admin-audit-severity-critical = Критическая
admin-audit-filter-button = Фильтровать
admin-audit-col-target = Цель
admin-audit-col-severity = Важность
admin-audit-col-when = Когда
admin-audit-col-actor = Инициатор
admin-audit-col-action = Действие
admin-audit-col-actions = Действия
admin-audit-empty = Ни одно событие не соответствует текущим фильтрам.
admin-audit-badge-critical = критическая
admin-audit-badge-error = ошибка
admin-audit-badge-warning = предупреждение
admin-audit-action-view = Просмотр
admin-audit-prev = ‹ Назад
admin-audit-next = Далее ›

# Сведения об аудите (audit_show.html)
admin-audit-back = ← Назад к аудиту
admin-audit-show-section-event = Событие
admin-audit-show-outcome = Результат
admin-audit-show-success = успех
admin-audit-show-failure = сбой
admin-audit-show-section-actor = Инициатор
admin-audit-show-field-kind = Вид
admin-audit-show-field-email = Эл. почта
admin-audit-show-none = нет
admin-audit-show-field-identity-id = ID личности
admin-audit-show-section-target = Цель
admin-audit-show-field-label = Метка
admin-audit-show-deleted = (удалено)
admin-audit-show-field-target-id = ID цели
admin-audit-show-section-metadata = Метаданные
admin-audit-show-section-request-context = Контекст запроса
admin-audit-show-field-ip-hash = Хеш IP
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = ID запроса
admin-audit-show-field-org-id = ID организации

# Список веб-хуков (webhooks.html)
admin-webhooks-page-title = Веб-хуки
admin-webhooks-heading = Недоставленные веб-хуки
admin-webhooks-subtitle = Уведомления об удалении аккаунта, исчерпавшие повторные попытки (12 попыток или 72 часа, что наступит раньше). Нажмите на строку, чтобы увидеть полную полезную нагрузку и последнюю ошибку, или поставьте в очередь заново из сводки, если уверены, что получатель снова работает.
admin-webhooks-empty = Недоставленных строк нет. Всё проходит.
admin-webhooks-col-client = Клиент
admin-webhooks-col-event = Событие
admin-webhooks-col-attempts = Попытки
admin-webhooks-col-age = Возраст
admin-webhooks-col-actions = Действия
admin-webhooks-deleted = (удалено)
admin-webhooks-action-view = Просмотр
admin-webhooks-action-requeue = В очередь заново

# Сведения о веб-хуке (webhook_show.html)
admin-webhook-back = ← Назад к веб-хукам
admin-webhook-heading = Недоставленный веб-хук
admin-webhook-action-requeue = В очередь заново
admin-webhook-action-discard = Отклонить
admin-webhook-section-delivery = Доставка
admin-webhook-field-client = Клиент
admin-webhook-deleted = (удалено)
admin-webhook-field-state = Состояние
admin-webhook-field-url = URL
admin-webhook-field-attempts = Попытки
admin-webhook-field-created = Создан
admin-webhook-field-next-attempt = Следующая попытка
admin-webhook-section-last-error = Последняя ошибка
admin-webhook-section-payload = Подписанная полезная нагрузка

# Список учётных записей POSIX (posix_list.html)
admin-posix-page-title = Учётные записи POSIX
admin-posix-subtitle = Личности Kratos, материализованные в учётные записи Linux (uid/gid + ключи SSH) для NSS-резолвера.
admin-posix-seats-label = Занято мест:
admin-posix-license-note = Коммерческая лицензия аутентификации Linux повышает лимит.
admin-posix-action-provision = Подготовить учётную запись
admin-posix-col-username = Имя пользователя
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = Статус
admin-posix-col-created = Создана
admin-posix-empty-prefix = Нет включённых учётных записей POSIX.
admin-posix-empty-link = Подготовьте одну
admin-posix-empty-suffix = из личности Kratos.
admin-posix-status-enabled = включена
admin-posix-status-disabled = отключена
admin-posix-action-manage = Управлять

# Сведения об учётной записи POSIX (posix_account.html)
admin-posix-action-disable = Отключить
admin-posix-action-enable = Включить
admin-posix-action-delete = Удалить
admin-posix-ssh-keys-heading = Ключи SSH
admin-posix-ssh-empty = Пока нет ключей SSH.
admin-posix-ssh-key-added-prefix = добавлен
admin-posix-ssh-action-remove = Удалить
admin-posix-ssh-field-public-key = Открытый ключ
admin-posix-ssh-field-comment = Комментарий (необязательно)
admin-posix-ssh-action-add = Добавить ключ
admin-posix-teams-heading = Команды
admin-posix-hosts-heading = Доступные хосты
admin-posix-back = ← Все учётные записи POSIX

# Новая учётная запись POSIX (posix_new.html)
admin-posix-new-page-title = Подготовить учётную запись POSIX
admin-posix-new-heading = Подготовить учётную запись POSIX
admin-posix-new-choose-identity = Выберите личность для подготовки.
admin-posix-new-action-select-user = Выбрать пользователя
admin-posix-new-or-enter-directly = Или введите напрямую
admin-posix-new-placeholder-id = UUID или почта
admin-posix-new-action-continue = Продолжить
admin-posix-new-provision-intro = Материализуйте личность Kratos в учётную запись Linux. uid/gid выделяется автоматически, и создаётся основная группа.
admin-posix-new-selected-prefix = Выбрано:
admin-posix-new-action-change = Изменить
admin-posix-new-field-username = Имя пользователя
admin-posix-new-username-hint = Предложено на основе почты; при желании измените. 1–32 символа, строчные, начиная с буквы или подчёркивания. Это становится именем входа POSIX.
admin-posix-new-field-shell = Командная оболочка входа
admin-posix-new-action-cancel = Отмена

# Список хостов (hosts_list.html)
admin-hosts-page-title = Хосты
admin-hosts-subtitle = Машины Linux, подключённые к POSIX/NSS-резолверу Forseti. Каждый хост аутентифицируется одноразовым секретом, который вы получаете при подключении.
admin-hosts-action-enroll = Подключить хост
admin-hosts-credential-heading = Учётные данные хоста (показаны один раз)
admin-hosts-credential-note-prefix = Формат:
admin-hosts-credential-note-suffix = . Настройте агент хоста с этими учётными данными сейчас. Мы не храним исходный секрет, только его SHA-256.
admin-hosts-col-hostname = Имя хоста
admin-hosts-col-teams = Команды
admin-hosts-col-force-mfa = Принудительный MFA
admin-hosts-col-enrolled = Подключён
admin-hosts-col-last-seen = Последняя активность
admin-hosts-empty-prefix = Нет подключённых хостов.
admin-hosts-empty-link = Подключите один
admin-hosts-empty-suffix = чтобы он мог разрешать учётные записи POSIX.
admin-hosts-status-mfa-pending = MFA (ожидает)
admin-hosts-mfa-pending-title = Записано, но пока не применяется; применение появится с интерактивным входом (PAM).
admin-hosts-action-edit = Изменить
admin-hosts-action-rotate = Сменить
admin-hosts-action-revoke = Отозвать

# Редактирование хоста (hosts_edit.html)
admin-hosts-edit-page-title = Изменить хост
admin-hosts-edit-intro = Обновите метку хоста, его флаг MFA и команды, к которым он привязан. Секрет здесь не показывается; смените его из списка хостов, если нужен новый.
admin-hosts-field-hostname = Имя хоста
admin-hosts-hostname-hint = Метка для ваших записей. Не обязательно совпадает с фактическим именем машины.
admin-hosts-field-org = Организация
admin-hosts-org-fixed-note = Организация хоста фиксируется при подключении и не может быть изменена здесь.
admin-hosts-field-allowed-teams = Разрешённые команды
admin-hosts-teams-empty = Пока нет команд. Этот хост разрешает любого участника организации. Привязка хоста к конкретным командам требует возможности «Организации».
admin-hosts-teams-hint = Ограничьте этот хост участниками выбранных команд. Не выбирайте ни одной, чтобы разрешить любого участника организации.
admin-hosts-field-force-mfa = Принудительный MFA на этом хосте
admin-hosts-force-mfa-hint = Записывается сейчас; применяется, когда появится интерактивный вход (PAM).
admin-hosts-action-cancel = Отмена

# Новый хост (hosts_new.html)
admin-hosts-new-heading = Подключить хост Linux
admin-hosts-new-intro-prefix = Одноразовый секрет показывается один раз на следующей странице. Настройте агент хоста с показанными учётными данными
admin-hosts-new-intro-suffix = которые он отображает.
admin-hosts-org-belongs-hint = Хост принадлежит этой организации. Фиксируется после подключения.
admin-hosts-new-teams-empty = Пока нет команд. Этот хост будет разрешать любого участника организации. Привязка хоста к конкретным командам требует возможности «Организации».
admin-hosts-new-teams-scope-hint = Ограничьте этот хост участниками выбранных команд. Применяются только команды выбранной организации; не выбирайте ни одной, чтобы разрешить любого участника организации.

# Список SAML SSO (saml_list.html)
admin-saml-page-title = SAML SSO
admin-saml-subtitle = Корпоративные подключения SAML, по одному на организацию. Метаданные IdP и сертификаты хранятся в Jackson; Forseti хранит опорную строку и переключатель включения.
admin-saml-action-new = Новое подключение
admin-saml-grace-notice = Лицензия в льготном периоде. Подключения SAML доступны только для чтения, пока лицензия не будет продлена. Входы через SSO продолжают работать.
admin-saml-col-org = Организация
admin-saml-col-connection = Подключение
admin-saml-col-sso-url = URL SSO
admin-saml-col-enabled = Включено
admin-saml-empty-prefix = Пока нет подключений SAML.
admin-saml-empty-link = Создайте одно
admin-saml-empty-suffix = чтобы включить SSO для организации.
admin-saml-status-enabled = Включено
admin-saml-status-disabled = Отключено
admin-saml-action-disable = Отключить
admin-saml-action-enable = Включить
admin-saml-action-delete = Удалить
admin-saml-idp-values-heading = Значения для администратора IdP клиента
admin-saml-idp-values-intro = Передайте это тому, кто настраивает приложение SAML на стороне провайдера идентификации. Они одинаковы для каждого подключения.
admin-saml-idp-acs-url = URL ACS
admin-saml-idp-entity-id = ID сущности SP

# Пагинация аудита
admin-audit-range = Показано { $from }–{ $to } из { $total } строк.
admin-audit-page = Страница { $page }
admin-saml-entity-id-note-prefix = ID сущности следует настройке Jackson
admin-saml-entity-id-note-suffix = ; измените его там, если переопределяете значение по умолчанию.

# Новое подключение SAML SSO (saml_new.html)
admin-saml-new-page-title = Новое подключение SAML
admin-saml-new-intro = Подключите организацию к её провайдеру идентификации. Вставьте XML метаданных IdP или укажите URL метаданных, который Jackson получит сам: ровно одно из двух.
admin-saml-new-field-org = Организация
admin-saml-new-org-hint = Одно подключение на организацию.
admin-saml-new-field-name = Имя подключения
admin-saml-new-name-hint = Только для ваших записей; участники этого никогда не видят.
admin-saml-new-field-metadata-url = URL метаданных
admin-saml-new-metadata-url-hint = Оставьте пустым при вставке необработанного XML ниже.
admin-saml-new-metadata-url-https-note = Jackson получает метаданные только по URL с HTTPS (или localhost). Для метаданных IdP по обычному HTTP вставьте XML ниже.
admin-saml-new-field-metadata-xml = XML метаданных
admin-saml-new-metadata-xml-hint = Оставьте пустым при использовании URL метаданных выше.
admin-saml-new-action-create = Создать подключение
admin-saml-new-action-cancel = Отмена

# Разбиение строк со встроенным кодом (пункт 8: 2+ элемента кода в строке)

# client_form.html - подсказка по типам ответа (code: code, token)
admin-client-field-response-types-hint-part1 = Через запятую, например
admin-client-field-response-types-hint-part2 = (код авторизации) или
admin-client-field-response-types-hint-part3 = (учётные данные клиента).

# client_form.html - подсказка по аудитории (code: audience=<value>)
admin-client-field-audience-hint-part1 = По одному на строку. Hydra требует, чтобы значения аудитории были заранее зарегистрированы здесь (RFC 8707 пока не поддерживается). Клиенты передают
admin-client-field-audience-hint-part2 = в запросе авторизации.

# client_form.html - подсказка по PKCE (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = Глобальное применение задаётся в
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). Этот флаг отражает намерение оператора.

# client_form.html + client_show.html - подсказка по веб-хуку (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = Когда пользователь сам удаляет аккаунт, Forseti отправляет сюда POST с токеном события безопасности RFC 8417 (RISC
admin-client-field-webhook-hint-part2 = ). Оставьте пустым, чтобы отказаться. Получатели проверяют JWS по JWKS Forseti на
admin-client-field-webhook-hint-part3 = .

# client_show.html - описание недокументированных областей доступа (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = Эти области доступа зарегистрированы для этого клиента, но не имеют записи под
admin-client-undoc-scopes-desc-part2 = в
admin-client-undoc-scopes-desc-part3 = . Экран согласия использует для них исходное имя области доступа.

# client_show.html - ошибка обнаружения (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = Не удалось получить конечную точку обнаружения Hydra, поэтому издатель и конечные точки скрыты, чтобы не показать неверное значение. Получите их сами с
admin-client-discovery-error-part2 = .

# client_show.html - вступление раздела редактирования (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = Обновите поля клиента ниже. Изменения отправляются через
admin-client-edit-intro-part2 = Hydra; несвязанные поля сохраняются.

# dcr_tokens_list.html - подзаголовок (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Bearer-токены, авторизующие
admin-dcr-subtitle-part2 = . Передайте один автору MCP-клиента, чтобы он мог зарегистрироваться сам без вашего ручного участия.

# dcr_tokens_list.html - описание показанного токена (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = Передайте это автору клиента. Он отправляет это как
admin-dcr-revealed-desc-part2 = при вызове
admin-dcr-revealed-desc-part3 = . Мы не храним исходное значение, только его SHA-256.

# dcr_token_new.html - подзаголовок (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = Токен показывается один раз на следующей странице. Передайте его автору клиента. Он отправляет его как
admin-dcr-new-subtitle-part2 = в одном вызове
admin-dcr-new-subtitle-part3 = .

# dcr_token_new.html - подсказка по максимуму использований (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = Оставьте пустым для неограниченного числа. Одноразовое (
admin-dcr-new-field-max-uses-hint-part2 = ) — самое безопасное значение по умолчанию.

# client_type_picker.html - описание популярных приложений (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = Заполнено заранее для известного приложения. URL используют заполнители
admin-client-type-popular-desc-part2 = (а иногда
admin-client-type-popular-desc-part3 = ). Замените их значениями вашего приложения после перехода к форме.

# posix_account.html - абзац о ключах SSH (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = Добавленные здесь открытые ключи передаются в sshd устройства (
admin-posix-ssh-keys-desc-part2 = ), чтобы этот пользователь мог
admin-posix-ssh-keys-desc-part3 = входить со своим ключом, без отдельного файла
admin-posix-ssh-keys-desc-part4 = на каждом хосте. Требует хука sshd на хосте (настраивается автоматически сервисом Guix
admin-posix-ssh-keys-desc-part5 = ; ручная настройка sshd на других дистрибутивах). Не используется для входа через консоль / PAM.

# posix_new.html - подсказка по оболочке (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = Должна существовать на устройстве(ах), обслуживающем эту учётную запись;
admin-posix-new-shell-hint-part2 = — безопасное межплатформенное значение по умолчанию (в Guix нет
admin-posix-new-shell-hint-part3 = ). Домашний каталог образуется из домашнего префикса + имени пользователя.

# saml_list.html - блок «не настроено» (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = не настроен
admin-saml-not-configured-part2 = добавьте настройки моста Jackson в
admin-saml-not-configured-part3 = чтобы включить SAML SSO. См.
admin-saml-not-configured-part4 = .

# Всплывающие сообщения администратора (показываются как баннер после перенаправления)
flash-identity-disabled = Личность отключена.
flash-identity-enabled = Личность включена.
flash-session-revoked = Сеанс отозван.
flash-client-create-failed = Не удалось создать клиента: { $error }
flash-client-account-deletion-url-rejected = URL удаления аккаунта отклонён: { $error }
flash-client-secret-stage-failed = Клиент создан, но не удалось подготовить секрет для одноразового показа. Смените секрет, чтобы получить новое значение.
