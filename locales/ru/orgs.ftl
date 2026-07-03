# Общие подписи полей на страницах организаций
orgs-field-name = Название
orgs-field-slug = Slug
orgs-field-email = Эл. почта
orgs-field-role = Роль

# Переключатель организаций (выпадающее меню в верхней навигации)
orgs-switcher-label = Сменить организацию
orgs-switcher-manage-link = Управление организациями

# Список организаций (list.html)
orgs-list-title = Организации
orgs-list-heading = Ваши организации
orgs-list-create-heading = Создать новую организацию
orgs-list-field-slug-optional = Slug (необязательно)
orgs-list-action-create = Создать
orgs-list-tier-gate-heading = Несколько организаций — возможность уровня { $tier }
orgs-list-license-missing = Ваша текущая лицензия не включает возможность «Организации».
orgs-list-unlicensed = Эта установка { $brand } работает без лицензии, поэтому дополнительные организации сверх стандартной заблокированы.
orgs-list-license-upgrade = Активируйте или обновите лицензию, чтобы создать больше.
orgs-list-link-get-license = Получить лицензию
orgs-list-link-activate-license = Активировать существующую лицензию

# Обзор организации - представление владельца (overview.html)
orgs-overview-subtitle-default = Это стандартная организация для этой установки { $brand }. Каждый, кто регистрируется, автоматически присоединяется к ней.
orgs-overview-subtitle = Управляйте настройками, брендингом и составом участников этой организации.
orgs-overview-identity-heading = Идентификация
orgs-overview-quicklinks-heading = Быстрые ссылки
orgs-link-branding = Брендинг
orgs-link-members = Участники
orgs-link-teams = Команды
orgs-sso-heading = Корпоративный SSO
orgs-sso-status-enabled = включён
orgs-sso-status-disabled = отключён
orgs-sso-operator-note = Подключения SSO управляются оператором.
orgs-danger-heading = Опасная зона
orgs-danger-delete-body = Полностью удалить эту организацию. Forseti откажет, если с ней ещё связаны какие-либо клиенты OAuth2.
orgs-danger-delete-action = Удалить организацию
orgs-confirm-delete-org = Удалить { $name }? Это действие нельзя отменить.

# Обзор организации - представление участника (overview_info.html)
orgs-info-subtitle-default = Это стандартная организация для этой установки { $brand }. Вы её участник.
orgs-info-subtitle = Вы участник этой организации.
orgs-info-org-heading = Организация
orgs-info-members-label = Участники
orgs-info-managed-by-heading = Кем управляется
orgs-info-managed-by-note = Обратитесь к владельцу, чтобы изменить название организации, брендинг или состав участников.

# Страница участников (members.html)
orgs-members-page-heading = Участники
orgs-members-subtitle = Владельцы могут повышать / понижать участников и удалять любого, кроме последнего владельца.
orgs-members-visibility-note-admins-only = Полный список участников виден только администраторам.
orgs-members-visibility-note-same-group = Вы видите участников, состоящих с вами в одной команде.
orgs-members-visibility-note-all = Все участники видимы.
orgs-members-invite-heading = Пригласить по электронной почте
orgs-members-role-member = Участник
orgs-members-role-owner = Владелец
orgs-members-action-invite = Отправить приглашение
orgs-members-visibility-heading = Видимость каталога
orgs-members-visibility-label = Кто может видеть список участников
orgs-members-visibility-opt-all = Все участники
orgs-members-visibility-opt-same-group = Только та же команда
orgs-members-visibility-opt-admins-only = Только администраторы
orgs-members-visibility-hint = Для варианта «Только та же команда» сначала должна существовать хотя бы одна команда.
orgs-members-col-joined = Присоединился
orgs-members-badge-you = вы
orgs-members-badge-hidden = Скрыт
orgs-members-action-show = Показать
orgs-members-action-hide = Скрыть
orgs-members-action-update = Обновить
orgs-members-action-remove = Удалить
orgs-confirm-remove-member = Удалить { $email }?
orgs-members-invites-heading = Ожидающие приглашения
orgs-members-invites-col-sent = Отправлено
orgs-members-invites-col-expires = Истекает

# Страница команд (teams.html)
orgs-teams-page-heading = Команды
orgs-teams-subtitle = Объединяйте участников в команды. Команды ограничивают доступ к хостам и определяют видимость каталога в пределах одной команды.
orgs-teams-create-heading = Создать команду
orgs-teams-action-create = Создать команду
orgs-teams-col-team = Команда
orgs-teams-col-members = Участники
orgs-teams-action-rename = Переименовать
orgs-teams-action-manage-members = Управление участниками
orgs-teams-action-delete = Удалить
orgs-confirm-delete-team = Удалить { $name }? Это удалит команду и её состав участников.
orgs-teams-selected-heading = Участники команды { $team }
orgs-teams-add-member-label = Добавить участника
orgs-teams-action-add = Добавить

# Страница брендинга (branding.html)
orgs-branding-page-heading = Брендинг
orgs-branding-subtitle-prefix = Переопределите стандартный бренд Forseti логотипом и адресом поддержки этой организации. Откатывается к
orgs-branding-subtitle-infix = в
orgs-branding-subtitle-suffix = если не задано.
orgs-branding-field-logo-url = URL логотипа
orgs-branding-field-support-email = Эл. почта поддержки
orgs-branding-theme-preset = Пресет темы
orgs-branding-primary = Основной цвет
orgs-branding-on-primary = Текст на основном цвете
orgs-branding-secondary = Акцентный цвет
orgs-branding-request-public = Включить публичную страницу входа (/o/ваш-slug)
orgs-branding-preview = Предпросмотр

# Публичная целевая страница (public_landing.html)
orgs-public-landing-note = Чтобы войти, откройте приложение, предоставленное вашей командой. Вход выполняется оттуда.
orgs-public-landing-register = Создать аккаунт
