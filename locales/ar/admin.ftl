# شريط الإدارة (admin_shell.html)
admin-banner-label = الإدارة
admin-banner-body = أنت على واجهة ذات صلاحيات. تُسجَّل الإجراءات هنا في سجل التدقيق.

# عنوان الشريط الجانبي لتنقّل الإدارة (admin_nav.html)
admin-nav-heading = الإدارة
admin-nav-subtitle = أدوات المشغّل

# عناوين أقسام تنقّل الإدارة
admin-nav-section-system = النظام
admin-nav-section-access = الوصول
admin-nav-section-linux = Linux

# تسميات عناصر تنقّل الإدارة
admin-nav-status = الحالة
admin-nav-configuration = الإعدادات
admin-nav-audit = التدقيق
admin-nav-webhooks = خطافات الويب
admin-nav-license = الترخيص
admin-nav-identities = الهويات
admin-nav-sessions = الجلسات
admin-nav-clients = عملاء OAuth2
admin-nav-dcr-tokens = رموز DCR
admin-nav-saml = الدخول الموحّد SAML
admin-nav-hosts = المضيفات
admin-nav-accounts = الحسابات

# قائمة الهويات (identities_list.html)
admin-identities-page-title = الهويات
admin-identities-subtitle = الهويات المُدارة عبر Kratos وحالتها.
admin-identities-search-placeholder = البحث بالمعرّف أو البريد الإلكتروني
admin-identities-search-button = بحث
admin-identities-col-email = البريد الإلكتروني
admin-identities-col-state = الحالة
admin-identities-col-created = تاريخ الإنشاء
admin-identities-empty = لم يُعثر على هويات.
admin-identities-prev = العودة إلى البداية
admin-identities-next = الصفحة التالية

# تفاصيل الهوية (identity_show.html)
admin-identity-status-active = نشطة
admin-identity-recovery-code-heading = رمز الاسترداد (يُعرَض مرة واحدة)
admin-identity-recovery-link-heading = رابط الاسترداد
admin-identity-recovery-note = شارك هذا مع المستخدم عبر قناة موثوقة. لن يُعرَض مرة أخرى.
admin-identity-section-actions = الإجراءات
admin-identity-action-generate-recovery = إنشاء رمز استرداد
admin-identity-action-disable = تعطيل
admin-identity-action-enable = تفعيل
admin-identity-action-delete = حذف
admin-identity-section-traits = السمات
admin-identity-section-addresses = العناوين القابلة للتحقق
admin-identity-addresses-empty = لا توجد عناوين قابلة للتحقق على هذه الهوية.
admin-identity-status-verified = مُتحقَّق منه
admin-identity-status-pending = قيد الانتظار
admin-identity-section-credentials = بيانات الاعتماد
admin-identity-credentials-empty = لا توجد بيانات اعتماد مُهيّأة.
admin-identity-section-sessions = الجلسات الأخيرة
admin-identity-sessions-empty = لا يوجد سجل جلسات.
admin-identity-action-revoke-session = إلغاء الجلسة

# مُنتقي الهوية (identity_picker.html)
admin-identity-picker-page-title = تحديد المستخدم
admin-identity-picker-subtitle = اختر هوية للمتابعة.
admin-identity-picker-invalid-return = هدف عودة غير صالح.
admin-identity-picker-search-placeholder = البحث بالمعرّف أو البريد الإلكتروني
admin-identity-picker-search-button = بحث
admin-identity-picker-col-email = البريد الإلكتروني
admin-identity-picker-col-state = الحالة
admin-identity-picker-col-created = تاريخ الإنشاء
admin-identity-picker-empty = لم يُعثر على هويات.
admin-identity-picker-action-select = تحديد
admin-identity-picker-prev = العودة إلى البداية
admin-identity-picker-next = الصفحة التالية

# قائمة الجلسات (sessions_list.html)
admin-sessions-page-title = الجلسات
admin-sessions-subtitle = كل جلسة معروفة لدى Kratos، عبر جميع الهويات.
admin-sessions-filter-active-only = الجلسات النشطة فقط
admin-sessions-col-identity = الهوية
admin-sessions-col-authenticated = المصادقة
admin-sessions-col-expires = تنتهي
admin-sessions-col-device = الجهاز
admin-sessions-empty = لا توجد جلسات لعرضها.
admin-sessions-action-revoke = إلغاء
admin-sessions-prev = العودة إلى البداية
admin-sessions-next = الصفحة التالية

# حوار التأكيد العام (confirm.html)
admin-confirm-cancel = إلغاء

# صفحة منع الوصول (forbidden.html)
admin-forbidden-back = العودة إلى لوحة التحكم

# صفحة خطأ الإدارة (error.html)
admin-error-back = العودة إلى حالة الإدارة

# قائمة العملاء (clients_list.html)
admin-clients-page-title = عملاء OAuth2
admin-clients-subtitle = الأطراف المعتمِدة المُسجَّلة في Hydra.
admin-clients-action-new = عميل جديد
admin-clients-search-placeholder = البحث باسم العميل أو المعرّف
admin-clients-filter-all-types = جميع الأنواع
admin-clients-filter-all-verifications = جميع حالات التوثيق
admin-clients-filter-verified = مُوثَّق
admin-clients-filter-unverified = غير مُوثَّق
admin-clients-search-button = بحث
admin-clients-col-name = الاسم
admin-clients-col-type = النوع
admin-clients-col-grants = المِنح
admin-clients-col-created = تاريخ الإنشاء
admin-clients-badge-unverified-title = لم يُدقَّق من قِبل مسؤول
admin-clients-badge-self-registered = مُسجَّل ذاتيًا
admin-clients-badge-self-registered-title = مُسجَّل عبر /oauth2/register (RFC 7591)
admin-clients-empty = لا توجد عملاء مُسجَّلون.
admin-clients-prev = العودة إلى البداية
admin-clients-next = الصفحة التالية

# شارات العميل المشتركة (clients_list.html, client_show.html)
admin-client-badge-verified = مُوثَّق
admin-client-badge-unverified = غير مُوثَّق
admin-client-badge-unverified-title = لم يُدقّق مسؤول هذا العميل. تُحذّر شاشة الموافقة المستخدمين النهائيين.

# عناوين صفحة نموذج العميل (client_form.html)
admin-client-form-title-new = عميل جديد
admin-client-form-title-edit = تعديل العميل
admin-client-form-heading-new = عميل OAuth2 جديد
admin-client-form-heading-edit = تعديل العميل
admin-client-form-preset-note = القيم الافتراضية مُعبّأة مسبقًا لهذا النوع.
admin-client-form-preset-change = تغيير النوع

# حقول النموذج المشتركة للعميل (client_form.html, client_show.html edit form)
admin-client-field-name = اسم العميل
admin-client-field-grant-types = أنواع المِنح
admin-client-grant-auth-code-hint = (تسجيل دخول يقوده المستخدم)
admin-client-grant-refresh-hint = (جلسات طويلة الأمد)
admin-client-grant-client-creds-hint = (من خدمة إلى خدمة)
admin-client-field-response-types = أنواع الاستجابة
admin-client-field-scope = النطاق
admin-client-field-scope-hint = نطاقات OAuth2 مفصولة بمسافات.
admin-client-field-redirect-uris = معرّفات إعادة التوجيه (URIs)
admin-client-field-redirect-uris-hint = واحد في كل سطر (أو مفصولة بفواصل).
admin-client-field-post-logout-uris = معرّفات إعادة التوجيه بعد تسجيل الخروج
admin-client-section-logout-fanout = توزيع تسجيل الخروج في OIDC
admin-client-section-logout-fanout-desc = عندما ينهي المستخدم جلسته عبر Forseti، يُخطر Hydra العملاء على هذه المعرّفات ليتمكّن كل تطبيق من مسح جلسته المحلية. اتركه فارغًا لاستثناء هذا العميل من التوزيع.
admin-client-field-backchannel-uri = معرّف تسجيل الخروج عبر القناة الخلفية
admin-client-field-backchannel-uri-hint = يرسل Hydra عبر POST رمز تسجيل خروج موقّعًا هنا (من خادم إلى خادم). عادةً ما يكون ذا معنى فقط لتطبيقات الويب المُقدَّمة من الخادم وواجهات BFF.
admin-client-field-backchannel-sid-prefix = يتطلب مطالبة
admin-client-field-backchannel-sid-suffix = في رمز تسجيل الخروج عبر القناة الخلفية
admin-client-field-backchannel-sid-short = مطالبة
admin-client-field-frontchannel-uri = معرّف تسجيل الخروج عبر القناة الأمامية
admin-client-field-frontchannel-uri-hint = يضع Hydra هذا الرابط في إطار iframe أثناء تسجيل الخروج ليتمكّن كل تطبيق من مسح ملفات تعريف الارتباط لجلسته في المتصفح.
admin-client-field-frontchannel-sid-prefix = يتطلب
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = معلَمات الاستعلام عند تسجيل الخروج عبر القناة الأمامية
admin-client-field-frontchannel-sid-short = معلَمات الاستعلام
admin-client-field-token-auth = طريقة مصادقة نقطة نهاية الرمز
admin-client-token-auth-post-hint = (السرّ في جسم POST)
admin-client-token-auth-basic-hint = (السرّ في ترويسة Authorization)
admin-client-token-auth-none-hint = (عميل عام، PKCE)
admin-client-token-auth-none-short = بلا (عام + PKCE)
admin-client-field-audience = قائمة السماح للجمهور
admin-client-field-audience-hint-short = واحد في كل سطر. يتطلب Hydra تسجيل قيم الجمهور مسبقًا هنا.
admin-client-field-require-pkce = يتطلب PKCE (للعلم)
admin-client-field-skip-consent = عميل موثوق (تخطّي شاشة الموافقة)
admin-client-field-webhook-url = رابط خطاف حذف الحساب
admin-client-action-cancel = إلغاء

# صفحة عرض العميل (client_show.html)
admin-client-action-revoke-verification = إلغاء التوثيق
admin-client-action-mark-verified = وضع علامة مُوثَّق
admin-client-action-rotate-secret = تدوير السرّ
admin-client-action-delete = حذف
admin-client-credentials-heading = بيانات الاعتماد: تُعرَض مرة واحدة
admin-client-credentials-note = انسخها الآن. لن تُعرَض مرة أخرى؛ أعد التحميل لإخفائها. معرّف العميل ونقاط النهاية أعلاه ليست سرية وتبقى مرئية.
admin-client-credentials-secret-label = سرّ العميل
admin-client-credentials-rat-label = رمز الوصول للتسجيل
admin-client-credentials-rat-note = وفقًا لـ RFC 7592: يتيح للعميل إدارة تسجيله الخاص (قراءة/تحديث/حذف) عبر واجهة تسجيل العملاء الديناميكية في Hydra. لا يمكن إعادة إصداره، لذا إن كنت في شك، فخزّنه.
admin-client-undoc-scopes-heading = نطاقات غير موثّقة
admin-client-section-connection = تفاصيل الاتصال
admin-client-connection-intro = الصق هذه في إعدادات عميل OIDC/OAuth على جانب التطبيق.
admin-client-conn-client-id = معرّف العميل
admin-client-conn-issuer = المُصدِر
admin-client-conn-discovery-url = رابط الاكتشاف
admin-client-conn-auth-endpoint = نقطة نهاية التفويض
admin-client-conn-token-endpoint = نقطة نهاية الرمز
admin-client-conn-userinfo-endpoint = نقطة نهاية معلومات المستخدم
admin-client-conn-jwks-uri = معرّف JWKS
admin-client-conn-end-session-endpoint = نقطة نهاية إنهاء الجلسة
admin-client-section-config = الإعدادات
admin-client-config-sid-required = (يتطلب sid)
admin-client-config-iss-sid-required = (يتطلب iss+sid)
admin-client-not-configured = غير مُهيّأ
admin-client-audience-none = بلا
admin-client-config-token-auth = مصادقة نقطة نهاية الرمز
admin-client-config-require-pkce = يتطلب PKCE
admin-client-bool-yes = نعم
admin-client-bool-no = لا
admin-client-config-trusted = موثوق (تخطّي الموافقة)
admin-client-config-created = تاريخ الإنشاء
admin-client-config-provenance-audience = الجمهور
admin-client-config-provenance-audience-note = (مُصرَّح به من مُستدعي DCR)
admin-client-config-provenance-url = مُستخدَم في
admin-client-config-provenance-url-note = (لوحظ أول مرة عند الموافقة)
admin-client-config-webhook = خطاف حذف الحساب
admin-client-section-edit = تعديل
admin-client-action-save = حفظ التغييرات
admin-client-action-back = العودة إلى القائمة

# مُنتقي نوع العميل (client_type_picker.html)
admin-client-type-page-title = عميل جديد
admin-client-type-heading = عميل OAuth2 جديد
admin-client-type-subtitle = اختر نوع التطبيق. الصفحة التالية هي النموذج نفسه، مع القيم الافتراضية الصحيحة مُعبّأة بالفعل، بحيث لا تقع بالخطأ على تركيبة معطّلة.
admin-client-type-popular-heading = التطبيقات الشائعة
admin-client-type-action-cancel = إلغاء

# قائمة رموز DCR (dcr_tokens_list.html)
admin-dcr-page-title = رموز الوصول الأولية لـ DCR
admin-dcr-action-issue = إصدار رمز
admin-dcr-token-revealed-heading = رمز الوصول الأولي (يُعرَض مرة واحدة)
admin-dcr-col-status = الحالة
admin-dcr-col-note = ملاحظة
admin-dcr-col-created-by = أنشأه
admin-dcr-col-created = تاريخ الإنشاء
admin-dcr-col-expires = تنتهي
admin-dcr-col-uses-left = الاستخدامات المتبقية
admin-dcr-status-active = نشط
admin-dcr-status-revoked = مُلغى
admin-dcr-status-expired = منتهي الصلاحية
admin-dcr-status-exhausted = مُستنفَد
admin-dcr-empty-prefix = لم تُصدَر أي رموز.
admin-dcr-empty-link = أصدر واحدًا
admin-dcr-empty-suffix = لتفعيل التسجيل الذاتي.
admin-dcr-action-revoke = إلغاء

# رمز DCR جديد (dcr_token_new.html)
admin-dcr-new-page-title = إصدار رمز DCR
admin-dcr-new-heading = إصدار رمز وصول أولي لـ DCR
admin-dcr-new-field-note = ملاحظة
admin-dcr-new-field-note-placeholder = ما الغرض من هذا الرمز؟ (مثل 'Claude Desktop لـ formshive')
admin-dcr-new-field-note-hint = اختياري، لسجلاتك فقط. لا يرى مؤلف العميل هذا أبدًا.
admin-dcr-new-field-ttl = مدة البقاء (بالساعات)
admin-dcr-new-field-ttl-hint = اتركه فارغًا لعدم انتهاء الصلاحية.
admin-dcr-new-field-max-uses = الحد الأقصى للاستخدامات
admin-dcr-new-action-cancel = إلغاء

# صفحة الحالة (status.html)
admin-status-page-title = الحالة
admin-status-heading = حالة النظام
admin-status-subtitle = الصحة الحيّة لمكوّنات مزوّد الهوية، وطابور البريد، وإصدارات البناء.
admin-status-issuer-label = المُصدِر
admin-status-issuer-config-link = عرض الإعدادات ←
admin-status-warning-db-label = قاعدة البيانات
admin-status-warning-db-body = sqlite مع نشر يبدو إنتاجيًا. ستُفسِد إعدادات تعدّد النسخ قاعدة البيانات. انتقل إلى Postgres لتوفّر عالٍ.
admin-status-warning-webhook-label = توزيع خطافات الويب
admin-status-dead-webhook-count =
    { $count ->
        [zero] لا صفوف خطافات ويب لحذف الحساب معلّقة
        [one] صف خطاف ويب واحد لحذف الحساب معلّق
        [two] صفّا خطاف ويب لحذف الحساب معلّقان
        [few] { $count } صفوف خطافات ويب لحذف الحساب معلّقة
        [many] { $count } صف خطاف ويب لحذف الحساب معلّق
       *[other] { $count } صف خطاف ويب لحذف الحساب معلّق
    }
admin-status-dead-webhook-middle = (لا يجري إخطار المستقبِلين).
admin-status-dead-webhook-open = افتح /admin/webhooks
admin-status-dead-webhook-action = لإعادة الإدراج في الطابور أو التجاهل.
admin-status-section-services = الخدمات
admin-status-col-service = الخدمة
admin-status-col-state = الحالة
admin-status-col-detail = التفاصيل
admin-status-state-up = يعمل
admin-status-state-down = متوقف
admin-status-section-courier = طابور البريد
admin-status-courier-pending = قيد الانتظار (في الطابور)
admin-status-courier-failed = فاشل (مهجور)
admin-status-courier-last-webhook = آخر خطاف ويب للتدقيق
admin-status-courier-never = أبدًا
admin-status-section-audit = التدقيق
admin-status-audit-write-failures = فشل كتابة التدقيق (منذ الإقلاع)
admin-status-audit-write-failures-note-prefix = يمكن استرداد الصفوف من أسطر
admin-status-audit-write-failures-note-suffix = المهيكلة على stderr التي يصدرها Forseti وقت الفشل.
admin-status-audit-webhook-rejected = خطاف ويب التدقيق مرفوض (منذ الإقلاع)
admin-status-audit-webhook-rejected-note-prefix = حمولات مشوّهة أو إجراءات غير معروفة، على الأرجح عدم تطابق في خطاف/إعدادات Kratos. تحقق من
admin-status-audit-webhook-rejected-note-suffix = سجلات التحذير.
admin-status-audit-freshness = شذوذات حداثة خطاف ويب التدقيق (منذ الإقلاع)
admin-status-audit-freshness-note = حمولات مختومة بأنها قديمة أو مؤرَّخة في المستقبل، عادةً بسبب تدفّق بطيء أو انحراف في الساعة. لا تزال الصفوف مُسجَّلة ومُعلَّمة.
admin-status-section-license = الترخيص
admin-status-license-oss-prefix = نشر من فئة المصدر المفتوح.
admin-status-license-oss-link = فعّل ترخيصًا
admin-status-license-oss-suffix = لفتح الميزات المميزة.
admin-status-section-build = إصدارات البناء
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = قاعدة البيانات

# صفحة الإعدادات (configuration.html)
admin-config-page-title = الإعدادات
admin-config-subtitle = كيفية تهيئة مزوّد الهوية هذا: نقاط نهاية وقدرات OIDC، ومفاتيح التوقيع، ومخططات هوية Kratos.
admin-config-discovery-warning-label = اكتشاف OIDC
admin-config-discovery-warning-body = تعذّر الوصول إلى مستند اكتشاف Hydra. تُخفى نقاط النهاية والقدرات حتى يصبح قابلًا للوصول مجددًا.
admin-config-section-oidc = نقاط نهاية OIDC
admin-config-field-issuer = المُصدِر
admin-config-field-discovery-url = رابط الاكتشاف
admin-config-field-authorization = التفويض
admin-config-field-token = الرمز
admin-config-field-userinfo = معلومات المستخدم
admin-config-field-jwks = JWKS
admin-config-field-end-session = إنهاء الجلسة
admin-config-field-registration = التسجيل (DCR)
admin-config-field-revocation = الإلغاء
admin-config-section-capabilities = القدرات
admin-config-cap-scopes = النطاقات
admin-config-cap-grant-types = أنواع المِنح
admin-config-cap-response-types = أنواع الاستجابة
admin-config-cap-token-auth-methods = طرق مصادقة نقطة نهاية الرمز
admin-config-cap-pkce-methods = طرق PKCE
admin-config-cap-id-token-signing-algs = خوارزميات توقيع رمز الهوية
admin-config-cap-subject-types = أنواع الموضوع
admin-config-cap-backchannel-logout = تسجيل الخروج عبر القناة الخلفية
admin-config-cap-frontchannel-logout = تسجيل الخروج عبر القناة الأمامية
admin-config-cap-yes = نعم
admin-config-cap-no = لا
admin-config-section-signing-keys = مفاتيح التوقيع (JWKS)
admin-config-signing-keys-unavailable = غير متاح: تعذّر جلب مفاتيح Hydra العامة.
admin-config-signing-keys-empty = لم يُعلن Hydra عن أي مفاتيح توقيع.
admin-config-col-key-id = معرّف المفتاح
admin-config-col-alg = الخوارزمية
admin-config-col-type = النوع
admin-config-col-use = الاستخدام
admin-config-section-schemas = مخططات هوية Kratos
admin-config-schemas-unavailable = غير متاح: تعذّر جلب مخططات الهوية من Kratos.
admin-config-schemas-empty = لا توجد مخططات هوية مُسجَّلة.

# قائمة التدقيق (audit.html)
admin-audit-page-title = التدقيق
admin-audit-subtitle = سجل أحداث للإلحاق فقط. يسجّل إجراءات الإدارة من جانب Forseti، ومِنح OAuth، وتغييرات الجلسات، واكتمال تدفّقات Kratos المُسلَّمة عبر خطاف الويب. الاحتفاظ مُهيّأ من قِبل المشغّل (`[audit].audit_retention_days`)؛ التقليم أمر فرعي في CLI، وليس تلقائيًا.
admin-audit-filter-email = البريد الإلكتروني يحتوي على
admin-audit-filter-action = بادئة الإجراء
admin-audit-filter-severity = الخطورة
admin-audit-filter-since = منذ
admin-audit-severity-any = أي
admin-audit-severity-info = معلومة
admin-audit-severity-warning = تحذير
admin-audit-severity-error = خطأ
admin-audit-severity-critical = حرج
admin-audit-filter-button = تصفية
admin-audit-col-target = الهدف
admin-audit-col-severity = الخطورة
admin-audit-col-when = متى
admin-audit-col-actor = الفاعل
admin-audit-col-action = الإجراء
admin-audit-col-actions = الإجراءات
admin-audit-empty = لا توجد أحداث تطابق عوامل التصفية الحالية.
admin-audit-badge-critical = حرج
admin-audit-badge-error = خطأ
admin-audit-badge-warning = تحذير
admin-audit-action-view = عرض
admin-audit-prev = ‹ السابق
admin-audit-next = التالي ›

# تفاصيل التدقيق (audit_show.html)
admin-audit-back = ← العودة إلى التدقيق
admin-audit-show-section-event = الحدث
admin-audit-show-outcome = النتيجة
admin-audit-show-success = نجاح
admin-audit-show-failure = فشل
admin-audit-show-section-actor = الفاعل
admin-audit-show-field-kind = النوع
admin-audit-show-field-email = البريد الإلكتروني
admin-audit-show-none = بلا
admin-audit-show-field-identity-id = معرّف الهوية
admin-audit-show-section-target = الهدف
admin-audit-show-field-label = التسمية
admin-audit-show-deleted = (محذوف)
admin-audit-show-field-target-id = معرّف الهدف
admin-audit-show-section-metadata = البيانات الوصفية
admin-audit-show-section-request-context = سياق الطلب
admin-audit-show-field-ip-hash = تجزئة عنوان IP
admin-audit-show-field-user-agent = وكيل المستخدم
admin-audit-show-field-request-id = معرّف الطلب
admin-audit-show-field-org-id = معرّف المؤسسة

# قائمة خطافات الويب (webhooks.html)
admin-webhooks-page-title = خطافات الويب
admin-webhooks-heading = خطافات الويب المعلّقة
admin-webhooks-subtitle = إشعارات حذف الحساب التي استنفدت المحاولات (12 محاولة أو 72 ساعة، أيهما أسبق). انقر على صف للاطلاع على الحمولة الكاملة وآخر خطأ، أو أعد إدراجه في الطابور من الملخّص إذا كنت تعلم أن المستقبِل عاد سليمًا.
admin-webhooks-empty = لا توجد صفوف معلّقة. كل شيء يصل بنجاح.
admin-webhooks-col-client = العميل
admin-webhooks-col-event = الحدث
admin-webhooks-col-attempts = المحاولات
admin-webhooks-col-age = العمر
admin-webhooks-col-actions = الإجراءات
admin-webhooks-deleted = (محذوف)
admin-webhooks-action-view = عرض
admin-webhooks-action-requeue = إعادة الإدراج في الطابور

# تفاصيل خطاف الويب (webhook_show.html)
admin-webhook-back = ← العودة إلى خطافات الويب
admin-webhook-heading = خطاف ويب معلّق
admin-webhook-action-requeue = إعادة الإدراج في الطابور
admin-webhook-action-discard = تجاهل
admin-webhook-section-delivery = التسليم
admin-webhook-field-client = العميل
admin-webhook-deleted = (محذوف)
admin-webhook-field-state = الحالة
admin-webhook-field-url = الرابط
admin-webhook-field-attempts = المحاولات
admin-webhook-field-created = تاريخ الإنشاء
admin-webhook-field-next-attempt = المحاولة التالية
admin-webhook-section-last-error = آخر خطأ
admin-webhook-section-payload = الحمولة الموقّعة

# قائمة حسابات POSIX (posix_list.html)
admin-posix-page-title = حسابات POSIX
admin-posix-subtitle = هويات Kratos مُجسَّدة إلى حسابات Linux (uid/gid + مفاتيح SSH) لمُحلِّل NSS.
admin-posix-seats-label = المقاعد المُستخدَمة:
admin-posix-license-note = يرفع ترخيص مصادقة Linux التجاري الحد الأقصى.
admin-posix-action-provision = تزويد حساب
admin-posix-col-username = اسم المستخدم
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = الحالة
admin-posix-col-created = تاريخ الإنشاء
admin-posix-empty-prefix = لا توجد حسابات POSIX مفعّلة.
admin-posix-empty-link = زوّد واحدًا
admin-posix-empty-suffix = من هوية Kratos.
admin-posix-status-enabled = مفعّل
admin-posix-status-disabled = معطّل
admin-posix-action-manage = إدارة

# تفاصيل حساب POSIX (posix_account.html)
admin-posix-action-disable = تعطيل
admin-posix-action-enable = تفعيل
admin-posix-action-delete = حذف
admin-posix-ssh-keys-heading = مفاتيح SSH
admin-posix-ssh-empty = لا توجد مفاتيح SSH بعد.
admin-posix-ssh-key-added-prefix = أُضيف
admin-posix-ssh-action-remove = إزالة
admin-posix-ssh-field-public-key = المفتاح العام
admin-posix-ssh-field-comment = تعليق (اختياري)
admin-posix-ssh-action-add = إضافة مفتاح
admin-posix-teams-heading = الفِرَق
admin-posix-hosts-heading = المضيفات القابلة للوصول
admin-posix-back = ← جميع حسابات POSIX

# حساب POSIX جديد (posix_new.html)
admin-posix-new-page-title = تزويد حساب POSIX
admin-posix-new-heading = تزويد حساب POSIX
admin-posix-new-choose-identity = اختر الهوية المراد تزويدها.
admin-posix-new-action-select-user = تحديد مستخدم
admin-posix-new-or-enter-directly = أو أدخل مباشرةً
admin-posix-new-placeholder-id = UUID أو بريد إلكتروني
admin-posix-new-action-continue = متابعة
admin-posix-new-provision-intro = جسّد هوية Kratos إلى حساب Linux. يُخصَّص uid/gid تلقائيًا ويُنشأ فريق أساسي.
admin-posix-new-selected-prefix = المُحدَّد:
admin-posix-new-action-change = تغيير
admin-posix-new-field-username = اسم المستخدم
admin-posix-new-username-hint = مُقترَح من البريد الإلكتروني؛ عدّله إن شئت. من 1 إلى 32 حرفًا، أحرف صغيرة، يبدأ بحرف أو شرطة سفلية. يصبح هذا اسم تسجيل الدخول في POSIX.
admin-posix-new-field-shell = صدفة تسجيل الدخول
admin-posix-new-action-cancel = إلغاء

# قائمة المضيفات (hosts_list.html)
admin-hosts-page-title = المضيفات
admin-hosts-subtitle = آلات Linux المُسجَّلة مقابل مُحلِّل POSIX/NSS في Forseti. يصادق كل مضيف بسرّ لمرة واحدة تكشفه عند التسجيل.
admin-hosts-action-enroll = تسجيل مضيف
admin-hosts-credential-heading = بيانات اعتماد المضيف (تُعرَض مرة واحدة)
admin-hosts-credential-note-prefix = الصيغة هي
admin-hosts-credential-note-suffix = . هيّئ وكيل المضيف بهذه البيانات الآن. لا نخزّن السرّ الخام، بل تجزئته SHA-256 فقط.
admin-hosts-col-hostname = اسم المضيف
admin-hosts-col-teams = الفِرَق
admin-hosts-col-force-mfa = فرض المصادقة الثنائية
admin-hosts-col-enrolled = تاريخ التسجيل
admin-hosts-col-last-seen = آخر ظهور
admin-hosts-empty-prefix = لا توجد مضيفات مُسجَّلة.
admin-hosts-empty-link = سجّل واحدًا
admin-hosts-empty-suffix = ليتمكّن من تحليل حسابات POSIX.
admin-hosts-status-mfa-pending = المصادقة الثنائية (قيد الانتظار)
admin-hosts-mfa-pending-title = مُسجَّل لكن غير مُنفَّذ بعد؛ يبدأ التنفيذ مع تسجيل الدخول التفاعلي (PAM).
admin-hosts-action-edit = تعديل
admin-hosts-action-rotate = تدوير
admin-hosts-action-revoke = إلغاء

# تعديل المضيف (hosts_edit.html)
admin-hosts-edit-page-title = تعديل المضيف
admin-hosts-edit-intro = حدّث تسمية المضيف وعلامة المصادقة الثنائية والفِرَق التي يقتصر عليها. لا يُعرَض السرّ هنا؛ دوّره من قائمة المضيفات إذا احتجت واحدًا جديدًا.
admin-hosts-field-hostname = اسم المضيف
admin-hosts-hostname-hint = تسمية لسجلاتك. لا يلزم أن تطابق اسم المضيف الفعلي للآلة.
admin-hosts-field-org = المؤسسة
admin-hosts-org-fixed-note = مؤسسة المضيف ثابتة عند التسجيل ولا يمكن تغييرها هنا.
admin-hosts-field-allowed-teams = الفِرَق المسموح بها
admin-hosts-teams-empty = لا توجد فِرَق بعد. يسمح هذا المضيف لأي عضو في المؤسسة. حصر مضيف بفِرَق محددة يتطلب ميزة المؤسسات.
admin-hosts-teams-hint = اقصر هذا المضيف على أعضاء الفِرَق المحددة. لا تحدد شيئًا للسماح لأي عضو في المؤسسة.
admin-hosts-field-force-mfa = فرض المصادقة الثنائية على هذا المضيف
admin-hosts-force-mfa-hint = مُسجَّل الآن؛ يُنفَّذ بمجرد إطلاق تسجيل الدخول التفاعلي (PAM).
admin-hosts-action-cancel = إلغاء

# مضيف جديد (hosts_new.html)
admin-hosts-new-heading = تسجيل مضيف Linux
admin-hosts-new-intro-prefix = يُكشَف سرّ لمرة واحدة في الصفحة التالية. هيّئ وكيل المضيف ببيانات الاعتماد
admin-hosts-new-intro-suffix = التي يعرضها.
admin-hosts-org-belongs-hint = ينتمي المضيف إلى هذه المؤسسة. ثابت بعد التسجيل.
admin-hosts-new-teams-empty = لا توجد فِرَق بعد. سيسمح هذا المضيف لأي عضو في المؤسسة. حصر مضيف بفِرَق محددة يتطلب ميزة المؤسسات.
admin-hosts-new-teams-scope-hint = اقصر هذا المضيف على أعضاء الفِرَق المحددة. تنطبق فقط الفِرَق في المؤسسة المختارة؛ لا تحدد شيئًا للسماح لأي عضو في المؤسسة.

# قائمة الدخول الموحّد SAML (saml_list.html)
admin-saml-page-title = الدخول الموحّد SAML
admin-saml-subtitle = اتصالات SAML للمؤسسات، واحد لكل مؤسسة. بيانات مزوّد الهوية والشهادات تعيش في Jackson؛ يحتفظ Forseti بصف الربط ومفتاح التفعيل.
admin-saml-action-new = اتصال جديد
admin-saml-grace-notice = الترخيص في فترة السماح. اتصالات SAML للقراءة فقط حتى يُجدَّد الترخيص. تستمر عمليات الدخول الموحّد في العمل.
admin-saml-col-org = المؤسسة
admin-saml-col-connection = الاتصال
admin-saml-col-sso-url = رابط الدخول الموحّد
admin-saml-col-enabled = مفعّل
admin-saml-empty-prefix = لا توجد اتصالات SAML بعد.
admin-saml-empty-link = أنشئ واحدًا
admin-saml-empty-suffix = لتفعيل الدخول الموحّد لمؤسسة.
admin-saml-status-enabled = مفعّل
admin-saml-status-disabled = معطّل
admin-saml-action-disable = تعطيل
admin-saml-action-enable = تفعيل
admin-saml-action-delete = حذف
admin-saml-idp-values-heading = القيم لمسؤول مزوّد الهوية لدى العميل
admin-saml-idp-values-intro = سلّم هذه لمن يهيّئ تطبيق SAML على جانب مزوّد الهوية. وهي نفسها لكل اتصال.
admin-saml-idp-acs-url = رابط ACS
admin-saml-idp-entity-id = معرّف كيان SP

# ترقيم صفحات التدقيق
admin-audit-range = عرض { $from }–{ $to } من { $total } صف.
admin-audit-page = الصفحة { $page }
admin-saml-entity-id-note-prefix = يتبع معرّف الكيان إعداد
admin-saml-entity-id-note-suffix = في Jackson؛ غيّره هناك إذا تجاوزت الافتراضي.

# اتصال SAML جديد (saml_new.html)
admin-saml-new-page-title = اتصال SAML جديد
admin-saml-new-intro = اربط مؤسسة بمزوّد هويتها. الصق بيانات مزوّد الهوية بصيغة XML، أو أعطِ رابط بيانات وصفية يجلبه Jackson بنفسه: واحد فقط من الاثنين.
admin-saml-new-field-org = المؤسسة
admin-saml-new-org-hint = اتصال واحد لكل مؤسسة.
admin-saml-new-field-name = اسم الاتصال
admin-saml-new-name-hint = لسجلاتك فقط؛ لا يراه الأعضاء أبدًا.
admin-saml-new-field-metadata-url = رابط البيانات الوصفية
admin-saml-new-metadata-url-hint = اتركه فارغًا عند لصق XML الخام أدناه.
admin-saml-new-metadata-url-https-note = يجلب Jackson فقط روابط البيانات الوصفية عبر HTTPS (أو localhost). لبيانات مزوّد الهوية عبر HTTP العادي، الصق XML أدناه بدلًا من ذلك.
admin-saml-new-field-metadata-xml = البيانات الوصفية XML
admin-saml-new-metadata-xml-hint = اتركه فارغًا عند استخدام رابط بيانات وصفية أعلاه.
admin-saml-new-action-create = إنشاء اتصال
admin-saml-new-action-cancel = إلغاء

# تقسيمات الشيفرة المضمّنة (البند 8: عنصرا شيفرة أو أكثر لكل سلسلة)

# client_form.html - تلميح أنواع الاستجابة (شيفرة: code, token)
admin-client-field-response-types-hint-part1 = مفصولة بفواصل، مثل
admin-client-field-response-types-hint-part2 = (رمز التفويض) أو
admin-client-field-response-types-hint-part3 = (بيانات اعتماد العميل).

# client_form.html - تلميح الجمهور (شيفرة: audience=<value>)
admin-client-field-audience-hint-part1 = واحد في كل سطر. يتطلب Hydra تسجيل قيم الجمهور مسبقًا هنا (فهو لا يدعم RFC 8707 بعد). يمرّر العملاء
admin-client-field-audience-hint-part2 = في طلب التفويض.

# client_form.html - تلميح PKCE (شيفرة: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = يعيش الفرض العام في
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ). هذه العلامة لنيّة المشغّل.

# client_form.html + client_show.html - تلميح خطاف الويب (شيفرة: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = عندما يحذف مستخدم نفسه، يرسل Forseti عبر POST رمز حدث أمني RFC 8417 (RISC
admin-client-field-webhook-hint-part2 = ) هنا. اتركه فارغًا للانسحاب. يتحقق المستقبِلون من JWS مقابل JWKS الخاص بـ Forseti على
admin-client-field-webhook-hint-part3 = .

# client_show.html - وصف النطاقات غير الموثّقة (شيفرة: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = هذه النطاقات مُسجَّلة على هذا العميل لكن لا يوجد لها مدخل تحت
admin-client-undoc-scopes-desc-part2 = في
admin-client-undoc-scopes-desc-part3 = . تعود شاشة الموافقة إلى اسم النطاق الخام لها.

# client_show.html - خطأ الاكتشاف (شيفرة: <hydra-public-url>/…)
admin-client-discovery-error-part1 = تعذّر الوصول إلى نقطة نهاية الاكتشاف في Hydra، لذا يُخفى المُصدِر ونقاط النهاية لتجنّب عرض قيمة خاطئة. اجلبها بنفسك من
admin-client-discovery-error-part2 = .

# client_show.html - مقدمة قسم التعديل (شيفرة: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = حدّث حقول العميل أدناه. تُدفَع التغييرات عبر واجهة
admin-client-edit-intro-part2 = في Hydra؛ تُحفظ الحقول غير ذات الصلة.

# dcr_tokens_list.html - العنوان الفرعي (شيفرة: POST /oauth2/register)
admin-dcr-subtitle-part1 = رموز حاملة تُصرّح بـ
admin-dcr-subtitle-part2 = . سلّم واحدًا لمؤلف عميل MCP ليتمكّن من التسجيل الذاتي دون أن تفعله أنت يدويًا.

# dcr_tokens_list.html - وصف الرمز المكشوف (شيفرة: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = شارك هذا مع مؤلف العميل. يرسله بصيغة
admin-dcr-revealed-desc-part2 = عند استدعاء
admin-dcr-revealed-desc-part3 = . لا نخزّن القيمة الخام، بل تجزئتها SHA-256 فقط.

# dcr_token_new.html - العنوان الفرعي (شيفرة: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = يُكشَف الرمز مرة واحدة في الصفحة التالية. سلّمه لمؤلف العميل. يرسله بصيغة
admin-dcr-new-subtitle-part2 = في استدعاء
admin-dcr-new-subtitle-part3 = واحد.

# dcr_token_new.html - تلميح الحد الأقصى للاستخدامات (شيفرة: 1)
admin-dcr-new-field-max-uses-hint-part1 = اتركه فارغًا لاستخدام غير محدود. الاستخدام لمرة واحدة (
admin-dcr-new-field-max-uses-hint-part2 = ) هو الافتراضي الأكثر أمانًا.

# client_type_picker.html - وصف التطبيقات الشائعة (شيفرة: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = مُعبّأ مسبقًا لتطبيق معروف. تستخدم الروابط عناصر نائبة
admin-client-type-popular-desc-part2 = (وأحيانًا
admin-client-type-popular-desc-part3 = ). استبدلها بقيم تطبيقك بعد الوصول إلى النموذج.

# posix_account.html - فقرة مفاتيح SSH (شيفرة: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = المفاتيح العامة المُضافة هنا تُقدَّم إلى sshd على الجهاز (
admin-posix-ssh-keys-desc-part2 = ) ليتمكّن هذا المستخدم من الاتصال عبر
admin-posix-ssh-keys-desc-part3 = بمفتاحه، دون الحاجة إلى ملف
admin-posix-ssh-keys-desc-part4 = لكل مضيف. يتطلب خطاف sshd للمضيف (يُعدّ تلقائيًا بواسطة خدمة
admin-posix-ssh-keys-desc-part5 = في Guix؛ إعداد sshd يدوي على التوزيعات الأخرى). لا يُستخدم لتسجيل الدخول عبر وحدة التحكم / PAM.

# posix_new.html - تلميح الصدفة (شيفرة: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = يجب أن توجد على الجهاز (الأجهزة) التي تخدم هذا الحساب؛
admin-posix-new-shell-hint-part2 = هو الافتراضي الآمن عبر التوزيعات (Guix لا يملك
admin-posix-new-shell-hint-part3 = ). يُشتقّ المجلد الرئيسي من بادئة المجلد الرئيسي + اسم المستخدم.

# saml_list.html - كتلة غير مُهيّأ (شيفرة: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = غير مُهيّأ
admin-saml-not-configured-part2 = أضف إعدادات جسر Jackson إلى
admin-saml-not-configured-part3 = لتفعيل الدخول الموحّد SAML. راجع
admin-saml-not-configured-part4 = .

# رسائل تنبيه الإدارة (تُعرَض كشريط بعد إعادة التوجيه)
flash-identity-disabled = تم تعطيل الهوية.
flash-identity-enabled = تم تفعيل الهوية.
flash-session-revoked = تم إلغاء الجلسة.
flash-client-create-failed = فشل إنشاء العميل: { $error }
flash-client-account-deletion-url-rejected = رُفض رابط حذف الحساب: { $error }
flash-client-secret-stage-failed = أُنشئ العميل، لكن تعذّر علينا تجهيز السرّ للعرض لمرة واحدة. دوّر السرّ لاسترداد قيمة جديدة.
