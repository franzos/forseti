# تسميات الحقول المشتركة المستخدمة عبر صفحات المؤسسة
orgs-field-name = الاسم
orgs-field-slug = المُعرّف اللطيف
orgs-field-email = البريد الإلكتروني
orgs-field-role = الدور

# مُبدّل المؤسسة (قائمة التنقّل العلوية المنسدلة)
orgs-switcher-label = تبديل المؤسسة
orgs-switcher-manage-link = إدارة المؤسسات

# قائمة المؤسسات (list.html)
orgs-list-title = المؤسسات
orgs-list-heading = مؤسساتك
orgs-list-create-heading = إنشاء مؤسسة جديدة
orgs-list-field-slug-optional = المُعرّف اللطيف (اختياري)
orgs-list-action-create = إنشاء
orgs-list-field-access-mode = وضع الوصول
orgs-list-mode-internal-title = داخلي
orgs-list-mode-internal-body = بالدعوة فقط. ينضم الأعضاء عبر دعوة (ولاحقًا عبر نطاق شركة موثّق).
orgs-list-mode-external-title = خارجي
orgs-list-mode-external-body = تسجيل عام ذاتي الخدمة. دليل الأعضاء مقتصر على المسؤولين فقط.
orgs-list-tier-gate-heading = تعدّد المؤسسات ميزة من فئة { $tier }
orgs-list-license-missing = ترخيصك الحالي لا يتضمّن ميزة المؤسسات.
orgs-list-unlicensed = تثبيت { $brand } هذا يعمل بدون ترخيص، لذا تُقيَّد المؤسسات الإضافية بخلاف الافتراضية.
orgs-list-license-upgrade = فعّل أو رقِّ ترخيصًا لإنشاء المزيد.
orgs-list-link-get-license = احصل على ترخيص
orgs-list-link-activate-license = فعّل ترخيصًا موجودًا

# نظرة عامة على المؤسسة - عرض المالك (overview.html)
orgs-overview-subtitle-default = هذه هي المؤسسة الافتراضية لتثبيت { $brand } هذا. كل من يسجّل ينضم إليها تلقائيًا.
orgs-overview-subtitle = أدِر إعدادات هذه المؤسسة وهويتها البصرية وعضويتها.
orgs-overview-identity-heading = الهوية
orgs-overview-quicklinks-heading = روابط سريعة
orgs-link-branding = الهوية البصرية
orgs-link-members = الأعضاء
orgs-link-teams = الفِرَق
orgs-link-domains = النطاقات
orgs-sso-heading = الدخول الموحّد للمؤسسات
orgs-sso-status-enabled = مفعّل
orgs-sso-status-disabled = معطّل
orgs-sso-operator-note = اتصالات الدخول الموحّد مُدارة من قِبل المشغّل.
orgs-access-mode-heading = وضع الوصول
orgs-access-mode-label = الوضع
orgs-access-mode-internal = داخلي
orgs-access-mode-external = خارجي
orgs-access-mode-note-default = المؤسسة الافتراضية داخلية دائمًا.
orgs-access-mode-note-internal = ينضم الأعضاء عبر دعوة. التبديل إلى خارجي يفعّل التسجيل العام.
orgs-access-mode-note-external = التسجيل العام مفعّل. دليل الأعضاء مقتصر على المسؤولين فقط طالما الوضع خارجي.
orgs-access-mode-action-switch-external = التبديل إلى خارجي
orgs-access-mode-action-switch-internal = التبديل إلى داخلي
orgs-confirm-switch-external = التبديل إلى خارجي؟ هذا يفعّل صفحة التسجيل العام ويقصر دليل الأعضاء على المسؤولين فقط.
orgs-confirm-switch-internal = التبديل إلى داخلي؟ هذا يعطّل صفحة التسجيل العام. يحتفظ الأعضاء الحاليون بعضويتهم.
orgs-danger-heading = منطقة الخطر
orgs-danger-delete-body = حذف نهائي لهذه المؤسسة. يرفض Forseti ذلك إذا كانت أي عملاء OAuth2 لا يزالون مرتبطين.
orgs-danger-delete-action = حذف المؤسسة
orgs-confirm-delete-org = هل تريد حذف { $name }؟ لا يمكن التراجع عن هذا.

# نظرة عامة على المؤسسة - عرض غير المالك (overview_info.html)
orgs-info-subtitle-default = هذه هي المؤسسة الافتراضية لتثبيت { $brand } هذا. أنت عضو فيها.
orgs-info-subtitle = أنت عضو في هذه المؤسسة.
orgs-info-org-heading = المؤسسة
orgs-info-members-label = الأعضاء
orgs-info-managed-by-heading = مُدارة من قِبل
orgs-info-managed-by-note = تواصل مع مالك لإجراء تغييرات على اسم المؤسسة أو هويتها البصرية أو عضويتها.

# صفحة الأعضاء (members.html)
orgs-members-page-heading = الأعضاء
orgs-members-subtitle = يمكن للمالكين ترقية الأعضاء أو خفض رتبتهم وإزالة أي شخص باستثناء المالك الأخير.
orgs-members-visibility-note-admins-only = يمكن للمسؤولين فقط رؤية قائمة الأعضاء الكاملة.
orgs-members-visibility-note-same-group = ترى الأعضاء الذين يشاركونك فريقًا.
orgs-members-visibility-note-all = جميع الأعضاء مرئيون.
orgs-members-invite-heading = دعوة عبر البريد الإلكتروني
orgs-members-role-member = عضو
orgs-members-role-owner = مالك
orgs-members-action-invite = إرسال دعوة
orgs-members-visibility-heading = ظهور الدليل
orgs-members-visibility-label = من يمكنه رؤية قائمة الأعضاء
orgs-members-visibility-opt-all = جميع الأعضاء
orgs-members-visibility-opt-same-group = نفس الفريق فقط
orgs-members-visibility-opt-admins-only = المسؤولون فقط
orgs-members-visibility-hint = خيار نفس الفريق فقط يتطلب وجود فريق واحد على الأقل أولًا.
orgs-members-col-joined = تاريخ الانضمام
orgs-members-badge-you = أنت
orgs-members-badge-hidden = مخفي
orgs-members-action-show = إظهار
orgs-members-action-hide = إخفاء
orgs-members-action-update = تحديث
orgs-members-action-remove = إزالة
orgs-confirm-remove-member = هل تريد إزالة { $email }؟
orgs-members-invites-heading = الدعوات المعلّقة
orgs-members-invites-col-sent = أُرسلت
orgs-members-invites-col-expires = تنتهي

# صفحة الفِرَق (teams.html)
orgs-teams-page-heading = الفِرَق
orgs-teams-subtitle = جمّع الأعضاء في فِرَق. تحدّد الفِرَق نطاق الوصول إلى المضيفات وتتحكم في ظهور دليل نفس الفريق.
orgs-teams-create-heading = إنشاء فريق
orgs-teams-action-create = إنشاء فريق
orgs-teams-col-team = الفريق
orgs-teams-col-members = الأعضاء
orgs-teams-action-rename = إعادة تسمية
orgs-teams-action-manage-members = إدارة الأعضاء
orgs-teams-action-delete = حذف
orgs-confirm-delete-team = هل تريد حذف { $name }؟ هذا يزيل الفريق وعضوياته.
orgs-teams-selected-heading = أعضاء { $team }
orgs-teams-add-member-label = إضافة عضو
orgs-teams-action-add = إضافة

# صفحة النطاقات (domains.html)
orgs-domains-page-heading = النطاقات المسموح بها
orgs-domains-subtitle = المستخدمون الذين لديهم بريد إلكتروني موثّق على نطاق مُثبت يلتحقون بهذه المؤسسة تلقائيًا.
orgs-domains-add-heading = إضافة نطاق
orgs-domains-field-domain = النطاق
orgs-domains-field-method = طريقة التحقق
orgs-domains-method-http_file = ملف HTTP
orgs-domains-method-dns_txt = سجل DNS TXT
orgs-domains-method-email = البريد الإلكتروني
orgs-domains-action-add = إضافة النطاق
orgs-domains-col-domain = النطاق
orgs-domains-col-method = الطريقة
orgs-domains-col-status = الحالة
orgs-domains-status-verified = مُوثّق
orgs-domains-status-pending = قيد الانتظار
orgs-domains-instructions-http_file = ضع { $token } على https://{ $domain }/.well-known/forseti-domain-verify
orgs-domains-instructions-dns_txt = أنشئ سجل TXT عند _forseti-verify.{ $domain } بالقيمة: { $token }
orgs-domains-instructions-email = تم إرسال رمز إلى admin@{ $domain } و postmaster@{ $domain }. الصقه أدناه.
orgs-domains-action-verify = تحقق
orgs-domains-action-confirm = تأكيد الرمز
orgs-domains-field-token = رمز التأكيد
orgs-domains-action-remove = إزالة
orgs-confirm-remove-domain = إزالة { $domain }؟ سيتوقف الانضمام التلقائي لهذا النطاق فورًا.
orgs-domains-policy-heading = سياسة الانضمام
orgs-domains-policy-subtitle = اختر كيفية انضمام المستخدمين الذين لديهم بريد إلكتروني مُتحقق منه على نطاق مُثبت إلى هذه المؤسسة.
orgs-domains-policy-field = السياسة
orgs-domains-policy-invite-only = بالدعوة فقط
orgs-domains-policy-auto-join = يمكن لمستخدمي النطاقات المُتحقق منها الانضمام بأنفسهم
orgs-domains-policy-save = حفظ السياسة

# صفحة الهوية البصرية (branding.html)
orgs-branding-page-heading = الهوية البصرية
orgs-branding-subtitle-prefix = تجاوز الهوية البصرية الافتراضية لـ Forseti بشعار هذه المؤسسة وبريد الدعم الخاص بها. يعود إلى
orgs-branding-subtitle-infix = في
orgs-branding-subtitle-suffix = عند عدم التعيين.
orgs-branding-field-logo-url = رابط الشعار
orgs-branding-field-logo-file = صورة الشعار (PNG أو JPEG أو WebP؛ بحد أقصى 256 كيلوبايت)
orgs-branding-logo-remove = إزالة الشعار
orgs-branding-logo-save = رفع الشعار
orgs-branding-field-support-email = بريد الدعم
orgs-branding-theme-preset = إعداد مظهر مسبق
orgs-branding-primary = اللون الأساسي
orgs-branding-on-primary = النص على اللون الأساسي
orgs-branding-secondary = لون التمييز
orgs-branding-request-public = تفعيل صفحة تسجيل دخول عامة (/o/your-slug)
orgs-branding-preview = معاينة

# صفحة الهبوط العامة (public_landing.html)
orgs-public-landing-note = لتسجيل الدخول، افتح التطبيق الذي وفّره فريقك. يتم تسجيل الدخول من هناك.
orgs-public-landing-register = إنشاء حساب

# تأكيد الانضمام (join_confirm.html)
join-confirm-page-title = الانضمام إلى المؤسسة
join-confirm-heading = الانضمام إلى { $org }
join-confirm-body = أنت على وشك الانضمام إلى { $org }. هل تريد المتابعة؟
join-confirm-cta = انضمام
join-confirm-register-cta = سجّل للانضمام إلى { $org }
