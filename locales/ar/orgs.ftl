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
orgs-sso-heading = الدخول الموحّد للمؤسسات
orgs-sso-status-enabled = مفعّل
orgs-sso-status-disabled = معطّل
orgs-sso-operator-note = اتصالات الدخول الموحّد مُدارة من قِبل المشغّل.
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
