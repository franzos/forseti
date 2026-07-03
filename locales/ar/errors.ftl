# صفحة الخطأ
error-reference-id = معرّف المرجع:
error-cta-back-to-sign-in = العودة إلى تسجيل الدخول

# تأكيد تسجيل الخروج من OAuth
logout-card-title = تسجيل الخروج من جميع التطبيقات؟
logout-card-subtitle = سيؤدي هذا إلى إنهاء جلستك مع { $brand } وإخطار كل تطبيق سجّلت الدخول إليه.
logout-body-text = سيُبلَّغ التطبيق الذي طلب منك تسجيل الخروج بأن الطلب قد اكتمل. قد تحتفظ بعض التطبيقات ببيانات محلية مخزّنة مؤقتًا لفترة قصيرة؛ تسجيل الخروج هنا ينهي الجلسة لدى { $brand }.
logout-action-sign-out = تسجيل الخروج
logout-action-cancel = إلغاء

# عناوين ونصوص حوارات الإدارة المستخدمة في render_admin_error عند مواضع الاستدعاء التي تملك لغة.
# مواضع الاستدعاء بلا لغة (الدوال المساعدة، حدود الأخطاء) تحتفظ بنصوصها الإنجليزية الحرفية.
dialog-identity-unavailable-title = الهوية غير متاحة
dialog-identity-unavailable-body = تعذّر علينا تحميل تلك الهوية. ربما تكون قد حُذفت.
dialog-recovery-code-failed-title = فشل رمز الاسترداد
dialog-recovery-code-failed-body = أنشأنا رمز الاسترداد لكن تعذّر علينا تجهيزه للعرض لمرة واحدة. أنشئ رمزًا جديدًا لإعادة المحاولة.
dialog-disable-failed-title = فشل التعطيل
dialog-enable-failed-title = فشل التفعيل
dialog-delete-failed-title = فشل الحذف
dialog-revoke-failed-title = فشل الإلغاء

# حدود الأخطاء (error_boundary.html)، العنوان/النص/الزر مضبوطة في معالجات Rust.
error-boundary-auth-unavailable-title = المصادقة غير متاحة
error-boundary-auth-unavailable-body = تعذّر علينا الوصول إلى خدمة المصادقة. يُرجى المحاولة مرة أخرى بعد لحظة.
error-boundary-cta-try-again = حاول مرة أخرى
error-boundary-cta-sign-in = تسجيل الدخول
error-boundary-cta-back-to-settings = العودة إلى الإعدادات
error-boundary-cta-back-to-dashboard = العودة إلى لوحة التحكم
error-boundary-cta-back-to-account = العودة إلى الحساب
error-boundary-signin-title = تسجيل الدخول غير متاح
error-boundary-signup-title = التسجيل غير متاح
error-boundary-recovery-title = الاسترداد غير متاح
error-boundary-verification-title = التحقق غير متاح
error-boundary-settings-title = الإعدادات غير متاحة
error-boundary-logout-title = تسجيل الخروج غير متاح
error-boundary-logout-body = تعذّر علينا إكمال تسجيل خروجك لأن خدمة المصادقة غير قابلة للوصول. جلستك لا تزال نشطة، لذا يُرجى المحاولة مرة أخرى بعد لحظة.
error-boundary-sessions-title = الجلسات غير متاحة
error-boundary-sessions-body = تعذّر علينا سرد جلساتك النشطة. يُرجى المحاولة مرة أخرى بعد لحظة.
error-boundary-authorized-apps-title = التطبيقات المُصرَّح لها غير متاحة
error-boundary-authorized-apps-no-session-body = تعذّر علينا قراءة جلستك. يُرجى تسجيل الدخول مرة أخرى.
error-boundary-authorized-apps-service-body = تعذّر علينا الوصول إلى خدمة OAuth. يُرجى المحاولة مرة أخرى بعد لحظة.
error-boundary-account-deletion-title = فشل حذف الحساب
error-boundary-account-delete-bad-session = جلستك في حالة غير متوقعة. يُرجى تسجيل الدخول مرة أخرى وإعادة المحاولة.
error-boundary-account-delete-sole-owner = أنت المالك الوحيد لـ { $names }. انقل الملكية إلى عضو آخر قبل حذف حسابك.
error-boundary-account-delete-ownership-check-failed = تعذّر علينا التحقق من ملكيتك للمؤسسة. لم يتغير شيء؛ يُرجى المحاولة مرة أخرى بعد لحظة.
error-boundary-account-delete-consent-unreachable = تعذّر علينا الوصول إلى خدمة الموافقة لإخطار تطبيقاتك المتصلة. لم يتغير شيء؛ يُرجى المحاولة مرة أخرى بعد لحظة.
error-boundary-account-delete-notifications-failed = تعذّر علينا تجهيز إشعارات الحذف. لم يتغير شيء؛ يُرجى المحاولة مرة أخرى.
error-boundary-account-delete-failed = تعذّر علينا حذف حسابك. يُرجى المحاولة مرة أخرى بعد لحظة.

# حدود أخطاء SAML (تُعرَض تحت اللغة الافتراضية؛ استدعاء ACS لا يحمل لغة الطلب).
error-boundary-sso-unavailable-title = الدخول الموحّد غير متاح
error-boundary-sso-unavailable-body = الدخول الموحّد غير متاح لهذا العنوان. تحقق من الرابط الذي أعطاك إياه مسؤولك، أو سجّل الدخول بطريقتك المعتادة.
error-boundary-sso-failed-title = فشل الدخول الموحّد
error-boundary-sso-validation-failed-body = تعذّر التحقق من محاولة تسجيل الدخول هذه. ابدأ من جديد من رابط الدخول الموحّد لمؤسستك.
error-boundary-sso-upstream-failed-body = خدمة تسجيل الدخول غير متاحة مؤقتًا. يُرجى المحاولة مرة أخرى.
error-boundary-sso-no-email-body = لم يوفّر مزوّد الهوية عنوان بريد إلكتروني. اطلب من مسؤولك ربط سمة البريد الإلكتروني في اتصال SAML.

# صفحة خطأ الخدمة الذاتية في Kratos (error.html)، القيم البديلة مضبوطة في Rust.
error-page-generic-title = حدث خطأ ما
error-page-generic-body = تعذّر علينا تحميل الصفحة المطلوبة. ربما انتهت صلاحية الرابط أو استُخدم بالفعل.
error-page-link-expired-title = انتهت صلاحية الرابط
error-page-link-expired-body = لم يعد هذا الرابط صالحًا. يُرجى البدء من جديد من تسجيل الدخول.
error-page-security-title = فشل الفحص الأمني
error-page-already-signed-in-title = مسجّل الدخول بالفعل
error-page-default-message = تعذّر علينا إكمال ذلك الطلب.

# صفحة منع الوصول إلى بوابة الإدارة (admin/forbidden.html)، مضبوطة في Rust.
error-admin-access-denied-title = تم رفض الوصول
error-admin-access-denied-body = حسابك غير مُصرَّح له باستخدام أدوات الإدارة.
error-admin-access-denied-forseti-body = حسابك غير مُصرَّح له باستخدام أدوات الإدارة على مستوى Forseti.
error-admin-access-denied-org-body = ليس لديك وصول إداري إلى تلك المؤسسة.

# حظر SAML
error-saml-blocked-page-title = تم حظر تسجيل الدخول
error-saml-blocked-card-title = تعذّر علينا تسجيل دخولك
error-saml-unverified-prefix = يوجد حساب لـ
error-saml-unverified-suffix = بالفعل لكن لم يُتحقَّق من عنوان بريده الإلكتروني، لذا لا يمكن للدخول الموحّد الارتباط به بأمان. تحقق من العنوان من رسالة تسجيلك الأصلية، أو اطلب المساعدة من مسؤولك.
error-saml-cross-org-not-member = حسابك ليس عضوًا في هذه المؤسسة بعد. اطلب من مسؤولك إضافتك، ثم حاول مرة أخرى.
error-saml-conflict = تعذّر علينا تسجيل دخولك. يُرجى التواصل مع مسؤولك.
error-saml-blocked-cta = الانتقال إلى تسجيل الدخول
