# صفحة تسجيل الدخول
auth-login-page-title = تسجيل الدخول
auth-login-card-title = تسجيل الدخول إلى حسابك
auth-login-card-subtitle = مرحبًا بعودتك إلى { $brand }.
auth-login-aal2-body = تتطلب هذه المنطقة مصادقة ثنائية العوامل، لكن حسابك لم يُعدّ بعد عاملًا ثانيًا.
auth-login-aal2-hint = قم بإعداد تطبيق مصادقة أو مفتاح أمان أو رموز استرداد في الإعدادات، ثم عُد.
auth-login-aal2-setup-link = إعداد المصادقة الثنائية العوامل
auth-login-forgot-password = هل نسيت كلمة المرور؟
auth-login-no-account = ليس لديك حساب؟
auth-login-create-account = إنشاء حساب

# فاصل مشترك (تسجيل الدخول + التسجيل)
auth-or-continue-with = أو تابع باستخدام

# صفحة التسجيل
auth-registration-page-title = إنشاء حساب
auth-registration-card-title = إنشاء حساب
auth-registration-card-subtitle = سجّل لإدارة هويتك بأمان.
auth-registration-have-account = لديك حساب بالفعل؟
auth-registration-sign-in-link = تسجيل الدخول
auth-registration-claim-body = إذا كان هذا بريدك الإلكتروني ولم تُكمل التسجيل قط،
auth-registration-claim-link = طالِب به

# صفحة الاسترداد
auth-recovery-page-title = استرداد الحساب
auth-recovery-card-title-sent = تحقق من بريدك الإلكتروني
auth-recovery-card-title-default = هل نسيت كلمة المرور؟
auth-recovery-card-subtitle-sent = أرسلنا رمز استرداد إلى صندوق الوارد لديك. أدخله أدناه للمتابعة.
auth-recovery-card-subtitle-default = أدخل بريدك الإلكتروني وسنرسل لك رابطًا لإعادة تعيينها.
auth-recovery-back-to-sign-in = العودة إلى تسجيل الدخول

# صفحة التحقق
auth-verification-page-title = تحقق من بريدك الإلكتروني
auth-verification-card-title-passed = تم التحقق من البريد الإلكتروني
auth-verification-card-title-sent = تحقق من بريدك الإلكتروني
auth-verification-card-title-default = تحقق من بريدك الإلكتروني
auth-verification-card-subtitle-passed = تم تأكيد بريدك الإلكتروني. يمكنك إغلاق هذه التبويبة أو المتابعة.
auth-verification-card-subtitle-sent = أرسلنا رمز تحقق إلى صندوق الوارد لديك. أدخله أدناه للتأكيد.
auth-verification-card-subtitle-default = أدخل بريدك الإلكتروني لتلقّي رمز تحقق.
auth-verification-sent-email-hint = استخدم الرمز من أحدث رسالة تحقق، أو افتح الرابط الموجود في تلك الرسالة بدلًا من كتابة الرمز يدويًا.
auth-verification-back-to-dashboard = العودة إلى لوحة التحكم
auth-verification-back-to-sign-in = العودة إلى تسجيل الدخول

# سلاسل جانب المتصفح لـ WebAuthn / مفاتيح المرور (مضمّنة عبر سمات البيانات في webauthn_helper.html)
auth-webauthn-no-support = متصفحك لا يدعم WebAuthn / مفاتيح المرور.
auth-passkey-needs-platform = يتطلب تسجيل الدخول بمفتاح المرور بيانات اعتماد منصّة على هذا الجهاز (Touch ID أو Windows Hello أو جهاز Android أو مفتاح مرور مُزامَن). متصفحك لا يملك واحدًا مُعدًّا.
auth-webauthn-err-not-allowed = أُلغي طلب بيانات الاعتماد أو انتهت مهلته أو لم تتوفر بيانات اعتماد مطابقة.
auth-webauthn-err-security = رفض متصفحك عملية الأمان. تأكد من تحميل الموقع عبر أصل موثوق ومن مطابقة المُعرّف المُسجَّل.
auth-webauthn-err-invalid-state = توجد بيانات اعتماد مُسجَّلة بالفعل على هذا الجهاز. حاول تسجيل الدخول بدلًا من ذلك، أو استخدم جهازًا مختلفًا.
auth-webauthn-err-not-supported = متصفحك لا يدعم معلَمات بيانات الاعتماد المطلوبة.
auth-webauthn-err-abort = أُجهِض طلب بيانات الاعتماد قبل اكتماله.
auth-webauthn-err-generic-prefix = خطأ في جهاز المصادقة:

# تسميات حقول التدفّق. يُصدر Kratos حقول السمات مع `title` من المخطط تحت
# معرّف التسمية العامة 1070002؛ يتجاوز flow_view.rs هذه القيم بالاسم.
auth-field-email = البريد الإلكتروني
auth-field-first-name = الاسم الأول
auth-field-last-name = اسم العائلة
