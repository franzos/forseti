# واجهة الإعداد الأولي (قوالب claim_email و invite)

# بريد المطالبة (claim_email.html)
claim-page-title = المطالبة بالبريد الإلكتروني
claim-card-title = المطالبة بعنوان البريد الإلكتروني
claim-subtitle = إذا سجّل أحدهم بريدك الإلكتروني لكنه لم يتحقق منه قط، يمكنك أخذ الملكية بتأكيد أنك تتلقى البريد على هذا العنوان.
claim-email-label = البريد الإلكتروني
claim-send-code = إرسال الرمز
claim-changed-mind = غيّرت رأيك؟
claim-back-to-signup = العودة إلى التسجيل

# تأكيد المطالبة (claim_email_confirm.html)
claim-confirm-page-title = تأكيد المطالبة
claim-confirm-card-title = أكّد رمزك
claim-confirm-subtitle = أدخل الرمز المكوّن من 6 أرقام الذي أرسلناه للتو. تنتهي صلاحية الرموز بعد 15 دقيقة.
claim-confirm-code-label = الرمز
claim-confirm-button = تأكيد
claim-confirm-no-code = لم تصلك رمز؟
claim-confirm-start-over = ابدأ من جديد

# قبول الدعوة (invite/accept.html)
invite-accept-page-title = قبول الدعوة
invite-accept-heading = انضم إلى { $org }
invite-accept-body = لقد دُعيت للانضمام إلى { $org } بصفة { $role }. أُرسلت الدعوة إلى { $email }.

# الدعوة غير متاحة (invite/invalid.html)
invite-invalid-page-title = الدعوة غير متاحة
invite-invalid-heading = الدعوة غير متاحة
invite-invalid-contact = تواصل مع الشخص الذي دعاك لطلب رابط جديد.
invite-invalid-back = العودة إلى لوحة التحكم

# أخطاء تدفّق المطالبة بالبريد (مضبوطة في Rust)
claim-error-invalid-email = أدخل عنوان بريد إلكتروني صالحًا.
claim-error-code-expired = انتهت صلاحية الرمز. ابدأ من جديد.
claim-error-invalid-token = رمز غير صالح. ابدأ من جديد.
claim-error-service-unavailable = الخدمة غير متاحة مؤقتًا. حاول مرة أخرى بعد لحظة.
claim-error-too-many-attempts = رموز خاطئة كثيرة جدًا. ابدأ من جديد.
claim-error-code-mismatch = لم يتطابق الرمز. حاول مرة أخرى.
claim-error-no-longer-claimable = لم يعد بالإمكان المطالبة بهذا البريد الإلكتروني.
claim-error-release-failed = تعذّر علينا تحرير البريد الإلكتروني. تواصل مع الدعم.

# إتمام الدعوة (مضبوط في Rust)
invite-error-corrupt = الدعوة تالفة. تواصل مع مسؤولك.
