# تنسيق الطوابع الزمنية النسبية (src/format.rs::humanise_timestamp).
# `{ $n }` هو مقدار الفترة الزمنية. الإنجليزية تحتفظ باللاحقة المختصرة للوحدة.
format-relative-just-now = الآن
format-relative-in-a-moment = بعد لحظة
format-relative-yesterday = أمس
format-relative-tomorrow = غدًا
format-relative-minutes-ago = قبل { $n } د
format-relative-minutes-in = بعد { $n } د
format-relative-hours-ago = قبل { $n } س
format-relative-hours-in = بعد { $n } س
format-relative-days-ago = قبل { $n } ي
format-relative-days-in = بعد { $n } ي
format-relative-months-ago = قبل { $n } شهر
format-relative-months-in = بعد { $n } شهر
format-relative-years-ago = قبل { $n } سنة
format-relative-years-in = بعد { $n } سنة

# تحسين قراءة وكيل المستخدم (src/format.rs::humanise_user_agent). أسماء المتصفحات
# وأنظمة التشغيل أسماء علم تبقى كما هي؛ يُترجم فقط الرابط والقيم البديلة عند عدم
# التعرّف.
format-ua-on = { $browser } على { $os }
format-ua-unknown-browser = متصفح غير معروف
format-ua-unknown-os = نظام تشغيل غير معروف
format-device-unknown = جهاز غير معروف
