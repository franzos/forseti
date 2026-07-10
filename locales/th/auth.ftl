# หน้าเข้าสู่ระบบ
auth-login-page-title = เข้าสู่ระบบ
auth-login-card-title = เข้าสู่ระบบบัญชีของคุณ
auth-login-card-subtitle = ยินดีต้อนรับกลับสู่ { $brand }
auth-login-aal2-body = พื้นที่นี้จำเป็นต้องใช้การยืนยันตัวตนแบบสองปัจจัย แต่บัญชีของคุณยังไม่ได้ตั้งค่าปัจจัยที่สอง
auth-login-aal2-hint = ตั้งค่าแอปยืนยันตัวตน กุญแจความปลอดภัย หรือรหัสกู้คืนในการตั้งค่า แล้วกลับมาอีกครั้ง
auth-login-aal2-setup-link = ตั้งค่าการยืนยันตัวตนแบบสองปัจจัย
auth-login-forgot-password = ลืมรหัสผ่านใช่หรือไม่
auth-login-no-account = ยังไม่มีบัญชีใช่หรือไม่
auth-login-create-account = สร้างบัญชี

# เส้นแบ่งที่ใช้ร่วมกัน (เข้าสู่ระบบ + ลงทะเบียน)
auth-or-continue-with = หรือดำเนินการต่อด้วย
auth-oidc-signin = เข้าสู่ระบบด้วย { $provider }

# หน้าลงทะเบียน
auth-registration-page-title = สร้างบัญชี
auth-registration-card-title = สร้างบัญชี
auth-registration-card-subtitle = ลงทะเบียนเพื่อจัดการตัวตนของคุณอย่างปลอดภัย
auth-registration-have-account = มีบัญชีอยู่แล้วใช่หรือไม่
auth-registration-sign-in-link = เข้าสู่ระบบ
auth-registration-claim-body = หากนี่คืออีเมลของคุณและคุณยังลงทะเบียนไม่เสร็จ
auth-registration-claim-link = ขอสิทธิ์ครอบครอง

# หน้ากู้คืนบัญชี
auth-recovery-page-title = การกู้คืนบัญชี
auth-recovery-card-title-sent = ตรวจสอบอีเมลของคุณ
auth-recovery-card-title-default = ลืมรหัสผ่านใช่หรือไม่
auth-recovery-card-subtitle-sent = เราได้ส่งรหัสกู้คืนไปยังกล่องจดหมายของคุณแล้ว กรอกรหัสด้านล่างเพื่อดำเนินการต่อ
auth-recovery-card-subtitle-default = กรอกอีเมลของคุณ แล้วเราจะส่งลิงก์เพื่อรีเซ็ตรหัสผ่านให้
auth-recovery-back-to-sign-in = กลับไปยังหน้าเข้าสู่ระบบ

# หน้ายืนยันอีเมล
auth-verification-page-title = ยืนยันอีเมลของคุณ
auth-verification-card-title-passed = ยืนยันอีเมลแล้ว
auth-verification-card-title-sent = ตรวจสอบอีเมลของคุณ
auth-verification-card-title-default = ยืนยันอีเมลของคุณ
auth-verification-card-subtitle-passed = อีเมลของคุณได้รับการยืนยันแล้ว คุณสามารถปิดแท็บนี้หรือดำเนินการต่อได้
auth-verification-card-subtitle-sent = เราได้ส่งรหัสยืนยันไปยังกล่องจดหมายของคุณแล้ว กรอกรหัสด้านล่างเพื่อยืนยัน
auth-verification-card-subtitle-default = กรอกอีเมลของคุณเพื่อรับรหัสยืนยัน
auth-verification-sent-email-hint = ใช้รหัสจากอีเมลยืนยันฉบับล่าสุด หรือเปิดลิงก์ในอีเมลนั้นแทนการพิมพ์รหัสด้วยตนเอง
auth-verification-back-to-dashboard = กลับไปยังแดชบอร์ด
auth-verification-back-to-sign-in = กลับไปยังหน้าเข้าสู่ระบบ

# ข้อความฝั่งเบราว์เซอร์สำหรับ WebAuthn / passkey (ฝังผ่าน data attribute ใน webauthn_helper.html)
auth-webauthn-no-support = เบราว์เซอร์ของคุณไม่รองรับ WebAuthn / passkey
auth-passkey-needs-platform = การเข้าสู่ระบบด้วย passkey ต้องมีข้อมูลรับรองระดับแพลตฟอร์มบนอุปกรณ์นี้ (Touch ID, Windows Hello, อุปกรณ์ Android หรือ passkey ที่ซิงค์ไว้) เบราว์เซอร์ของคุณยังไม่ได้ตั้งค่าไว้
auth-webauthn-err-not-allowed = คำขอข้อมูลรับรองถูกยกเลิก หมดเวลา หรือไม่มีข้อมูลรับรองที่ตรงกัน
auth-webauthn-err-security = เบราว์เซอร์ของคุณปฏิเสธการดำเนินการด้านความปลอดภัย โปรดตรวจสอบว่าเว็บไซต์โหลดผ่านต้นทางที่เชื่อถือได้และตัวระบุที่ลงทะเบียนไว้ตรงกัน
auth-webauthn-err-invalid-state = มีข้อมูลรับรองที่ลงทะเบียนไว้กับอุปกรณ์นี้แล้ว ลองเข้าสู่ระบบแทน หรือใช้อุปกรณ์อื่น
auth-webauthn-err-not-supported = เบราว์เซอร์ของคุณไม่รองรับพารามิเตอร์ข้อมูลรับรองที่ร้องขอ
auth-webauthn-err-abort = คำขอข้อมูลรับรองถูกยกเลิกก่อนที่จะเสร็จสมบูรณ์
auth-webauthn-err-generic-prefix = ข้อผิดพลาดของตัวยืนยันตัวตน:

# ป้ายกำกับฟิลด์ของโฟลว์ Kratos ปล่อยฟิลด์ trait ด้วย `title` ของสคีมาภายใต้ป้าย
# passthrough ทั่วไป id 1070002 flow_view.rs แทนที่ป้ายเหล่านี้ตามชื่อ
auth-field-email = อีเมล
auth-field-first-name = ชื่อ
auth-field-last-name = นามสกุล
