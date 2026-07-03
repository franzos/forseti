# หน้าข้อผิดพลาด
error-reference-id = รหัสอ้างอิง:
error-cta-back-to-sign-in = กลับไปยังหน้าเข้าสู่ระบบ

# การยืนยันการออกจากระบบ OAuth
logout-card-title = ออกจากระบบทุกแอปใช่หรือไม่
logout-card-subtitle = การดำเนินการนี้จะสิ้นสุดเซสชันของคุณกับ { $brand } และแจ้งเตือนทุกแอปที่คุณเข้าสู่ระบบไว้
logout-body-text = แอปที่ขอให้คุณออกจากระบบจะได้รับแจ้งว่าคำขอเสร็จสมบูรณ์แล้ว บางแอปอาจเก็บข้อมูลในเครื่องไว้ในแคชชั่วระยะหนึ่ง การออกจากระบบที่นี่จะสิ้นสุดเซสชันที่ { $brand }
logout-action-sign-out = ออกจากระบบ
logout-action-cancel = ยกเลิก

# ชื่อและเนื้อหาของกล่องโต้ตอบผู้ดูแลระบบที่ใช้โดย render_admin_error ณ จุดเรียกที่มีภาษาท้องถิ่น
# จุดเรียกที่ไม่มีภาษาท้องถิ่น (ฟังก์ชันช่วย ขอบเขตข้อผิดพลาด) จะคงข้อความภาษาอังกฤษไว้
dialog-identity-unavailable-title = ตัวตนไม่พร้อมใช้งาน
dialog-identity-unavailable-body = เราไม่สามารถโหลดตัวตนนั้นได้ อาจถูกลบไปแล้ว
dialog-recovery-code-failed-title = รหัสกู้คืนล้มเหลว
dialog-recovery-code-failed-body = เราสร้างรหัสกู้คืนแล้วแต่ไม่สามารถเตรียมให้แสดงแบบครั้งเดียวได้ สร้างรหัสใหม่เพื่อลองอีกครั้ง
dialog-disable-failed-title = ปิดใช้งานล้มเหลว
dialog-enable-failed-title = เปิดใช้งานล้มเหลว
dialog-delete-failed-title = ลบล้มเหลว
dialog-revoke-failed-title = เพิกถอนล้มเหลว

# ขอบเขตข้อผิดพลาด (error_boundary.html) กำหนดชื่อ/เนื้อหา/ปุ่มในตัวจัดการ Rust
error-boundary-auth-unavailable-title = การยืนยันตัวตนไม่พร้อมใช้งาน
error-boundary-auth-unavailable-body = เราไม่สามารถเข้าถึงบริการยืนยันตัวตนได้ โปรดลองอีกครั้งในอีกสักครู่
error-boundary-cta-try-again = ลองอีกครั้ง
error-boundary-cta-sign-in = เข้าสู่ระบบ
error-boundary-cta-back-to-settings = กลับไปยังการตั้งค่า
error-boundary-cta-back-to-dashboard = กลับไปยังแดชบอร์ด
error-boundary-cta-back-to-account = กลับไปยังบัญชี
error-boundary-signin-title = การเข้าสู่ระบบไม่พร้อมใช้งาน
error-boundary-signup-title = การลงทะเบียนไม่พร้อมใช้งาน
error-boundary-recovery-title = การกู้คืนไม่พร้อมใช้งาน
error-boundary-verification-title = การยืนยันไม่พร้อมใช้งาน
error-boundary-settings-title = การตั้งค่าไม่พร้อมใช้งาน
error-boundary-logout-title = การออกจากระบบไม่พร้อมใช้งาน
error-boundary-logout-body = เราไม่สามารถดำเนินการออกจากระบบให้เสร็จได้เพราะเข้าถึงบริการยืนยันตัวตนไม่ได้ เซสชันของคุณยังคงใช้งานอยู่ โปรดลองอีกครั้งในอีกสักครู่
error-boundary-sessions-title = เซสชันไม่พร้อมใช้งาน
error-boundary-sessions-body = เราไม่สามารถแสดงรายการเซสชันที่ใช้งานอยู่ของคุณได้ โปรดลองอีกครั้งในอีกสักครู่
error-boundary-authorized-apps-title = แอปที่ได้รับอนุญาตไม่พร้อมใช้งาน
error-boundary-authorized-apps-no-session-body = เราไม่สามารถอ่านเซสชันของคุณได้ โปรดเข้าสู่ระบบอีกครั้ง
error-boundary-authorized-apps-service-body = เราไม่สามารถเข้าถึงบริการ OAuth ได้ โปรดลองอีกครั้งในอีกสักครู่
error-boundary-account-deletion-title = การลบบัญชีล้มเหลว
error-boundary-account-delete-bad-session = เซสชันของคุณอยู่ในสถานะที่ไม่คาดคิด โปรดเข้าสู่ระบบอีกครั้งแล้วลองใหม่
error-boundary-account-delete-sole-owner = คุณเป็นเจ้าของเพียงคนเดียวของ { $names } โอนความเป็นเจ้าของให้สมาชิกอื่นก่อนลบบัญชีของคุณ
error-boundary-account-delete-ownership-check-failed = เราไม่สามารถตรวจสอบความเป็นเจ้าขององค์กรของคุณได้ ไม่มีการเปลี่ยนแปลงใด ๆ โปรดลองอีกครั้งในอีกสักครู่
error-boundary-account-delete-consent-unreachable = เราไม่สามารถเข้าถึงบริการให้ความยินยอมเพื่อแจ้งเตือนแอปที่เชื่อมต่อของคุณได้ ไม่มีการเปลี่ยนแปลงใด ๆ โปรดลองอีกครั้งในอีกสักครู่
error-boundary-account-delete-notifications-failed = เราไม่สามารถเตรียมการแจ้งเตือนการลบได้ ไม่มีการเปลี่ยนแปลงใด ๆ โปรดลองอีกครั้ง
error-boundary-account-delete-failed = เราไม่สามารถลบบัญชีของคุณได้ โปรดลองอีกครั้งในอีกสักครู่

# ขอบเขตข้อผิดพลาด SAML (แสดงภายใต้ภาษาท้องถิ่นเริ่มต้น การเรียกกลับ ACS ไม่มีภาษาท้องถิ่นของคำขอ)
error-boundary-sso-unavailable-title = การลงชื่อเข้าใช้ครั้งเดียวไม่พร้อมใช้งาน
error-boundary-sso-unavailable-body = การลงชื่อเข้าใช้ครั้งเดียวไม่พร้อมใช้งานสำหรับที่อยู่นี้ ตรวจสอบลิงก์ที่ผู้ดูแลระบบของคุณให้มา หรือเข้าสู่ระบบด้วยวิธีปกติของคุณ
error-boundary-sso-failed-title = การลงชื่อเข้าใช้ครั้งเดียวล้มเหลว
error-boundary-sso-validation-failed-body = ไม่สามารถตรวจสอบความถูกต้องของการลงชื่อเข้าใช้นี้ได้ เริ่มใหม่จากลิงก์ SSO ขององค์กรของคุณ
error-boundary-sso-upstream-failed-body = บริการลงชื่อเข้าใช้ไม่พร้อมใช้งานชั่วคราว โปรดลองอีกครั้ง
error-boundary-sso-no-email-body = ผู้ให้บริการตัวตนไม่ได้ให้ที่อยู่อีเมลมา ขอให้ผู้ดูแลระบบของคุณแมปแอตทริบิวต์อีเมลบนการเชื่อมต่อ SAML

# หน้าข้อผิดพลาดของบริการตนเองของ Kratos (error.html) กำหนดค่าสำรองใน Rust
error-page-generic-title = เกิดข้อผิดพลาดบางอย่าง
error-page-generic-body = เราไม่สามารถโหลดหน้าที่ร้องขอได้ ลิงก์อาจหมดอายุหรือถูกใช้ไปแล้ว
error-page-link-expired-title = ลิงก์หมดอายุ
error-page-link-expired-body = ลิงก์นี้ใช้ไม่ได้อีกต่อไป โปรดเริ่มใหม่จากหน้าเข้าสู่ระบบ
error-page-security-title = การตรวจสอบความปลอดภัยล้มเหลว
error-page-already-signed-in-title = เข้าสู่ระบบอยู่แล้ว
error-page-default-message = เราไม่สามารถดำเนินการตามคำขอนั้นได้

# หน้าปฏิเสธการเข้าถึงของด่านผู้ดูแลระบบ (admin/forbidden.html) กำหนดใน Rust
error-admin-access-denied-title = ปฏิเสธการเข้าถึง
error-admin-access-denied-body = บัญชีของคุณไม่ได้รับอนุญาตให้ใช้เครื่องมือผู้ดูแลระบบ
error-admin-access-denied-forseti-body = บัญชีของคุณไม่ได้รับอนุญาตให้ใช้เครื่องมือผู้ดูแลระบบระดับ Forseti ทั้งหมด
error-admin-access-denied-org-body = คุณไม่มีสิทธิ์การเข้าถึงระดับผู้ดูแลระบบขององค์กรนั้น

# SAML ถูกบล็อก
error-saml-blocked-page-title = การลงชื่อเข้าใช้ถูกบล็อก
error-saml-blocked-card-title = เราไม่สามารถลงชื่อเข้าใช้ให้คุณได้
error-saml-unverified-prefix = บัญชีสำหรับ
error-saml-unverified-suffix = มีอยู่แล้วแต่ที่อยู่อีเมลยังไม่ได้รับการยืนยัน ดังนั้นการลงชื่อเข้าใช้ครั้งเดียวจึงไม่สามารถผูกกับบัญชีนั้นได้อย่างปลอดภัย ยืนยันที่อยู่จากอีเมลลงทะเบียนเดิมของคุณ หรือขอความช่วยเหลือจากผู้ดูแลระบบของคุณ
error-saml-cross-org-not-member = บัญชีของคุณยังไม่ได้เป็นสมาชิกขององค์กรนี้ ขอให้ผู้ดูแลระบบของคุณเพิ่มคุณเข้าไป แล้วลองอีกครั้ง
error-saml-conflict = เราไม่สามารถลงชื่อเข้าใช้ให้คุณได้ โปรดติดต่อผู้ดูแลระบบของคุณ
error-saml-blocked-cta = ไปยังหน้าเข้าสู่ระบบ
