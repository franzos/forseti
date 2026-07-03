# ส่วนเริ่มต้นใช้งาน (เทมเพลต claim_email และ invite)

# อีเมลขอสิทธิ์ครอบครอง (claim_email.html)
claim-page-title = ขอสิทธิ์ครอบครองอีเมล
claim-card-title = ขอสิทธิ์ครอบครองที่อยู่อีเมล
claim-subtitle = หากมีคนลงทะเบียนด้วยอีเมลของคุณแต่ไม่เคยยืนยัน คุณสามารถขอสิทธิ์ครอบครองได้โดยยืนยันว่าคุณได้รับจดหมายที่ส่งมายังที่อยู่นี้
claim-email-label = อีเมล
claim-send-code = ส่งรหัส
claim-changed-mind = เปลี่ยนใจใช่หรือไม่
claim-back-to-signup = กลับไปยังหน้าลงทะเบียน

# ยืนยันการขอสิทธิ์ครอบครอง (claim_email_confirm.html)
claim-confirm-page-title = ยืนยันการขอสิทธิ์ครอบครอง
claim-confirm-card-title = ยืนยันรหัสของคุณ
claim-confirm-subtitle = กรอกรหัส 6 หลักที่เราเพิ่งส่งให้ รหัสจะหมดอายุหลังจาก 15 นาที
claim-confirm-code-label = รหัส
claim-confirm-button = ยืนยัน
claim-confirm-no-code = ไม่ได้รับรหัสใช่หรือไม่
claim-confirm-start-over = เริ่มใหม่

# ตอบรับคำเชิญ (invite/accept.html)
invite-accept-page-title = ตอบรับคำเชิญ
invite-accept-heading = เข้าร่วม { $org }
invite-accept-body = คุณได้รับเชิญให้เข้าร่วม { $org } ในฐานะ { $role } คำเชิญถูกส่งไปยัง { $email }

# คำเชิญไม่พร้อมใช้งาน (invite/invalid.html)
invite-invalid-page-title = คำเชิญไม่พร้อมใช้งาน
invite-invalid-heading = คำเชิญไม่พร้อมใช้งาน
invite-invalid-contact = ติดต่อผู้ที่เชิญคุณเพื่อขอลิงก์ใหม่
invite-invalid-back = กลับไปยังแดชบอร์ด

# ข้อผิดพลาดของโฟลว์ขอสิทธิ์ครอบครองอีเมล (กำหนดใน Rust)
claim-error-invalid-email = กรอกที่อยู่อีเมลที่ถูกต้อง
claim-error-code-expired = รหัสหมดอายุแล้ว เริ่มใหม่
claim-error-invalid-token = โทเคนไม่ถูกต้อง เริ่มใหม่
claim-error-service-unavailable = บริการไม่พร้อมใช้งานชั่วคราว ลองอีกครั้งในอีกสักครู่
claim-error-too-many-attempts = กรอกรหัสผิดมากเกินไป เริ่มใหม่
claim-error-code-mismatch = รหัสไม่ตรงกัน ลองอีกครั้ง
claim-error-no-longer-claimable = อีเมลนี้ไม่สามารถขอสิทธิ์ครอบครองได้อีกต่อไป
claim-error-release-failed = เราไม่สามารถปลดอีเมลได้ ติดต่อฝ่ายสนับสนุน

# การสรุปผลคำเชิญ (กำหนดใน Rust)
invite-error-corrupt = คำเชิญเสียหาย ติดต่อผู้ดูแลระบบของคุณ
