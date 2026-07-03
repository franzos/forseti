# การแสดงเวลาแบบสัมพัทธ์ให้อ่านง่าย (src/format.rs::humanise_timestamp)
# `{ $n }` คือขนาดของช่วงเวลา ภาษาอังกฤษใช้คำต่อท้ายหน่วยแบบย่อ
format-relative-just-now = เมื่อสักครู่
format-relative-in-a-moment = ในอีกสักครู่
format-relative-yesterday = เมื่อวาน
format-relative-tomorrow = พรุ่งนี้
format-relative-minutes-ago = { $n } นาทีที่แล้ว
format-relative-minutes-in = ในอีก { $n } นาที
format-relative-hours-ago = { $n } ชม.ที่แล้ว
format-relative-hours-in = ในอีก { $n } ชม.
format-relative-days-ago = { $n } วันที่แล้ว
format-relative-days-in = ในอีก { $n } วัน
format-relative-months-ago = { $n } เดือนที่แล้ว
format-relative-months-in = ในอีก { $n } เดือน
format-relative-years-ago = { $n } ปีที่แล้ว
format-relative-years-in = ในอีก { $n } ปี

# การแสดง User-Agent ให้อ่านง่าย (src/format.rs::humanise_user_agent) ชื่อเบราว์เซอร์และ
# ระบบปฏิบัติการเป็นคำเฉพาะและคงไว้ตามเดิม แปลเฉพาะคำเชื่อมและข้อความสำรองกรณีไม่ทราบ
# เท่านั้น
format-ua-on = { $browser } บน { $os }
format-ua-unknown-browser = เบราว์เซอร์ที่ไม่รู้จัก
format-ua-unknown-os = ระบบปฏิบัติการที่ไม่รู้จัก
format-device-unknown = อุปกรณ์ที่ไม่รู้จัก
