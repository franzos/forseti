# แบนเนอร์ผู้ดูแลระบบ (admin_shell.html)
admin-banner-label = ผู้ดูแลระบบ
admin-banner-body = คุณอยู่บนพื้นที่ที่มีสิทธิ์พิเศษ การดำเนินการที่นี่จะถูกบันทึกในบันทึกการตรวจสอบ

# หัวข้อแถบนำทางผู้ดูแลระบบ (admin_nav.html)
admin-nav-heading = ผู้ดูแลระบบ
admin-nav-subtitle = เครื่องมือผู้ดำเนินการ

# หัวข้อส่วนของแถบนำทางผู้ดูแลระบบ
admin-nav-section-system = ระบบ
admin-nav-section-access = การเข้าถึง
admin-nav-section-linux = Linux

# ป้ายกำกับรายการในแถบนำทางผู้ดูแลระบบ
admin-nav-status = สถานะ
admin-nav-configuration = การกำหนดค่า
admin-nav-audit = การตรวจสอบ
admin-nav-webhooks = Webhook
admin-nav-license = ใบอนุญาต
admin-nav-identities = ตัวตน
admin-nav-sessions = เซสชัน
admin-nav-clients = ไคลเอนต์ OAuth2
admin-nav-dcr-tokens = โทเคน DCR
admin-nav-saml = SAML SSO
admin-nav-hosts = โฮสต์
admin-nav-accounts = บัญชี

# รายการตัวตน (identities_list.html)
admin-identities-page-title = ตัวตน
admin-identities-subtitle = ตัวตนที่จัดการโดย Kratos และสถานะของตัวตนเหล่านั้น
admin-identities-search-placeholder = ค้นหาด้วย ID หรืออีเมล
admin-identities-search-button = ค้นหา
admin-identities-col-email = อีเมล
admin-identities-col-state = สถานะ
admin-identities-col-created = สร้างเมื่อ
admin-identities-empty = ไม่พบตัวตน
admin-identities-prev = กลับไปยังจุดเริ่มต้น
admin-identities-next = หน้าถัดไป

# รายละเอียดตัวตน (identity_show.html)
admin-identity-status-active = ใช้งานอยู่
admin-identity-recovery-code-heading = รหัสกู้คืน (แสดงครั้งเดียว)
admin-identity-recovery-link-heading = ลิงก์กู้คืน
admin-identity-recovery-note = แบ่งปันสิ่งนี้กับผู้ใช้ผ่านช่องทางที่เชื่อถือได้ รหัสจะไม่ถูกแสดงอีก
admin-identity-section-actions = การดำเนินการ
admin-identity-action-generate-recovery = สร้างรหัสกู้คืน
admin-identity-action-disable = ปิดใช้งาน
admin-identity-action-enable = เปิดใช้งาน
admin-identity-action-delete = ลบ
admin-identity-section-traits = คุณลักษณะ
admin-identity-section-addresses = ที่อยู่ที่ยืนยันได้
admin-identity-addresses-empty = ตัวตนนี้ไม่มีที่อยู่ที่ยืนยันได้
admin-identity-status-verified = ยืนยันแล้ว
admin-identity-status-pending = รอดำเนินการ
admin-identity-section-credentials = ข้อมูลรับรอง
admin-identity-credentials-empty = ยังไม่ได้กำหนดค่าข้อมูลรับรอง
admin-identity-section-sessions = เซสชันล่าสุด
admin-identity-sessions-empty = ไม่มีประวัติเซสชัน
admin-identity-action-revoke-session = เพิกถอนเซสชัน

# ตัวเลือกตัวตน (identity_picker.html)
admin-identity-picker-page-title = เลือกผู้ใช้
admin-identity-picker-subtitle = เลือกตัวตนเพื่อดำเนินการต่อ
admin-identity-picker-invalid-return = เป้าหมายการกลับไม่ถูกต้อง
admin-identity-picker-search-placeholder = ค้นหาด้วย ID หรืออีเมล
admin-identity-picker-search-button = ค้นหา
admin-identity-picker-col-email = อีเมล
admin-identity-picker-col-state = สถานะ
admin-identity-picker-col-created = สร้างเมื่อ
admin-identity-picker-empty = ไม่พบตัวตน
admin-identity-picker-action-select = เลือก
admin-identity-picker-prev = กลับไปยังจุดเริ่มต้น
admin-identity-picker-next = หน้าถัดไป

# รายการเซสชัน (sessions_list.html)
admin-sessions-page-title = เซสชัน
admin-sessions-subtitle = ทุกเซสชันที่ Kratos รู้จัก ครอบคลุมทุกตัวตน
admin-sessions-filter-active-only = เฉพาะเซสชันที่ใช้งานอยู่
admin-sessions-col-identity = ตัวตน
admin-sessions-col-authenticated = ยืนยันตัวตนเมื่อ
admin-sessions-col-expires = หมดอายุ
admin-sessions-col-device = อุปกรณ์
admin-sessions-empty = ไม่มีเซสชันให้แสดง
admin-sessions-action-revoke = เพิกถอน
admin-sessions-prev = กลับไปยังจุดเริ่มต้น
admin-sessions-next = หน้าถัดไป

# กล่องโต้ตอบยืนยันทั่วไป (confirm.html)
admin-confirm-cancel = ยกเลิก

# หน้าปฏิเสธการเข้าถึง (forbidden.html)
admin-forbidden-back = กลับไปยังแดชบอร์ด

# หน้าข้อผิดพลาดของผู้ดูแลระบบ (error.html)
admin-error-back = กลับไปยังสถานะผู้ดูแลระบบ

# รายการไคลเอนต์ (clients_list.html)
admin-clients-page-title = ไคลเอนต์ OAuth2
admin-clients-subtitle = ฝ่ายที่พึ่งพา (relying party) ที่ลงทะเบียนกับ Hydra
admin-clients-action-new = ไคลเอนต์ใหม่
admin-clients-search-placeholder = ค้นหาด้วยชื่อหรือ ID ของไคลเอนต์
admin-clients-filter-all-types = ทุกประเภท
admin-clients-filter-all-verifications = การยืนยันทั้งหมด
admin-clients-filter-verified = ยืนยันแล้ว
admin-clients-filter-unverified = ยังไม่ได้ยืนยัน
admin-clients-search-button = ค้นหา
admin-clients-col-name = ชื่อ
admin-clients-col-type = ประเภท
admin-clients-col-grants = การให้สิทธิ์
admin-clients-col-created = สร้างเมื่อ
admin-clients-badge-unverified-title = ยังไม่ได้ผ่านการตรวจสอบโดยผู้ดูแลระบบ
admin-clients-badge-self-registered = ลงทะเบียนด้วยตนเอง
admin-clients-badge-self-registered-title = ลงทะเบียนผ่าน /oauth2/register (RFC 7591)
admin-clients-empty = ไม่มีไคลเอนต์ที่ลงทะเบียน
admin-clients-prev = กลับไปยังจุดเริ่มต้น
admin-clients-next = หน้าถัดไป

# ป้ายที่ใช้ร่วมกันของไคลเอนต์ (clients_list.html, client_show.html)
admin-client-badge-verified = ยืนยันแล้ว
admin-client-badge-unverified = ยังไม่ได้ยืนยัน
admin-client-badge-unverified-title = ผู้ดูแลระบบยังไม่ได้ตรวจสอบไคลเอนต์นี้ หน้าจอให้ความยินยอมจะเตือนผู้ใช้ปลายทาง

# หัวข้อหน้าฟอร์มไคลเอนต์ (client_form.html)
admin-client-form-title-new = ไคลเอนต์ใหม่
admin-client-form-title-edit = แก้ไขไคลเอนต์
admin-client-form-heading-new = ไคลเอนต์ OAuth2 ใหม่
admin-client-form-heading-edit = แก้ไขไคลเอนต์
admin-client-form-preset-note = ค่าเริ่มต้นถูกกรอกไว้ล่วงหน้าสำหรับประเภทนี้
admin-client-form-preset-change = เปลี่ยนประเภท

# ฟิลด์ฟอร์มที่ใช้ร่วมกันของไคลเอนต์ (client_form.html, ฟอร์มแก้ไขใน client_show.html)
admin-client-field-name = ชื่อไคลเอนต์
admin-client-field-grant-types = ประเภทการให้สิทธิ์
admin-client-grant-auth-code-hint = (การเข้าสู่ระบบที่ขับเคลื่อนโดยผู้ใช้)
admin-client-grant-refresh-hint = (เซสชันที่อยู่ได้นาน)
admin-client-grant-client-creds-hint = (บริการต่อบริการ)
admin-client-field-response-types = ประเภทการตอบกลับ
admin-client-field-scope = ขอบเขต
admin-client-field-scope-hint = ขอบเขต OAuth2 คั่นด้วยช่องว่าง
admin-client-field-redirect-uris = URI สำหรับเปลี่ยนเส้นทาง
admin-client-field-redirect-uris-hint = หนึ่งรายการต่อบรรทัด (หรือคั่นด้วยจุลภาค)
admin-client-field-post-logout-uris = URI เปลี่ยนเส้นทางหลังออกจากระบบ
admin-client-section-logout-fanout = การกระจายการออกจากระบบ OIDC
admin-client-section-logout-fanout-desc = เมื่อผู้ใช้สิ้นสุดเซสชันผ่าน Forseti Hydra จะแจ้งเตือนไคลเอนต์บน URI เหล่านี้เพื่อให้แต่ละแอปสามารถล้างเซสชันในเครื่องได้ เว้นว่างไว้เพื่อยกเลิกการรวมไคลเอนต์นี้เข้าในการกระจาย
admin-client-field-backchannel-uri = URI การออกจากระบบแบบ back-channel
admin-client-field-backchannel-uri-hint = Hydra จะ POST โทเคนการออกจากระบบที่ลงลายเซ็นมาที่นี่ (เซิร์ฟเวอร์ต่อเซิร์ฟเวอร์) โดยทั่วไปมีความหมายเฉพาะกับเว็บแอปที่แสดงผลฝั่งเซิร์ฟเวอร์และ BFF
admin-client-field-backchannel-sid-prefix = กำหนดให้ต้องมีการอ้างสิทธิ์
admin-client-field-backchannel-sid-suffix = ในโทเคนการออกจากระบบแบบ back-channel
admin-client-field-backchannel-sid-short = การอ้างสิทธิ์
admin-client-field-frontchannel-uri = URI การออกจากระบบแบบ front-channel
admin-client-field-frontchannel-uri-hint = Hydra จะฝัง URL นี้ใน iframe ระหว่างการออกจากระบบเพื่อให้แต่ละแอปสามารถล้างคุกกี้เซสชันในเบราว์เซอร์ได้
admin-client-field-frontchannel-sid-prefix = กำหนดให้ต้องมีพารามิเตอร์คิวรี
admin-client-field-frontchannel-sid-middle = +
admin-client-field-frontchannel-sid-suffix = ในการออกจากระบบแบบ front-channel
admin-client-field-frontchannel-sid-short = พารามิเตอร์คิวรี
admin-client-field-token-auth = วิธีการยืนยันตัวตนของ token endpoint
admin-client-token-auth-post-hint = (รหัสลับในเนื้อหา POST)
admin-client-token-auth-basic-hint = (รหัสลับในส่วนหัว Authorization)
admin-client-token-auth-none-hint = (ไคลเอนต์สาธารณะ, PKCE)
admin-client-token-auth-none-short = ไม่มี (สาธารณะ + PKCE)
admin-client-field-audience = รายการอนุญาต audience
admin-client-field-audience-hint-short = หนึ่งรายการต่อบรรทัด Hydra กำหนดให้ต้องลงทะเบียนค่า audience ไว้ล่วงหน้าที่นี่
admin-client-field-require-pkce = กำหนดให้ต้องใช้ PKCE (เพื่อเป็นข้อมูล)
admin-client-field-skip-consent = ไคลเอนต์ที่เชื่อถือได้ (ข้ามหน้าจอให้ความยินยอม)
admin-client-field-webhook-url = URL webhook การลบบัญชี
admin-client-action-cancel = ยกเลิก

# หน้าแสดงไคลเอนต์ (client_show.html)
admin-client-action-revoke-verification = เพิกถอนการยืนยัน
admin-client-action-mark-verified = ทำเครื่องหมายว่ายืนยันแล้ว
admin-client-action-rotate-secret = หมุนเวียนรหัสลับ
admin-client-action-delete = ลบ
admin-client-credentials-heading = ข้อมูลรับรอง: แสดงครั้งเดียว
admin-client-credentials-note = คัดลอกสิ่งเหล่านี้ตอนนี้ ข้อมูลจะไม่ถูกแสดงอีก โหลดหน้าใหม่เพื่อปิด ID ไคลเอนต์และ endpoint ด้านบนไม่ใช่ความลับและยังคงมองเห็นได้
admin-client-credentials-secret-label = รหัสลับไคลเอนต์
admin-client-credentials-rat-label = โทเคนการเข้าถึงการลงทะเบียน
admin-client-credentials-rat-note = ตาม RFC 7592: ให้ไคลเอนต์จัดการการลงทะเบียนของตนเอง (อ่าน/อัปเดต/ลบ) ผ่าน API การลงทะเบียนไคลเอนต์แบบไดนามิกของ Hydra ไม่สามารถออกใหม่ได้ ดังนั้นหากไม่แน่ใจ ให้เก็บไว้
admin-client-undoc-scopes-heading = ขอบเขตที่ไม่มีเอกสาร
admin-client-section-connection = รายละเอียดการเชื่อมต่อ
admin-client-connection-intro = วางสิ่งเหล่านี้ในการกำหนดค่าไคลเอนต์ OIDC/OAuth ฝั่งแอป
admin-client-conn-client-id = ID ไคลเอนต์
admin-client-conn-issuer = ผู้ออก
admin-client-conn-discovery-url = URL การค้นพบ
admin-client-conn-auth-endpoint = Authorization endpoint
admin-client-conn-token-endpoint = Token endpoint
admin-client-conn-userinfo-endpoint = Userinfo endpoint
admin-client-conn-jwks-uri = JWKS URI
admin-client-conn-end-session-endpoint = End-session endpoint
admin-client-section-config = การกำหนดค่า
admin-client-config-sid-required = (ต้องมี sid)
admin-client-config-iss-sid-required = (ต้องมี iss+sid)
admin-client-not-configured = ยังไม่ได้กำหนดค่า
admin-client-audience-none = ไม่มี
admin-client-config-token-auth = การยืนยันตัวตนของ token endpoint
admin-client-config-require-pkce = กำหนดให้ต้องใช้ PKCE
admin-client-bool-yes = ใช่
admin-client-bool-no = ไม่ใช่
admin-client-config-trusted = เชื่อถือได้ (ข้ามความยินยอม)
admin-client-config-created = สร้างเมื่อ
admin-client-config-provenance-audience = Audience
admin-client-config-provenance-audience-note = (ประกาศโดยผู้เรียก DCR)
admin-client-config-provenance-url = ใช้ที่
admin-client-config-provenance-url-note = (สังเกตครั้งแรกตอนให้ความยินยอม)
admin-client-config-webhook = Webhook การลบบัญชี
admin-client-section-edit = แก้ไข
admin-client-action-save = บันทึกการเปลี่ยนแปลง
admin-client-action-back = กลับไปยังรายการ

# ตัวเลือกประเภทไคลเอนต์ (client_type_picker.html)
admin-client-type-page-title = ไคลเอนต์ใหม่
admin-client-type-heading = ไคลเอนต์ OAuth2 ใหม่
admin-client-type-subtitle = เลือกประเภทแอปพลิเคชัน หน้าถัดไปคือฟอร์มเดียวกัน โดยกรอกค่าเริ่มต้นที่ถูกต้องไว้แล้ว เพื่อไม่ให้คุณตกอยู่ในชุดค่าผสมที่ใช้งานไม่ได้โดยไม่ตั้งใจ
admin-client-type-popular-heading = แอปยอดนิยม
admin-client-type-action-cancel = ยกเลิก

# รายการโทเคน DCR (dcr_tokens_list.html)
admin-dcr-page-title = โทเคนการเข้าถึงเริ่มต้น DCR
admin-dcr-action-issue = ออกโทเคน
admin-dcr-token-revealed-heading = โทเคนการเข้าถึงเริ่มต้น (แสดงครั้งเดียว)
admin-dcr-col-status = สถานะ
admin-dcr-col-note = หมายเหตุ
admin-dcr-col-created-by = สร้างโดย
admin-dcr-col-created = สร้างเมื่อ
admin-dcr-col-expires = หมดอายุ
admin-dcr-col-uses-left = จำนวนครั้งที่เหลือ
admin-dcr-status-active = ใช้งานอยู่
admin-dcr-status-revoked = เพิกถอนแล้ว
admin-dcr-status-expired = หมดอายุแล้ว
admin-dcr-status-exhausted = ใช้หมดแล้ว
admin-dcr-empty-prefix = ยังไม่ได้ออกโทเคน
admin-dcr-empty-link = ออกสักหนึ่ง
admin-dcr-empty-suffix = เพื่อเปิดใช้งานการลงทะเบียนด้วยตนเอง
admin-dcr-action-revoke = เพิกถอน

# โทเคน DCR ใหม่ (dcr_token_new.html)
admin-dcr-new-page-title = ออกโทเคน DCR
admin-dcr-new-heading = ออกโทเคนการเข้าถึงเริ่มต้น DCR
admin-dcr-new-field-note = หมายเหตุ
admin-dcr-new-field-note-placeholder = โทเคนนี้ใช้ทำอะไร (เช่น 'Claude Desktop for formshive')
admin-dcr-new-field-note-hint = ไม่บังคับ สำหรับบันทึกของคุณเท่านั้น ผู้เขียนไคลเอนต์จะไม่เห็นข้อความนี้
admin-dcr-new-field-ttl = TTL (ชั่วโมง)
admin-dcr-new-field-ttl-hint = เว้นว่างไว้เพื่อไม่ให้หมดอายุ
admin-dcr-new-field-max-uses = จำนวนครั้งใช้งานสูงสุด
admin-dcr-new-action-cancel = ยกเลิก

# หน้าสถานะ (status.html)
admin-status-page-title = สถานะ
admin-status-heading = สถานะระบบ
admin-status-subtitle = สุขภาพแบบเรียลไทม์ของส่วนประกอบ IdP คิว courier และเวอร์ชันบิลด์
admin-status-issuer-label = ผู้ออก
admin-status-issuer-config-link = ดูการกำหนดค่า →
admin-status-warning-db-label = ฐานข้อมูล
admin-status-warning-db-body = sqlite + การปรับใช้ที่ดูเหมือนใช้งานจริง การตั้งค่าแบบหลายอินสแตนซ์จะทำให้ฐานข้อมูลเสียหาย เปลี่ยนไปใช้ Postgres สำหรับ HA
admin-status-warning-webhook-label = การกระจาย Webhook
admin-status-dead-webhook-count =
    { $count ->
       *[other] มีแถว webhook การลบบัญชีที่ตกไปยัง dead-letter { $count } แถว
    }
admin-status-dead-webhook-middle = (ผู้รับไม่ได้รับการแจ้งเตือน)
admin-status-dead-webhook-open = เปิด /admin/webhooks
admin-status-dead-webhook-action = เพื่อจัดคิวใหม่หรือทิ้ง
admin-status-section-services = บริการ
admin-status-col-service = บริการ
admin-status-col-state = สถานะ
admin-status-col-detail = รายละเอียด
admin-status-state-up = ทำงานอยู่
admin-status-state-down = ไม่ทำงาน
admin-status-section-courier = คิว courier
admin-status-courier-pending = รอดำเนินการ (อยู่ในคิว)
admin-status-courier-failed = ล้มเหลว (ถูกละทิ้ง)
admin-status-courier-last-webhook = webhook การตรวจสอบล่าสุด
admin-status-courier-never = ไม่เคย
admin-status-section-audit = การตรวจสอบ
admin-status-audit-write-failures = การเขียนบันทึกการตรวจสอบล้มเหลว (ตั้งแต่บูต)
admin-status-audit-write-failures-note-prefix = แถวสามารถกู้คืนได้จากบรรทัด
admin-status-audit-write-failures-note-suffix = ที่มีโครงสร้างซึ่ง Forseti ส่งออกไปยัง stderr ในเวลาที่เกิดความล้มเหลว
admin-status-audit-webhook-rejected = webhook การตรวจสอบถูกปฏิเสธ (ตั้งแต่บูต)
admin-status-audit-webhook-rejected-note-prefix = เพย์โหลดผิดรูปแบบหรือการกระทำที่ไม่รู้จัก มีแนวโน้มว่าเป็นความไม่ตรงกันของ hook/config ของ Kratos ตรวจสอบบันทึก
admin-status-audit-webhook-rejected-note-suffix = ระดับ warn
admin-status-audit-freshness = ความผิดปกติด้านความสดใหม่ของ webhook การตรวจสอบ (ตั้งแต่บูต)
admin-status-audit-freshness-note = เพย์โหลดถูกประทับว่าเก่าหรือลงวันที่ในอนาคต โดยปกติเกิดจากโฟลว์ที่ช้าหรือนาฬิกาคลาดเคลื่อน แถวยังคงถูกบันทึกและตั้งค่าสถานะไว้
admin-status-section-license = ใบอนุญาต
admin-status-license-oss-prefix = การปรับใช้ระดับ OSS
admin-status-license-oss-link = เปิดใช้งานใบอนุญาต
admin-status-license-oss-suffix = เพื่อปลดล็อกฟีเจอร์พรีเมียม
admin-status-section-build = เวอร์ชันบิลด์
admin-status-build-forseti = Forseti
admin-status-build-kratos = Kratos
admin-status-build-hydra = Hydra
admin-status-build-database = ฐานข้อมูล

# หน้าการกำหนดค่า (configuration.html)
admin-config-page-title = การกำหนดค่า
admin-config-subtitle = ผู้ให้บริการตัวตนนี้กำหนดค่าอย่างไร: endpoint และความสามารถของ OIDC กุญแจการลงลายเซ็น และสคีมาตัวตนของ Kratos
admin-config-discovery-warning-label = การค้นพบ OIDC
admin-config-discovery-warning-body = ไม่สามารถเข้าถึงเอกสารการค้นพบของ Hydra ได้ endpoint และความสามารถจะถูกซ่อนไว้จนกว่าจะเข้าถึงได้อีกครั้ง
admin-config-section-oidc = OIDC endpoint
admin-config-field-issuer = ผู้ออก
admin-config-field-discovery-url = URL การค้นพบ
admin-config-field-authorization = Authorization
admin-config-field-token = Token
admin-config-field-userinfo = Userinfo
admin-config-field-jwks = JWKS
admin-config-field-end-session = End session
admin-config-field-registration = การลงทะเบียน (DCR)
admin-config-field-revocation = การเพิกถอน
admin-config-section-capabilities = ความสามารถ
admin-config-cap-scopes = ขอบเขต
admin-config-cap-grant-types = ประเภทการให้สิทธิ์
admin-config-cap-response-types = ประเภทการตอบกลับ
admin-config-cap-token-auth-methods = วิธีการยืนยันตัวตนของ token endpoint
admin-config-cap-pkce-methods = วิธีการ PKCE
admin-config-cap-id-token-signing-algs = อัลกอริทึมการลงลายเซ็น ID token
admin-config-cap-subject-types = ประเภท subject
admin-config-cap-backchannel-logout = การออกจากระบบแบบ back-channel
admin-config-cap-frontchannel-logout = การออกจากระบบแบบ front-channel
admin-config-cap-yes = ใช่
admin-config-cap-no = ไม่ใช่
admin-config-section-signing-keys = กุญแจการลงลายเซ็น (JWKS)
admin-config-signing-keys-unavailable = ไม่พร้อมใช้งาน: ไม่สามารถดึงกุญแจสาธารณะของ Hydra ได้
admin-config-signing-keys-empty = Hydra ไม่ได้ประกาศกุญแจการลงลายเซ็น
admin-config-col-key-id = ID กุญแจ
admin-config-col-alg = อัลกอริทึม
admin-config-col-type = ประเภท
admin-config-col-use = การใช้งาน
admin-config-section-schemas = สคีมาตัวตนของ Kratos
admin-config-schemas-unavailable = ไม่พร้อมใช้งาน: ไม่สามารถดึงสคีมาตัวตนจาก Kratos ได้
admin-config-schemas-empty = ไม่มีสคีมาตัวตนที่ลงทะเบียน

# รายการการตรวจสอบ (audit.html)
admin-audit-page-title = การตรวจสอบ
admin-audit-subtitle = บันทึกเหตุการณ์แบบเพิ่มต่อท้ายเท่านั้น บันทึกการดำเนินการของผู้ดูแลระบบฝั่ง Forseti การให้สิทธิ์ OAuth การเปลี่ยนแปลงเซสชัน และการเสร็จสิ้นโฟลว์ Kratos ที่ส่งมาผ่าน webhook การเก็บรักษากำหนดค่าโดยผู้ดำเนินการ (`[audit].audit_retention_days`) การตัดข้อมูลเป็นคำสั่งย่อย CLI ไม่ใช่อัตโนมัติ
admin-audit-filter-email = อีเมลที่มีคำว่า
admin-audit-filter-action = คำนำหน้าการกระทำ
admin-audit-filter-severity = ระดับความรุนแรง
admin-audit-filter-since = ตั้งแต่
admin-audit-severity-any = ทั้งหมด
admin-audit-severity-info = ข้อมูล
admin-audit-severity-warning = คำเตือน
admin-audit-severity-error = ข้อผิดพลาด
admin-audit-severity-critical = วิกฤต
admin-audit-filter-button = กรอง
admin-audit-col-target = เป้าหมาย
admin-audit-col-severity = ระดับความรุนแรง
admin-audit-col-when = เมื่อ
admin-audit-col-actor = ผู้กระทำ
admin-audit-col-action = การกระทำ
admin-audit-col-actions = การดำเนินการ
admin-audit-empty = ไม่มีเหตุการณ์ที่ตรงกับตัวกรองปัจจุบัน
admin-audit-badge-critical = วิกฤต
admin-audit-badge-error = ข้อผิดพลาด
admin-audit-badge-warning = คำเตือน
admin-audit-action-view = ดู
admin-audit-prev = ‹ ก่อนหน้า
admin-audit-next = ถัดไป ›

# รายละเอียดการตรวจสอบ (audit_show.html)
admin-audit-back = ← กลับไปยังการตรวจสอบ
admin-audit-show-section-event = เหตุการณ์
admin-audit-show-outcome = ผลลัพธ์
admin-audit-show-success = สำเร็จ
admin-audit-show-failure = ล้มเหลว
admin-audit-show-section-actor = ผู้กระทำ
admin-audit-show-field-kind = ชนิด
admin-audit-show-field-email = อีเมล
admin-audit-show-none = ไม่มี
admin-audit-show-field-identity-id = ID ตัวตน
admin-audit-show-section-target = เป้าหมาย
admin-audit-show-field-label = ป้ายกำกับ
admin-audit-show-deleted = (ลบแล้ว)
admin-audit-show-field-target-id = ID เป้าหมาย
admin-audit-show-section-metadata = เมตาดาตา
admin-audit-show-section-request-context = บริบทของคำขอ
admin-audit-show-field-ip-hash = แฮช IP
admin-audit-show-field-user-agent = User agent
admin-audit-show-field-request-id = ID คำขอ
admin-audit-show-field-org-id = ID องค์กร

# รายการ Webhook (webhooks.html)
admin-webhooks-page-title = Webhook
admin-webhooks-heading = Webhook ที่ตกไปยัง dead-letter
admin-webhooks-subtitle = การแจ้งเตือนการลบบัญชีที่ใช้ความพยายามในการลองใหม่จนหมด (12 ครั้งหรือ 72 ชั่วโมง แล้วแต่ว่าอย่างใดมาถึงก่อน) คลิกที่แถวเพื่อดูเพย์โหลดฉบับเต็มและข้อผิดพลาดล่าสุด หรือจัดคิวใหม่จากสรุปหากคุณทราบว่าผู้รับกลับมาทำงานปกติแล้ว
admin-webhooks-empty = ไม่มีแถวที่ตกไปยัง dead-letter ทุกอย่างส่งผ่านได้
admin-webhooks-col-client = ไคลเอนต์
admin-webhooks-col-event = เหตุการณ์
admin-webhooks-col-attempts = จำนวนครั้งที่พยายาม
admin-webhooks-col-age = อายุ
admin-webhooks-col-actions = การดำเนินการ
admin-webhooks-deleted = (ลบแล้ว)
admin-webhooks-action-view = ดู
admin-webhooks-action-requeue = จัดคิวใหม่

# รายละเอียด Webhook (webhook_show.html)
admin-webhook-back = ← กลับไปยัง webhook
admin-webhook-heading = Webhook ที่ตกไปยัง dead-letter
admin-webhook-action-requeue = จัดคิวใหม่
admin-webhook-action-discard = ทิ้ง
admin-webhook-section-delivery = การส่ง
admin-webhook-field-client = ไคลเอนต์
admin-webhook-deleted = (ลบแล้ว)
admin-webhook-field-state = สถานะ
admin-webhook-field-url = URL
admin-webhook-field-attempts = จำนวนครั้งที่พยายาม
admin-webhook-field-created = สร้างเมื่อ
admin-webhook-field-next-attempt = ความพยายามครั้งถัดไป
admin-webhook-section-last-error = ข้อผิดพลาดล่าสุด
admin-webhook-section-payload = เพย์โหลดที่ลงลายเซ็น

# รายการบัญชี POSIX (posix_list.html)
admin-posix-page-title = บัญชี POSIX
admin-posix-subtitle = ตัวตน Kratos ที่แปลงเป็นบัญชี Linux (uid/gid + กุญแจ SSH) สำหรับตัวแก้ไข NSS
admin-posix-seats-label = ที่นั่งที่ใช้อยู่:
admin-posix-license-note = ใบอนุญาตการยืนยันตัวตน Linux เชิงพาณิชย์จะเพิ่มขีดจำกัด
admin-posix-action-provision = จัดเตรียมบัญชี
admin-posix-col-username = ชื่อผู้ใช้
admin-posix-col-uid = UID
admin-posix-col-gid = GID
admin-posix-col-status = สถานะ
admin-posix-col-created = สร้างเมื่อ
admin-posix-empty-prefix = ไม่มีบัญชี POSIX ที่เปิดใช้งาน
admin-posix-empty-link = จัดเตรียมสักหนึ่ง
admin-posix-empty-suffix = จากตัวตน Kratos
admin-posix-status-enabled = เปิดใช้งาน
admin-posix-status-disabled = ปิดใช้งาน
admin-posix-action-manage = จัดการ

# รายละเอียดบัญชี POSIX (posix_account.html)
admin-posix-action-disable = ปิดใช้งาน
admin-posix-action-enable = เปิดใช้งาน
admin-posix-action-delete = ลบ
admin-posix-ssh-keys-heading = กุญแจ SSH
admin-posix-ssh-empty = ยังไม่มีกุญแจ SSH
admin-posix-ssh-key-added-prefix = เพิ่มเมื่อ
admin-posix-ssh-action-remove = ลบออก
admin-posix-ssh-field-public-key = กุญแจสาธารณะ
admin-posix-ssh-field-comment = ความคิดเห็น (ไม่บังคับ)
admin-posix-ssh-action-add = เพิ่มกุญแจ
admin-posix-teams-heading = ทีม
admin-posix-hosts-heading = โฮสต์ที่เข้าถึงได้
admin-posix-back = ← บัญชี POSIX ทั้งหมด

# บัญชี POSIX ใหม่ (posix_new.html)
admin-posix-new-page-title = จัดเตรียมบัญชี POSIX
admin-posix-new-heading = จัดเตรียมบัญชี POSIX
admin-posix-new-choose-identity = เลือกตัวตนที่จะจัดเตรียม
admin-posix-new-action-select-user = เลือกผู้ใช้
admin-posix-new-or-enter-directly = หรือกรอกโดยตรง
admin-posix-new-placeholder-id = UUID หรืออีเมล
admin-posix-new-action-continue = ดำเนินการต่อ
admin-posix-new-provision-intro = แปลงตัวตน Kratos เป็นบัญชี Linux uid/gid จะถูกจัดสรรโดยอัตโนมัติและสร้างกลุ่มหลัก
admin-posix-new-selected-prefix = เลือกแล้ว:
admin-posix-new-action-change = เปลี่ยน
admin-posix-new-field-username = ชื่อผู้ใช้
admin-posix-new-username-hint = แนะนำจากอีเมล แก้ไขได้ตามต้องการ 1–32 ตัวอักษร ตัวพิมพ์เล็ก ขึ้นต้นด้วยตัวอักษรหรือขีดล่าง ค่านี้จะกลายเป็นชื่อเข้าสู่ระบบ POSIX
admin-posix-new-field-shell = เชลล์เข้าสู่ระบบ
admin-posix-new-action-cancel = ยกเลิก

# รายการโฮสต์ (hosts_list.html)
admin-hosts-page-title = โฮสต์
admin-hosts-subtitle = เครื่อง Linux ที่ลงทะเบียนกับตัวแก้ไข POSIX/NSS ของ Forseti แต่ละโฮสต์ยืนยันตัวตนด้วยรหัสลับใช้ครั้งเดียวที่คุณแสดงตอนลงทะเบียน
admin-hosts-action-enroll = ลงทะเบียนโฮสต์
admin-hosts-credential-heading = ข้อมูลรับรองโฮสต์ (แสดงครั้งเดียว)
admin-hosts-credential-note-prefix = รูปแบบคือ
admin-hosts-credential-note-suffix = กำหนดค่าตัวแทนโฮสต์ด้วยข้อมูลรับรองนี้ตอนนี้ เราไม่เก็บรหัสลับดิบ เก็บเพียง SHA-256 ของมัน
admin-hosts-col-hostname = ชื่อโฮสต์
admin-hosts-col-teams = ทีม
admin-hosts-col-force-mfa = บังคับ MFA
admin-hosts-col-enrolled = ลงทะเบียนเมื่อ
admin-hosts-col-last-seen = พบล่าสุด
admin-hosts-empty-prefix = ไม่มีโฮสต์ที่ลงทะเบียน
admin-hosts-empty-link = ลงทะเบียนสักหนึ่ง
admin-hosts-empty-suffix = เพื่อให้สามารถแก้ไขบัญชี POSIX ได้
admin-hosts-status-mfa-pending = MFA (รอดำเนินการ)
admin-hosts-mfa-pending-title = บันทึกแล้วแต่ยังไม่บังคับใช้ การบังคับใช้จะมาพร้อมกับการเข้าสู่ระบบแบบโต้ตอบ (PAM)
admin-hosts-action-edit = แก้ไข
admin-hosts-action-rotate = หมุนเวียน
admin-hosts-action-revoke = เพิกถอน

# แก้ไขโฮสต์ (hosts_edit.html)
admin-hosts-edit-page-title = แก้ไขโฮสต์
admin-hosts-edit-intro = อัปเดตป้ายกำกับโฮสต์ ธง MFA และทีมที่กำหนดขอบเขตให้ รหัสลับจะไม่แสดงที่นี่ หมุนเวียนจากรายการโฮสต์หากคุณต้องการรหัสใหม่
admin-hosts-field-hostname = ชื่อโฮสต์
admin-hosts-hostname-hint = ป้ายกำกับสำหรับบันทึกของคุณ ไม่จำเป็นต้องตรงกับชื่อโฮสต์จริงของเครื่อง
admin-hosts-field-org = องค์กร
admin-hosts-org-fixed-note = องค์กรของโฮสต์ถูกกำหนดตายตัวตอนลงทะเบียนและไม่สามารถเปลี่ยนได้ที่นี่
admin-hosts-field-allowed-teams = ทีมที่อนุญาต
admin-hosts-teams-empty = ยังไม่มีทีมอยู่ โฮสต์นี้อนุญาตสมาชิกองค์กรใดก็ได้ การกำหนดขอบเขตโฮสต์ให้เฉพาะทีมต้องใช้ฟีเจอร์องค์กร
admin-hosts-teams-hint = จำกัดโฮสต์นี้ไว้เฉพาะสมาชิกของทีมที่เลือก ไม่เลือกทีมใดเลยเพื่ออนุญาตสมาชิกองค์กรใดก็ได้
admin-hosts-field-force-mfa = บังคับ MFA บนโฮสต์นี้
admin-hosts-force-mfa-hint = บันทึกตอนนี้ บังคับใช้เมื่อการเข้าสู่ระบบแบบโต้ตอบ (PAM) พร้อมใช้งาน
admin-hosts-action-cancel = ยกเลิก

# โฮสต์ใหม่ (hosts_new.html)
admin-hosts-new-heading = ลงทะเบียนโฮสต์ Linux
admin-hosts-new-intro-prefix = รหัสลับใช้ครั้งเดียวจะถูกแสดงครั้งเดียวในหน้าถัดไป กำหนดค่าตัวแทนโฮสต์ด้วยข้อมูลรับรอง
admin-hosts-new-intro-suffix = ที่แสดง
admin-hosts-org-belongs-hint = โฮสต์เป็นขององค์กรนี้ กำหนดตายตัวหลังลงทะเบียน
admin-hosts-new-teams-empty = ยังไม่มีทีมอยู่ โฮสต์นี้จะอนุญาตสมาชิกองค์กรใดก็ได้ การกำหนดขอบเขตโฮสต์ให้เฉพาะทีมต้องใช้ฟีเจอร์องค์กร
admin-hosts-new-teams-scope-hint = จำกัดโฮสต์นี้ไว้เฉพาะสมาชิกของทีมที่เลือก เฉพาะทีมในองค์กรที่เลือกเท่านั้นที่มีผล ไม่เลือกทีมใดเลยเพื่ออนุญาตสมาชิกองค์กรใดก็ได้

# รายการ SAML SSO (saml_list.html)
admin-saml-page-title = SAML SSO
admin-saml-subtitle = การเชื่อมต่อ SAML ระดับองค์กร หนึ่งการเชื่อมต่อต่อองค์กร เมตาดาตาและใบรับรอง IdP อยู่ใน Jackson Forseti เก็บแถวหลักและสวิตช์เปิดใช้งาน
admin-saml-action-new = การเชื่อมต่อใหม่
admin-saml-grace-notice = ใบอนุญาตอยู่ในช่วงผ่อนผัน การเชื่อมต่อ SAML จะเป็นแบบอ่านอย่างเดียวจนกว่าจะต่ออายุใบอนุญาต การเข้าสู่ระบบ SSO ยังคงทำงานได้
admin-saml-col-org = องค์กร
admin-saml-col-connection = การเชื่อมต่อ
admin-saml-col-sso-url = URL SSO
admin-saml-col-enabled = เปิดใช้งาน
admin-saml-empty-prefix = ยังไม่มีการเชื่อมต่อ SAML
admin-saml-empty-link = สร้างสักหนึ่ง
admin-saml-empty-suffix = เพื่อเปิดใช้งาน SSO สำหรับองค์กร
admin-saml-status-enabled = เปิดใช้งาน
admin-saml-status-disabled = ปิดใช้งาน
admin-saml-action-disable = ปิดใช้งาน
admin-saml-action-enable = เปิดใช้งาน
admin-saml-action-delete = ลบ
admin-saml-idp-values-heading = ค่าสำหรับผู้ดูแล IdP ของลูกค้า
admin-saml-idp-values-intro = ส่งค่าเหล่านี้ให้ผู้ที่กำหนดค่าแอป SAML ฝั่งผู้ให้บริการตัวตน ค่าเหล่านี้เหมือนกันสำหรับทุกการเชื่อมต่อ
admin-saml-idp-acs-url = ACS URL
admin-saml-idp-entity-id = SP entity ID

# การแบ่งหน้าการตรวจสอบ
admin-audit-range = กำลังแสดง { $from }–{ $to } จาก { $total } แถว
admin-audit-page = หน้า { $page }
admin-saml-entity-id-note-prefix = entity ID เป็นไปตามการตั้งค่า
admin-saml-entity-id-note-suffix = ของ Jackson เปลี่ยนที่นั่นหากคุณแทนที่ค่าเริ่มต้น

# การเชื่อมต่อ SAML SSO ใหม่ (saml_new.html)
admin-saml-new-page-title = การเชื่อมต่อ SAML ใหม่
admin-saml-new-intro = เชื่อมต่อองค์กรกับผู้ให้บริการตัวตนของตน วางเมตาดาตา XML ของ IdP หรือให้ URL เมตาดาตาที่ Jackson ดึงเอง: เลือกอย่างใดอย่างหนึ่งจากสองอย่างนี้
admin-saml-new-field-org = องค์กร
admin-saml-new-org-hint = หนึ่งการเชื่อมต่อต่อองค์กร
admin-saml-new-field-name = ชื่อการเชื่อมต่อ
admin-saml-new-name-hint = สำหรับบันทึกของคุณเท่านั้น สมาชิกจะไม่เห็นชื่อนี้
admin-saml-new-field-metadata-url = URL เมตาดาตา
admin-saml-new-metadata-url-hint = เว้นว่างไว้เมื่อวาง XML ดิบด้านล่าง
admin-saml-new-metadata-url-https-note = Jackson ดึงเฉพาะ URL เมตาดาตาแบบ HTTPS (หรือ localhost) เท่านั้น สำหรับเมตาดาตา IdP แบบ HTTP ธรรมดา ให้วาง XML ด้านล่างแทน
admin-saml-new-field-metadata-xml = เมตาดาตา XML
admin-saml-new-metadata-xml-hint = เว้นว่างไว้เมื่อใช้ URL เมตาดาตาด้านบน
admin-saml-new-action-create = สร้างการเชื่อมต่อ
admin-saml-new-action-cancel = ยกเลิก

# การแยกโค้ดในบรรทัด (ข้อ 8: มีองค์ประกอบโค้ด 2 ตัวขึ้นไปต่อสตริง)

# client_form.html - คำแนะนำประเภทการตอบกลับ (code: code, token)
admin-client-field-response-types-hint-part1 = คั่นด้วยจุลภาค เช่น
admin-client-field-response-types-hint-part2 = (auth code) หรือ
admin-client-field-response-types-hint-part3 = (client credentials)

# client_form.html - คำแนะนำ audience (code: audience=<value>)
admin-client-field-audience-hint-part1 = หนึ่งรายการต่อบรรทัด Hydra กำหนดให้ต้องลงทะเบียนค่า audience ไว้ล่วงหน้าที่นี่ (ยังไม่รองรับ RFC 8707) ไคลเอนต์ส่ง
admin-client-field-audience-hint-part2 = ในคำขอ authorization

# client_form.html - คำแนะนำ PKCE (code: hydra.yml, oauth2.pkce.enforced_for_public_clients)
admin-client-field-pkce-hint-part1 = การบังคับใช้ทั่วโลกอยู่ใน
admin-client-field-pkce-hint-part2 = (
admin-client-field-pkce-hint-part3 = ) ธงนี้ไว้แสดงเจตนาของผู้ดำเนินการ

# client_form.html + client_show.html - คำแนะนำ webhook (code: account-purged, /.well-known/webhook-jwks.json)
admin-client-field-webhook-hint-part1 = เมื่อผู้ใช้ลบตนเอง Forseti จะ POST RFC 8417 Security Event Token (RISC
admin-client-field-webhook-hint-part2 = ) มาที่นี่ เว้นว่างไว้เพื่อไม่ให้มีการแจ้ง ผู้รับตรวจสอบ JWS กับ JWKS ของ Forseti ที่
admin-client-field-webhook-hint-part3 = .

# client_show.html - คำอธิบายขอบเขตที่ไม่มีเอกสาร (code: [oauth.scope_descriptions], config.toml)
admin-client-undoc-scopes-desc-part1 = ขอบเขตเหล่านี้ลงทะเบียนไว้บนไคลเอนต์นี้แต่ไม่มีรายการภายใต้
admin-client-undoc-scopes-desc-part2 = ใน
admin-client-undoc-scopes-desc-part3 = หน้าจอให้ความยินยอมจะกลับไปใช้ชื่อขอบเขตดิบสำหรับขอบเขตเหล่านั้น

# client_show.html - ข้อผิดพลาดการค้นพบ (code: <hydra-public-url>/…)
admin-client-discovery-error-part1 = ไม่สามารถเข้าถึง discovery endpoint ของ Hydra ได้ ดังนั้นผู้ออกและ endpoint จึงถูกซ่อนไว้เพื่อหลีกเลี่ยงการแสดงค่าที่ผิด ดึงค่าเหล่านั้นด้วยตนเองจาก
admin-client-discovery-error-part2 = .

# client_show.html - บทนำส่วนแก้ไข (code: PUT /admin/clients/<id>)
admin-client-edit-intro-part1 = อัปเดตฟิลด์ไคลเอนต์ด้านล่าง การเปลี่ยนแปลงถูกส่งผ่าน
admin-client-edit-intro-part2 = ของ Hydra ฟิลด์ที่ไม่เกี่ยวข้องจะถูกเก็บรักษาไว้

# dcr_tokens_list.html - คำบรรยาย (code: POST /oauth2/register)
admin-dcr-subtitle-part1 = Bearer token ที่อนุญาต
admin-dcr-subtitle-part2 = ส่งให้ผู้เขียนไคลเอนต์ MCP หนึ่งอันเพื่อให้พวกเขาลงทะเบียนด้วยตนเองได้โดยที่คุณไม่ต้องทำเอง

# dcr_tokens_list.html - คำอธิบายโทเคนที่แสดง (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-revealed-desc-part1 = แบ่งปันสิ่งนี้กับผู้เขียนไคลเอนต์ พวกเขาส่งมันเป็น
admin-dcr-revealed-desc-part2 = เมื่อเรียก
admin-dcr-revealed-desc-part3 = เราไม่เก็บค่าดิบ เก็บเพียง SHA-256 ของมัน

# dcr_token_new.html - คำบรรยาย (code: Authorization: Bearer <token>, POST /oauth2/register)
admin-dcr-new-subtitle-part1 = โทเคนจะถูกแสดงครั้งเดียวในหน้าถัดไป ส่งให้ผู้เขียนไคลเอนต์ พวกเขาส่งมันเป็น
admin-dcr-new-subtitle-part2 = ในการเรียก
admin-dcr-new-subtitle-part3 = ครั้งเดียว

# dcr_token_new.html - คำแนะนำจำนวนครั้งใช้งานสูงสุด (code: 1)
admin-dcr-new-field-max-uses-hint-part1 = เว้นว่างไว้เพื่อไม่จำกัด การใช้ครั้งเดียว (
admin-dcr-new-field-max-uses-hint-part2 = ) เป็นค่าเริ่มต้นที่ปลอดภัยที่สุด

# client_type_picker.html - คำอธิบายแอปยอดนิยม (code: YOUR_DOMAIN, PROVIDER_NAME)
admin-client-type-popular-desc-part1 = กรอกไว้ล่วงหน้าสำหรับแอปที่รู้จัก URL ใช้ตัวยึด
admin-client-type-popular-desc-part2 = (และบางครั้ง
admin-client-type-popular-desc-part3 = ) แทนที่ด้วยค่าของแอปคุณหลังจากมาถึงฟอร์ม

# posix_account.html - ย่อหน้ากุญแจ SSH (code: AuthorizedKeysCommand, ssh, authorized_keys, forseti-unix)
admin-posix-ssh-keys-desc-part1 = กุญแจสาธารณะที่เพิ่มที่นี่จะถูกส่งไปยัง sshd ของอุปกรณ์ (
admin-posix-ssh-keys-desc-part2 = ) เพื่อให้ผู้ใช้นี้สามารถ
admin-posix-ssh-keys-desc-part3 = เข้าด้วยกุญแจของตน โดยไม่ต้องมีไฟล์
admin-posix-ssh-keys-desc-part4 = ต่อโฮสต์ ต้องใช้ hook ของ sshd ของโฮสต์ (ตั้งค่าอัตโนมัติโดยบริการ
admin-posix-ssh-keys-desc-part5 = Guix การกำหนดค่า sshd ด้วยตนเองบนดิสโทรอื่น) ไม่ใช้สำหรับการเข้าสู่ระบบคอนโซล / PAM

# posix_new.html - คำแนะนำเชลล์ (code: /bin/sh, /bin/bash)
admin-posix-new-shell-hint-part1 = ต้องมีอยู่บนอุปกรณ์ที่ให้บริการบัญชีนี้
admin-posix-new-shell-hint-part2 = เป็นค่าเริ่มต้นข้ามดิสโทรที่ปลอดภัย (Guix ไม่มี
admin-posix-new-shell-hint-part3 = ) โฮมไดเรกทอรีได้มาจากคำนำหน้าโฮม + ชื่อผู้ใช้

# saml_list.html - บล็อกที่ยังไม่ได้กำหนดค่า (code: [saml], config.toml, docs/operator-guide.md)
admin-saml-not-configured-part1 = ยังไม่ได้กำหนดค่า
admin-saml-not-configured-part2 = เพิ่มการตั้งค่าบริดจ์ Jackson ลงใน
admin-saml-not-configured-part3 = เพื่อเปิดใช้งาน SAML SSO ดู
admin-saml-not-configured-part4 = .

# ข้อความแฟลชของผู้ดูแลระบบ (แสดงเป็นแบนเนอร์หลังการเปลี่ยนเส้นทาง)
flash-identity-disabled = ปิดใช้งานตัวตนแล้ว
flash-identity-enabled = เปิดใช้งานตัวตนแล้ว
flash-session-revoked = เพิกถอนเซสชันแล้ว
flash-client-create-failed = สร้างไคลเอนต์ล้มเหลว: { $error }
flash-client-account-deletion-url-rejected = URL การลบบัญชีถูกปฏิเสธ: { $error }
flash-client-secret-stage-failed = สร้างไคลเอนต์แล้ว แต่เราไม่สามารถเตรียมรหัสลับให้แสดงแบบครั้งเดียวได้ หมุนเวียนรหัสลับเพื่อรับค่าใหม่
