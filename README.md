# Cyber-Security

# Information
- รหัสนักศึกษา: 084-5
- ความคาดหวังของรายวิชา: อยากเรียนรู้เกี่ยวกับความปลอดภัยทางไซเบอร์ การป้องกันการโจมตี และสามารถนำความรู้ไปประยุกต์ใช้ในการทำงานจริงได้ และได้เรียนรู้อีกหนึ่งสายงานเพิ่ม

# How to run
1. Configure `.env` (คัดลอกจาก `.env.example` ถ้ามี) แล้วรัน:
   ```
   docker compose up -d
   ```
2. บริการ:
   - Strapi (HTTP): `http://localhost:9092`
   - Strapi (TLS): `https://localhost:9443`
   - Admin panel ฐานข้อมูล (pgadmin): `http://localhost:8082`
3. "กล่องจดหมาย" ใช้ console email provider -> อีเมลทั้งหมด (OTP, reset link, confirm link) ปรากฏใน `docker logs 69-s2-app`
   ตัวอย่างการค้นหา:
   ```
   docker logs 69-s2-app | findstr "verification code is:"   # admin MFA OTP
   docker logs 69-s2-app | findstr "?code="                  # reset password token
   docker logs 69-s2-app | findstr "?confirmation="          # email confirmation token
   ```

# Security notes (IAAA)
- **TLS (dev):** ใช้ self-signed certificate ที่สร้างตอน container เริ่มทำงาน
  สำหรับ **production ต้องเปลี่ยนเป็น certificate จาก CA ที่น่าเชื่อถือ** เช่น Let's Encrypt
  (แก้ที่ nginx/default.conf และวอลุ่ม mount ของ nginx)
- MFA สำหรับ admin: OTP 6 หลัก อ่านได้จาก docker logs (console email)
- Token limit: JWT 15 นาที (มี refresh token 7 วัน, rotates), reset token 30 นาที, MFA code 5 นาที
- ผู้ใช้ที่เชื่อมต่อ DB ผ่าน pgadmin ใช้ role `dbadmin` (รหัสใน .env `DB_ADMIN_PASSWORD`)
  หรือ `auditor` — ไม่สามารถอ่านคอลัมน์ `password` ได้ (เฉพาะ role `strapi_app` ของ app เท่านั้น)
- role `thitiwat` (bootstrap) ถูกตั้งเป็น NOLOGIN: ห้าม login ผ่าน network/pgadmin โดยเด็ดขาด
- การเข้าถึง DB ผ่าน local socket ใช้ `docker exec -i 69-s2-db psql -U dbadmin -d thitiwat`

<!-- update -->