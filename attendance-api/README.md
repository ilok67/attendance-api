# سامانه حضور و غیاب چندمدرسه‌ای — API

## راه‌اندازی سریع (لوکال)

```bash
# 1. Postgres را بالا بیاور
docker compose up -d db

# 2. وابستگی‌ها
npm install

# 3. اسکیما را اعمال کن
npx prisma db push

# 4. سوپرادمین بساز
npm run seed

# 5. سرور را اجرا کن
npm run dev
```

API روی `http://localhost:3000` در دسترس است.

### حساب پیش‌فرض سوپرادمین
- schoolCode: `ADMIN`
- username: `superadmin`
- password: `SuperAdmin@1403`

**حتماً بعد از اولین ورود رمز را عوض کنید.**

## ساختار مسیرها

| مسیر | نقش | توضیح |
|------|-----|-------|
| GET /api/health | عمومی | سلامت |
| GET /api/salt | عمومی | salt برای ورود |
| POST /api/login | عمومی | ورود |
| GET /api/data | JWT | داده مدرسه (نقش‌محور) |
| POST /api/sync | credentials | سینک آفلاین |
| GET/POST /api/admin/schools | superadmin | مدیریت مدارس |
| PUT /api/admin/schools/:id | superadmin | فعال/غیرفعال |
| POST/PUT/DELETE /api/classes | deputy | مدیریت کلاس |
| POST/PUT/DELETE /api/students | deputy | مدیریت دانش‌آموز |
| POST /api/students/import | deputy | ایمپورت گروهی |
| POST/PUT /api/users | deputy | مدیریت معلم/معاون |
| PUT /api/school/settings | deputy | تنظیمات مدرسه |
| GET /api/audit | deputy | لاگ حسابرسی |

## احراز هویت

کلاینت باید رمز را با PBKDF2-SHA256 (100000 دور، 32 بایت) هش کند و فقط hash + salt را بفرستد.
سرور scrypt روی آن اعمال می‌کند.

## Docker کامل

```bash
docker compose up --build
```

## نکات امنیتی

- رمز متن‌ساده هرگز ذخیره یا ارسال نمی‌شود.
- `school_id` همیشه از JWT گرفته می‌شود، نه از ورودی کلاینت.
- معلم فقط کلاس‌های خودش را می‌بیند و ثبت می‌کند.
