<div dir="rtl">

# 🚀 Xray Config Collector 🛰️

<div align="center">

| [فارسی (Persian)](README.md) | [English](README.en.md) |
| :---: | :---: |

</div>

***

## 🇮🇷 راهنمای فارسی

این پروژه یک موتور هوشمند و پرسرعت برای جمع‌آوری، تست و فیلتر کردن خودکار کانفیگ‌های VLESS، VMESS، Trojan، Shadowsocks و Hysteria 2 از منابع معتبر تلگرامی است.

> **تست کیفیت:** تمام کانفیگ‌ها قبل از انتشار توسط یک سیستم تست‌کننده موازی (TCP/UDP) بررسی می‌شوند تا فقط موارد سالم و فعال در لیست قرار بگیرند.

***

## 🌐 لینک‌های اشتراک (Subscription)

برای استفاده، کافی است لینک مورد نظر را کپی کرده و در قسمت Subscription یا Import نرم‌افزار خود وارد کنید.

| پروتکل 🧩 | لینک اشتراک 🔗 | بهینه‌سازی شده برای موبایل 📱 |
| :--- | :--- | :---: |
| 🔵 **Vmess** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vmess_iran.txt` | ✅ (۲۰۰ برتر) |
| 🟢 **Vless** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vless_iran.txt` | ✅ (۲۰۰ برتر) |
| 🟡 **Trojan** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/trojan_iran.txt` | ✅ (۲۰۰ برتر) |
| 🟠 **ShadowSocks** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/ss_iran.txt` | ✅ (۲۰۰ برتر) |
| 🟣 **Hysteria 2** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/hy2_iran.txt` | ✅ (۲۰۰ برتر) |
| 🌈 **Mixed (ترکیبی)** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/mixed_iran.txt` | ❌ (نامحدود) |

### ⚠️ نکات مهم
* 📱 **لیست‌های تفکیک شده (۲۰۰ برتر):** این لیست‌ها به **۲۰۰ کانفیگ با بهترین پینگ** محدود شده‌اند. این کار مخصوصاً برای گوشی‌های موبایل انجام شده تا نرم‌افزارهایی مثل **v2rayNG** یا **V2Box** هنگام آپدیت کردن دچار لگ یا کرش نشوند.
* 🌈 **لیست ترکیبی (نامحدود):** این فایل شامل **تمامی** کانفیگ‌های سالم پیدا شده (بیش از ۱۰۰۰ مورد) است. **توصیه می‌شود این لینک را فقط در کلاینت‌های دسکتاپ (ویندوز/لینوکس) استفاده کنید**؛ چرا که سخت‌افزار کامپیوتر قدرت پردازش این حجم از داده را بدون افت سرعت دارد.

***

## 📥 کلاینت‌های پیشنهادی

### 🤖 اندروید (Android)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | :--- | :--- | :---: |
| 🟢 | **v2rayNG** | پایدارترین و محبوب‌ترین کلاینت اندروید. | Vless, Vmess, Trojan, SS | [Google Play](https://play.google.com/store/apps/details?id=com.v2ray.ang) |
| 🟠 | **NekoBox** | پشتیبانی از پروتکل‌های بسیار متنوع و شخصی‌سازی روتینگ. | All + Hysteria 2, SSH, TUIC | [GitHub](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) |
| 🛡️ | **Hiddify** | محیط کاربری بسیار ساده و اتصال با یک کلیک. | All + Reality, Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| ⚡ | **V2Box** | مدیریت آسان اشتراک‌ها و رابط کاربری مدرن. | Vless, Vmess, Reality | [Google Play](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box) |

### 🪟 ویندوز (Windows)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | :--- | :--- | :---: |
| 🔵 | **v2rayN** | قدرتمندترین ابزار ویندوز با قابلیت تنظیم هسته Xray. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/2dust/v2rayN/releases) |
| 🟣 | **Nekoray** | بهترین گزینه برای گیمینگ و استفاده از مود TUN. | All + Hysteria 2, Reality | [GitHub](https://github.com/MatsuriDayo/nekoray/releases) |
| ⚙️ | **Hiddify-Next** | مدرن، چندزبانه و سازگار با انواع فرمت‌های ساب. | All + Hysteria 2, TUIC | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 🏗️ | **Clash Verge** | مدیریت ترافیک پیشرفته بر اساس Ruleهای مختلف. | Vless, Vmess, Trojan | [GitHub](https://github.com/zzzgydi/clash-verge/releases) |

### 🐧 لینوکس (Linux)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | :--- | :--- | :---: |
| 💻 | **Nekoray** | نسخه Native لینوکس با پشتیبانی کامل از TUN Mode. | All + Hysteria 2 | [GitHub](https://github.com/MatsuriDayo/nekoray/releases) |
| 🛠️ | **v2rayA** | رابط کاربری تحت وب که به صورت سرویس اجرا می‌شود. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/v2rayA/v2rayA/releases) |
| 🌀 | **Hiddify** | نصب آسان و رابط کاربری یکپارچه با نسخه‌های دیگر. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |

### 🍏 آی‌او‌اس (iPhone & iPad)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | :--- | :--- | :---: |
| 💠 | **FairVPN** | ساده، رایگان و عالی برای کاربران تازه‌وارد. | Vless, Vmess, Trojan | [App Store](https://apps.apple.com/us/app/fair-vpn/id1533873488) |
| 🚀 | **Shadowrocket** | (غیررایگان) قدرتمندترین کلاینت برای iOS. | **تمام پروتکل‌ها** | [App Store](https://apps.apple.com/us/app/shadowrocket/id932747118) |
| 🦊 | **FoXray** | رابط کاربری مدرن با پشتیبانی نیتیو از Reality و Hy2. | Vless, Vmess, Hy2, SS | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 📦 | **V2Box** | بسیار پایدار روی نسخه‌های جدید iOS. | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690) |

### 🍎 مک (macOS)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | :--- | :--- | :---: |
| 🦊 | **FoXray** | بهینه شده برای پردازنده‌های Apple Silicon (M1/M2/M3). | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| ⚙️ | **Hiddify** | اتصال تک‌کلیک و طراحی شیک هماهنگ با مک. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 💎 | **V2Free** | کلاینت بومی مک با مصرف منابع بسیار پایین. | Vless, Vmess, Trojan | [GitHub](https://github.com/v2free/v2free/releases) |

***

### 🛠️ ویژگی‌های فنی و قابلیت‌ها

[**گزارش آخرین وضعیت و منابع**](https://github.com/justVisiting992/xray-Config-Collector/blob/main/report.md)

این پروژه با استفاده از ترکیب Python و Go بازنویسی شده است تا بالاترین دقت و سرعت را در جمع‌آوری منابع داشته باشد. ویژگی‌های کلیدی عبارتند از:
1. **جمع‌آوری دوگانه (API + Scraper):**
   - استفاده از **Telegram API** (پایتون) برای استخراج مستقیم پیام‌ها از بزرگترین مرجع‌های کانفیگ با سرعت بالا.
   - استفاده از **Web Scraper** (گو) به عنوان سیستم پشتیبان برای پایش بیش از ۱۰۰ کانال تلگرامی دیگر.
2. **رمزگشایی هوشمند VMess:**
   - برخلاف اسکریپت‌های ساده، این کد پیام‌های Base64 پروتکل VMess را کاملاً باز کرده، JSON داخلی آن را آنالیز می‌کند و پس از تایید آدرس و پورت، آن را تست می‌کند.
3. **پشتیبانی از Hysteria 2 (UDP):**
   - قابلیت شناسایی و تست پروتکل Hy2. از آنجایی که این پروتکل بر بستر UDP است، سیستم از متد ترکیبی TCP-Dial و DNS-Lookup برای اطمینان از زنده بودن سرور استفاده می‌کند.
4. **تست سلامت چندرشته‌ای (Multi-threaded):**
   - تست همزمان صدها کانفیگ با استفاده از Goroutines در زبان Go که باعث می‌شود کل فرآیند تست در کمتر از چند ثانیه انجام شود.
5. **برچسب‌گذاری جغرافیایی (Geo-IP tagging):**
   - شناسایی خودکار کشور سرور با استفاده از دیتابیس MaxMind و اضافه کردن نام کشور و پرچم مربوطه به نام کانفیگ.
6. **سازگاری کامل با Hiddify و نپستر:**
   - اصلاح خودکار فرمت نام‌گذاری (Fragment) برای جلوگیری از بروز خطا در کلاینت‌های محبوب مانند Hiddify Next.
7. **پایداری در برابر محدودیت‌های تلگرام (Flood Error Handling):**
   - سیستم هوشمند Python Collector در صورت برخورد با محدودیت نرخ تلگرام (Rate Limit)، به جای توقف کل پروژه، به صورت خودکار از مدار خارج شده و اجازه می‌دهد بقیه بخش‌های اسکریپت کار خود را ادامه دهند.
8. **بایگانی خودکار (History Preservation):**
   - کانفیگ‌های سالم قدیمی حذف نمی‌شوند، بلکه با هر آپدیت دوباره تست شده و در صورت زنده بودن، در لیست باقی می‌مانند.

</div>