<div dir="rtl">

# 🚀 Xray Config Collector 🛰️

<div align="center">

| [فارسی (Persian)](README.md) | [English](README.en.md) |
| :---: | :---: |

</div>

***

<div align="right">

## 🇮🇷 راهنمای فارسی

</div>

این مخزن کانفیگ‌های VLESS ،VMess ،Trojan ،Shadowsocks و Hysteria 2 را از کانال‌های تلگرام و صدها لیست اشتراک عمومی جمع می‌کند، همه را یکی‌یکی تست می‌کند و فقط آن‌هایی را منتشر می‌کند که واقعاً کار می‌کنند. لیست‌ها هر ۲ ساعت به‌صورت خودکار از نو ساخته می‌شوند؛ شما فقط کافی است لینک موردنظرتان را از پایین بردارید و در برنامه‌تان وارد کنید.

> **تست ما چطور است؟** باز بودن پورت هیچ‌چیز را ثابت نمی‌کند؛ برای همین هر کانفیگ قبل از انتشار باید یک تست ترافیک واقعی را رد کند. هسته‌ی Xray داخلی یک درخواست HTTP واقعی را از داخل پروکسی رد می‌کند و فقط کانفیگ‌هایی که ترافیک را عبور می‌دهند به لیست می‌رسند.

***

## 🌐 لینک‌های اشتراک (Subscription)

لینک پروتکلی را که می‌خواهید کپی کنید و در قسمت Subscription یا Import برنامه‌تان بگذارید. همین!

| پروتکل 🧩 | لینک اشتراک 🔗 | بهینه‌سازی شده برای موبایل 📱 |
| :--- | :--- | :---: |
| 🔵 **Vmess** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vmess_iran.txt` | ✅ (۲۰۰) |
| 🟢 **Vless** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vless_iran.txt` | ✅ (۲۰۰) |
| 🟡 **Trojan** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/trojan_iran.txt` | ✅ (۲۰۰) |
| 🟠 **ShadowSocks** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/ss_iran.txt` | ✅ (۲۰۰) |
| 🟣 **Hysteria 2** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/hy2_iran.txt` | ✅ (۲۰۰) |
| 🌈 **Mixed (ترکیبی)** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/mixed_iran.txt` | ❌ (نامحدود) |
| 💥 **Clash** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/clash.yaml` | فرمت Clash / Mihomo (۵۰۰ کانفیگ) |

### ⚠️ نکات مهم
* 📱 **لیست‌های تفکیک‌شده (۲۰۰):** هر لیست فقط کانفیگ‌هایی را دارد که تست ترافیک واقعی را رد کرده‌اند و برای اینکه برنامه‌های موبایل مثل **v2rayNG** و **V2Box** موقع آپدیت هنگ نکنند، به ۲۰۰ کانفیگ محدود شده است. ترتیب کانفیگ‌ها تصادفی است و عمداً رتبه‌بندی نشده‌اند؛ چون پینگی که ما اندازه می‌گیریم فاصله تا سرور تست ماست، نه تا شما، و رتبه‌بندی بر اساس آن معنایی ندارد.
* 🌈 **لیست ترکیبی (نامحدود):** همه‌ی کانفیگ‌های تست‌شده در یک فایل، بدون سقف. روی دسکتاپ عالی است، ولی روی گوشی ممکن است سنگین باشد؛ آنجا همان لیست‌های تفکیک‌شده بهترند.
* 💥 **کانفیگ Clash / Mihomo:** یک پروفایل کامل و آماده‌ی Mihomo است، نه یک لیست پروکسی ساده. **۵۰۰ کانفیگ تست‌شده** دارد، حدود ۱۰۰ تا از هر پروتکل (VLESS ،VMess ،Trojan ،Shadowsocks و Hysteria2) که در **گروه‌های کشوری** 🇺🇸 آمریکا، 🇳🇱 هلند، 🇩🇪 آلمان، 🇯🇵 ژاپن، 🇫🇷 فرانسه، 🇨🇦 کانادا، 🇷🇺 روسیه، 🇸🇬 سنگاپور، 🇪🇸 اسپانیا، 🇬🇧 بریتانیا، 🇨🇭 سوئیس، 🇭🇰 هنگ‌کنگ، 🇫🇮 فنلاند، 🇸🇪 سوئد، 🇵🇱 لهستان و 🇰🇷 کره جنوبی مرتب شده‌اند، به‌همراه‌ی یک گروه انتخاب خودکار که یک کانفیگ سریع را برایتان برمی‌دارد. مسیریابی‌اش از همان اول برای ایران تنظیم شده است: سایت‌ها، آی‌پی‌ها و رنج‌های ابری ایران مستقیم وصل می‌شوند؛ تبلیغات (فارسی و جهانی)، بدافزار، فیشینگ، ماینرهای رمزارز، ترکرهای عمومی، سایت‌های کلاهبرداری پانزی، تله‌متری شیائومی و سایت‌های دانلود رایگان فیلم‌های سانسوری بسته‌اند؛ سرویس‌های Google Play ،Google ،Microsoft ،Apple و Xiaomi مستقیم باز می‌شوند و بازی‌ها از پروکسی رد می‌شوند.

***

## 📥 کلاینت‌های پیشنهادی

### 🤖 اندروید (Android)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | ---: | :--- | :---: |
| 🟢 | **v2rayNG** | پایدارترین و محبوب‌ترین کلاینت اندروید. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/2dust/v2rayNG/releases) |
| 🔷 | **PattNG** | نسخه‌ی بهبودیافته‌ی v2rayNG برای کاربران ایرانی، با هسته‌ی Aether و گزینه‌های TLS بیشتر. | Vless, Vmess, Trojan, SS, Hy2 | [GitHub](https://github.com/patterniha/PattNG/releases) |
| 🟠 | **Throne** | جانشین NekoBox با هسته‌ی sing-box؛ پشتیبانی از پروتکل‌های بسیار متنوع و شخصی‌سازی روتینگ. | All + Hysteria 2, SSH, TUIC | [GitHub](https://github.com/throneproj/ThroneForAndroid/releases) |
| 🛡️ | **Hiddify** | محیط کاربری بسیار ساده و اتصال با یک کلیک. | All + Reality, Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| ⚡ | **V2Box** | مدیریت آسان اشتراک‌ها و رابط کاربری مدرن. | Vless, Vmess, Reality | [Google Play](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box) |
| 🌐 | **CMFA** | کلاینت رسمی Mihomo (Clash Meta) از MetaCubeX، با حالت TUN و مسیریابی قانون‌محور. | All (Mihomo) | [GitHub](https://github.com/MetaCubeX/ClashMetaForAndroid/releases) |
| 📦 | **Bettbox** | کلاینت Mihomo بازسازی‌شده از FlClash؛ رابط روان و مصرف پس‌زمینه‌ی کم، با یک اپ یکسان روی دسکتاپ و اندروید تی‌وی. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🌟 | **Karing** | کلاینت چندسکویی sing-box با رابط کاربری ساده و پشتیبانی گسترده از فرمت‌های اشتراک. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

### 🪟 ویندوز (Windows)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | ---: | :--- | :---: |
| 🔵 | **v2rayN** | قدرتمندترین ابزار ویندوز با قابلیت تنظیم هسته Xray. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/2dust/v2rayN/releases) |
| 🔶 | **PattN** | کلاینت گرافیکی چندسکویی (ویندوز، لینوکس، مک) با هسته‌های Xray و sing-box. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| 🟣 | **Throne** | جانشین Nekoray با هسته‌ی sing-box؛ بهترین گزینه برای گیمینگ و استفاده از مود TUN. | All + Hysteria 2, Reality | [GitHub](https://github.com/throneproj/Throne/releases) |
| ⚙️ | **Hiddify-Next** | مدرن، چندزبانه و سازگار با انواع فرمت‌های ساب. | All + Hysteria 2, TUIC | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 🏗️ | **Clash Verge** | مدیریت ترافیک پیشرفته بر اساس Ruleهای مختلف. | Vless, Vmess, Trojan | [GitHub](https://github.com/zzzgydi/clash-verge/releases) |
| 📦 | **Bettbox** | کلاینت Mihomo بازسازی‌شده از FlClash؛ رابط روان و مصرف پس‌زمینه‌ی کم، با یک اپ یکسان روی موبایل و دسکتاپ. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🌟 | **Karing** | کلاینت چندسکویی sing-box با رابط کاربری ساده و پشتیبانی گسترده از فرمت‌های اشتراک. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

### 🐧 لینوکس (Linux)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | ---: | :--- | :---: |
| 💻 | **Throne** | جانشین Nekoray؛ نسخه Native لینوکس با پشتیبانی کامل از TUN Mode. | All + Hysteria 2 | [GitHub](https://github.com/throneproj/Throne/releases) |
| 🔶 | **PattN** | کلاینت گرافیکی چندسکویی با هسته‌های Xray و sing-box. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| 🛠️ | **v2rayA** | رابط کاربری تحت وب که به صورت سرویس اجرا می‌شود. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/v2rayA/v2rayA/releases) |
| 🌀 | **Hiddify** | نصب آسان و رابط کاربری یکپارچه با نسخه‌های دیگر. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 📦 | **Bettbox** | کلاینت Mihomo بازسازی‌شده از FlClash؛ رابط روان و مصرف پس‌زمینه‌ی کم، با یک اپ یکسان روی موبایل و دسکتاپ. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🌟 | **Karing** | کلاینت چندسکویی sing-box با رابط کاربری ساده و پشتیبانی گسترده از فرمت‌های اشتراک. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

### 🍏 آی‌او‌اس (iPhone & iPad)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | ---: | :--- | :---: |
| 💠 | **FairVPN** | ساده، رایگان و عالی برای کاربران تازه‌وارد. | Vless, Vmess, Trojan | [App Store](https://apps.apple.com/us/app/fair-vpn/id1533873488) |
| 🚀 | **Shadowrocket** | (غیررایگان) قدرتمندترین کلاینت برای iOS. | **تمام پروتکل‌ها** | [App Store](https://apps.apple.com/us/app/shadowrocket/id932747118) |
| 🦊 | **FoXray** | رابط کاربری مدرن با پشتیبانی نیتیو از Reality و Hy2. | Vless, Vmess, Hy2, SS | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 📦 | **V2Box** | بسیار پایدار روی نسخه‌های جدید iOS. | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690) |
| 🐱 | **Clash Mi** | کلاینت رایگان و متن‌باز هسته‌ی Mihomo از تیم KaringX، با داشبورد داخلی و پشتیبانی کامل از قابلیت‌های Meta. | All (Mihomo) | [App Store](https://apps.apple.com/us/app/clash-mi/id6744321968) |
| 🌟 | **Karing** | کلاینت چندسکویی sing-box با رابط کاربری ساده و پشتیبانی گسترده از فرمت‌های اشتراک. | All (sing-box) | [App Store](https://apps.apple.com/us/app/karing/id6472431552) |

### 🍎 مک (macOS)
|  | نام نرم‌افزار | ویژگی‌های کلیدی | پروتکل‌های پشتیبانی شده | لینک دانلود |
| :---: | :--- | ---: | :--- | :---: |
| 🦊 | **FoXray** | بهینه شده برای پردازنده‌های Apple Silicon (M1/M2/M3). | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 🔶 | **PattN** | کلاینت گرافیکی چندسکویی با هسته‌های Xray و sing-box. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| ⚙️ | **Hiddify** | اتصال تک‌کلیک و طراحی شیک هماهنگ با مک. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 💎 | **V2Free** | کلاینت بومی مک با مصرف منابع بسیار پایین. | Vless, Vmess, Trojan | [GitHub](https://github.com/v2free/v2free/releases) |
| 📦 | **Bettbox** | کلاینت Mihomo بازسازی‌شده از FlClash؛ رابط روان و مصرف پس‌زمینه‌ی کم، با یک اپ یکسان روی موبایل و دسکتاپ. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🐱 | **Clash Mi** | کلاینت رایگان و متن‌باز هسته‌ی Mihomo از تیم KaringX، با داشبورد داخلی و پشتیبانی کامل از قابلیت‌های Meta. | All (Mihomo) | [GitHub](https://github.com/KaringX/clashmi/releases) |
| 🌟 | **Karing** | کلاینت چندسکویی sing-box با رابط کاربری ساده و پشتیبانی گسترده از فرمت‌های اشتراک. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

***

### 🛠️ ویژگی‌های فنی و قابلیت‌ها

[**گزارش آخرین وضعیت و منابع**](https://github.com/justVisiting992/xray-Config-Collector/blob/main/report.md)

زیر پوست این پروژه ترکیبی از Python و Go است. این‌که دقیقاً چه کار می‌کند و چرا:
1. **کانفیگ‌ها از کجا می‌آیند:**
   - یک جمع‌کننده‌ی پایتونی با **Telegram API** پیام‌ها را مستقیم از بزرگ‌ترین کانال‌های کانفیگ می‌خواند.
   - یک اسکرپر Go هم **بیش از ۱۰۰ کانال تلگرامی** دیگر را از وب زیر نظر دارد.
   - **بیش از ۲۰۰ لیست اشتراک عمومی** از فایل `subscriptions.txt` هم در هر اجرا به‌صورت موازی خوانده و با بقیه در یک مجموعه ادغام می‌شوند.
   - هیچ پیامی هم از قلم نمی‌افتد: نقطه‌ی بازبینی هر کانال فقط وقتی جلو می‌رود که پیام‌هایش کامل پردازش شده باشند و اجرای بعدی دقیقاً از همان‌جایی ادامه می‌دهد که قبلی ایستاده بود.
2. **لینک‌های VMess درست رمزگشایی می‌شوند:**
   - Base64 کانفیگ VMess (از جمله نسخه‌ی URL-safe) کامل باز می‌شود، JSON داخلش خوانده می‌شود و آدرس و پورت قبل از تست بررسی می‌شوند؛ حدس و گمان در کار نیست.
3. **تست ترافیک واقعی، نه فقط پینگ:**
   - هر کانفیگی که از غربال اولیه رد شود، دوباره با یک **هسته‌ی Xray داخلی** تست می‌شود که یک درخواست HTTP واقعی را *از داخل خود پروکسی* رد می‌کند. ترافیک رد نشود، کانفیگ منتشر نمی‌شود.
   - **Hysteria 2** هم با یک نشست واقعی Hysteria (با مبهم‌سازی Salamander) تست می‌شود، نه با یک DNS Lookup ساده.
   - هر تست ناموفق **یک بار دیگر** هم تلاش می‌شود تا یک اختلال لحظه‌ای شبکه، یک کانفیگ سالم را از لیست نیندازد.
4. **تست‌ها موازی انجام می‌شوند:**
   - ده‌ها هزار کانفیگ هم‌زمان با Goroutineهای Go تست می‌شوند، برای همین کل کار سریع تمام می‌شود.
5. **پرچم، کشور خروجی واقعی است:**
   - کشور هر کانفیگ از روی **آی‌پی خروجی واقعی** پروکسی (دیتابیس MaxMind) مشخص می‌شود، نه آدرسی که به آن وصل می‌شوید؛ یعنی پرچم می‌گوید ترافیک‌تان واقعاً از کجا بیرون می‌آید.
6. **اسم‌هایی که برنامه‌ها را اذیت نمی‌کنند:**
   - فرمت نام کانفیگ‌ها خودکار اصلاح می‌شود تا کلاینت‌هایی مثل Hiddify Next روی آن‌ها خطا ندهند.
7. **محدودیت تلگرام کار را متوقف نمی‌کند:**
   - اگر تلگرام جمع‌کننده‌ی پایتون را Rate Limit کند، خودش کنار می‌کشد و بقیه‌ی کار بدون توقف ادامه پیدا می‌کند.
8. **کانفیگ‌های قدیمی دور ریخته نمی‌شوند:**
   - کانفیگ سالمی که از قبل هست در هر اجرا دوباره تست می‌شود و تا وقتی زنده است در لیست می‌ماند.
9. **ترتیب تصادفی است، عمداً:**
   - تأخیری که ما در تست اندازه می‌گیریم فاصله‌ی سرور تست (رانر گیت‌هاب) تا سرور است و هیچ ربطی به سرعت آن سرور از خانه یا گوشی شما ندارد. مرتب‌کردن بر اساس آن فقط سرورهای نزدیک به رانر را جلو می‌انداخت. پس لیست‌ها به‌صورت تصادفی منتشر می‌شوند و هر کانفیگ سالم شانس برابری برای قرار گرفتن در لیست‌های محدود دارد؛ ترتیب در هر اجرا از نو تصادفی می‌شود.
10. **خروجی Clash / Mihomo:**
    - در هر اجرا فایل `clash.yaml` هم از همان کانفیگ‌های تست‌شده ساخته می‌شود؛ یک پروفایل آماده‌ی Mihomo برای وارد کردن در کلاینت‌های Clash.
11. **تکراری‌ها حذف می‌شوند، ولی درست:**
    - تکراری‌زدایی بر اساس هویت کامل کانفیگ است: سرور، اطلاعات ورود و تنظیمات انتقال. نسخه‌های مختلف یک سرور با TLS/SNI/Path متفاوت، کانفیگ‌های متفاوتی‌اند و همه می‌مانند؛ فقط کپیِ عیناً تکراری حذف می‌شود.
12. **یک تور ایمنی:**
    - اگر یک اجرا نتیجه‌ی بی‌معنی بدهد (مثلاً صفر کانفیگ سالم)، لیست‌های قبلی سر جایشان می‌مانند و فایل خالی منتشر نمی‌شود.
13. **یک مجموعه، یک بار تست:**
    - لیست ترکیبی یک بار به‌صورت کامل تست می‌شود و لیست هر پروتکل از همان مجموعه‌ی تست‌شده برداشته می‌شود: ۲۰۰ کانفیگ تصادفی از کانفیگ‌های سالم همان پروتکل. یعنی هیچ کانفیگی بدون رد کردن تست واقعی به هیچ لیستی نمی‌رسد.
14. **برچسب‌هایی که حرف می‌زنند:**
    - اسم هر کانفیگ کشور خروجی و ویژگی‌های انتقال و رمزنگاری‌اش را نشان می‌دهد (مثلاً `WS • TLS`، `TCP • Reality • Vision` یا روش رمزنگاری Shadowsocks). اگر چند کانفیگ اسم کاملاً یکسان بگیرند شماره می‌خورند (`01`، `02`، …) تا هر کدام یکتا بمانند — در `clash.yaml` هم همین‌طور.
    - گزارش وضعیت هر منبع را با یک اسم کوتاه و لینک‌دار می‌آورد و اعدادش همان مجموع‌های واقعیِ تست‌شده‌اند؛ برای همین جمع اعداد هر پروتکل دقیقاً با عدد کل جور درمی‌آید.

</div>