<div dir="rtl">

# دليل فريق تقنية المعلومات: اختراق سيرفرات *.pua.edu.eg بأسلوب SEO Cloaking

**من:** إدارة التسويق الرقمي، جامعة فاروس بالإسكندرية
**الأولوية:** عاجلة. كل إعلانات Google Ads للجامعة متوقفة حاليًا.

## 1. ما الذي وجدناه

- رفضت Google Ads كل إعلانات `pua.edu.eg` بسبب **"Compromised Site"** و**"Malicious software"**، ورُفض الاستئناف.
- أدوات الفحص الخارجية (Sucuri وVirusTotal) لم تجد شيئًا. السبب أن البرمجية الخبيثة تعرض المحتوى المزعج **لزاحف Google (Googlebot) فقط**، وهو أسلوب يسمى **Cloaking**. الزائر العادي يرى الصفحة سليمة.
- **الدليل:** في نتائج Google بتايلاند يوم 2 أكتوبر 2026 ظهرت الصفحة
  `https://academic.pua.edu.eg/Account/Register` في المركز الأول بعنوان قمار (سلوتس) باللغة التايلاندية، مع أن عنوانها الحقيقي هو `Register - Instructor Work Load`.
- **Search Console (أغسطس إلى أكتوبر 2026):** الاستعلامات المزعجة جلبت قرابة **14,000 نقرة** و**203,000 ظهور**، منها قرابة **7,000 نقرة** من استعلامات قمار تايلاندية (تايلاند هي الدولة الأولى في الزيارات)، وقرابة **4,900 نقرة** من استعلامات عربية لمحتوى للبالغين.
- **المواقع المتأثرة:** `academic.pua.edu.eg` و`portal.pua.edu.eg` (تطبيقات ASP.NET على IIS، والأرجح أنهما على نفس السيرفر)، بالإضافة إلى الصفحة الرئيسية `www.pua.edu.eg` (WordPress، ولم يتأكد السبب فيها بعد).
- **النمط مطابق لعائلات برمجيات IIS الخبيثة** مثل **BADIIS** و**GhostRedirector / Gamshen**: موديول IIS أصلي (Native DLL) خبيث يعدّل الاستجابة عندما يكون الزائر زاحف محرك بحث. الاختراق يبدأ غالبًا بـ **SQL Injection** ثم `xp_cmdshell`، ويتبعه زرع Web Shells وإنشاء حسابات Admin محلية ومهام مجدولة وأدوات تحكم عن بعد.

> ملحوظة: التحقق بتغيير الـ User-Agent فقط لا يكفي. كثير من هذه البرمجيات تتحقق من **عنوان IP** الخاص بـ Google، فقد تبدو الصفحة سليمة من أي جهاز آخر.

## 2. قبل أي شيء: خذ نسخة كاملة

قبل التشغيل أو التنظيف، خذ **Snapshot أو Backup كامل** لكل سيرفر (VM snapshot أو image للقرص) واحتفظ به بعيدًا عن الشبكة. هذه النسخة دليل جنائي، وستلزمنا لو احتجنا تحليلًا أعمق لاحقًا. **لا تحذف أي ملف قبل أخذ النسخة.**

## 3. تشغيل سكربت الفحص `iis_triage.ps1`

السكربت **للقراءة فقط**: لا يعدّل ولا يحذف ولا يوقف ولا يزيل أي شيء. يكتب نتائجه فقط في `C:\PUA-Triage\<hostname>-<timestamp>\` وينشئ ملف ZIP منها.

شغّله على **كل سيرفر** يستضيف academic أو portal أو www:

1. انسخ `iis_triage.ps1` إلى السيرفر (مثلًا إلى `C:\Tools\`).
2. افتح **Windows PowerShell** (نسخة 64-bit) بخيار **Run as Administrator**.
3. نفّذ:

</div>

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd C:\Tools
.\iis_triage.ps1
```

<div dir="rtl">

4. قد يستغرق التشغيل من 5 إلى 30 دقيقة حسب حجم سجلات IIS.
5. في النهاية أرسل ملف الـ ZIP الناتج، مثل `C:\PUA-Triage\SERVERNAME-20261102-101500.zip`، إلى فريق التحقيق. أهم ملف فيه هو `summary.txt`.

## 4. معنى كل RED FLAG في `summary.txt`

| RED FLAG | المعنى | ماذا تفعل |
|---|---|---|
| `IIS MODULE NOT MICROSOFT-SIGNED` | موديول مسجّل في `globalModules` داخل `applicationHost.config` وغير موقّع من Microsoft. **هذا هو المشتبه الأول** في حالة BADIIS. | سجّل الاسم والمسار والـ SHA-256، وارفع الهاش إلى VirusTotal (الهاش فقط وليس الملف). |
| `UNSIGNED DLL IN INETSRV` | ملف DLL غير موقّع داخل `System32\inetsrv` أو `SysWOW64\inetsrv`. هذه المجلدات لا يُفترض أن تحتوي ملفات غير موقّعة. | نفس الإجراء السابق، وقارن تاريخ إنشاء الملف بتاريخ بداية المشكلة. |
| `RECENT UNSIGNED DLL IN .NET GAC` | مكتبة .NET غير موقّعة أُضيفت للـ GAC خلال آخر سنة. قد تكون موديول خبيث مُدارًا (Managed). | تأكد إن كانت من برنامج معروف (مثل Ellucian أو Crystal Reports). |
| `WEB.CONFIG HANDLER OUTSIDE WINDOWS` | ملف `web.config` يوجّه الطلبات لبرنامج خارج `C:\Windows`. | راجع الـ handler وتأكد من مصدره. |
| `RECENTLY MODIFIED SCRIPT FILE` | ملف `.aspx` أو `.ashx` أو `.asmx` أو `.asp` أو `.php` أو `.cshtml` تغيّر خلال 365 يومًا. | قارنه بآخر نشر رسمي للتطبيق. أي ملف لا يعرفه المطورون يُعامل كـ Web Shell. |
| `POSSIBLE WEB SHELL PATTERN` | ملف سكربت حديث فيه أكواد مثل `cmd.exe` أو `Process.Start` أو `eval(Request` أو `FromBase64String`. | **خطر عالٍ.** احتفظ بنسخة منه كدليل ولا تفتحه في المتصفح. |
| `PHP FILE ON ASP.NET SITE` | ملف PHP داخل موقع ASP.NET، وهذا غير طبيعي. | غالبًا Web Shell. |
| `MEMBER OF ADMINISTRATORS / REMOTE DESKTOP USERS - CONFIRM EXPECTED` | كل عضو في المجموعتين باستثناء Administrator المدمج وDomain Admins. | تأكد من كل اسم. أي حساب غير معروف يعني أن المهاجم أنشأ حسابًا لنفسه. |
| `BUILT-IN ACCOUNT ENABLED` | حساب Guest أو DefaultAccount مفعّل. | يجب أن يكون معطّلًا. |
| `NON-MICROSOFT SCHEDULED TASK` / `SUSPICIOUS TASK UNDER \Microsoft\` | مهمة مجدولة خارج مجلد Microsoft، أو داخله لكنها تشغّل ملفًا من `Users` أو `Temp` أو `ProgramData`. | تأكد من كل مهمة. المهاجمون يستخدمونها لإعادة زرع البرمجية بعد التنظيف. |
| `UNSIGNED SERVICE BINARY OUTSIDE WINDOWS` / `SERVICE IN USER/TEMP FOLDER` | خدمة Windows ملفها غير موقّع أو في مكان غير معتاد. | مشتبه به كأداة تحكم عن بعد. |
| `REMOTE-ACCESS / TUNNEL TOOL LISTENING` | برامج مثل AnyDesk أو ngrok أو frp أو chisel تستمع على منفذ. | لو لم يركّبها فريق IT فهي باب خلفي. |
| `GOOGLEBOT GETS DIFFERENT-SIZE RESPONSES (CLOAKING EVIDENCE)` | من سجلات IIS: حجم الاستجابة لـ Googlebot يختلف بأكثر من 30% عن حجمها للمتصفحات على نفس الصفحة. | **دليل مباشر على الـ Cloaking من السيرفر نفسه.** |
| `SQL XP_CMDSHELL ENABLED` | الخاصية `xp_cmdshell` مفعّلة في SQL Server، وهي الطريقة الشائعة لتنفيذ أوامر النظام بعد SQL Injection. | تُعطَّل في مرحلة الإصلاح (انظر بالأسفل). |

قسم **ITEMS TO REVIEW** يحتوي عناصر تحتاج مراجعة بشرية وليست بالضرورة خبيثة، مثل أحداث إنشاء الحسابات (4720)، والإضافة للمجموعات (4732)، وإنشاء المهام (4698)، وتثبيت الخدمات (7045)، وإعادة التوجيه 3xx للزوار القادمين من Google، وحقول السجلات الناقصة.

## 5. خطوات الإصلاح

### أ) الإزالة الفورية (حل مؤقت)

بعد أخذ النسخة الاحتياطية، ولكل موديول خبيث مؤكد:

</div>

```cmd
%windir%\system32\inetsrv\appcmd.exe list modules
%windir%\system32\inetsrv\appcmd.exe uninstall module <ModuleName>
```

<div dir="rtl">

- احذف أي إشارة للموديول من ملفات `web.config` (في أقسام `<modules>` و`<handlers>`).
- احذف ملف الـ DLL بعد نسخه كدليل.
- احذف الـ Web Shells والحسابات والمهام المجدولة والخدمات الخبيثة التي حددها التقرير.
- أعد تشغيل IIS:

</div>

```cmd
iisreset
```

<div dir="rtl">

> تحذير: هذا الحل وحده **لا يكفي**. المهاجم الذي وصل إلى صلاحيات Admin غالبًا ترك أبوابًا خلفية أخرى.

### ب) الحل الموصى به

**أعد بناء السيرفر من Image نظيف**، ثم أعد نشر تطبيقي academic وportal **من الكود المصدري** أو من حزمة النشر الأصلية، وليس من نسخة السيرفر المخترق. انقل البيانات فقط بعد فحصها.

### ج) سد الثغرات

1. ثبّت كل التحديثات: **Windows وIIS و.NET وSQL Server**.
2. عطّل `xp_cmdshell`:

</div>

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```

<div dir="rtl">

3. **أصلح ثغرات SQL Injection** في التطبيقات باستخدام Parameterized Queries، واجعل حساب قاعدة البيانات الخاص بالتطبيق بأقل صلاحيات ممكنة، وليس `sa` أو `sysadmin`.
4. **أغلق RDP (المنفذ 3389) من الإنترنت.** الدخول يكون عبر VPN فقط.
5. **غيّر كل كلمات المرور:** حسابات Windows المحلية وحسابات الدومين التي دخلت السيرفر وحسابات SQL وحسابات الـ App Pool وconnection strings، بالإضافة إلى حسابات WordPress ومفاتيح `wp-config.php` الخاصة بـ www.
6. افحص موقع **www (WordPress)** بنفس الجدية: الإضافات (plugins)، والقوالب، والملف `functions.php`، والمستخدمين الإداريين، وملف `.htaccess` أو `web.config`.
7. فعّل حقل `sc-bytes` في إعدادات IIS Logging لتسهيل الكشف مستقبلًا.

## 6. بعد التنظيف: دور فريق التسويق

1. في **Search Console** نستخدم **URL Inspection** ثم **Test Live URL** ثم **View crawled page** على:
   `https://academic.pua.edu.eg/Account/Register` وصفحات portal والصفحة الرئيسية، ونتأكد أن العنوان والمحتوى اللذين يراهما Google سليمان.
2. نطلب **إعادة الفهرسة (Request Indexing)** للصفحات المتأثرة، ونراجع تقرير **Security Issues**.
3. نقدّم **استئنافًا في Google Ads** ونذكر فيه ما تم: إزالة الموديول، وإعادة البناء، والتحديثات، وتغيير كلمات المرور.
4. نتابع أسبوعيًا بالسكربت `gsc_monitor.py`، ويجب أن تنخفض نقرات الاستعلامات المزعجة إلى صفر.

**أرجو إبلاغنا بموعد التشغيل وإرسال ملفات الـ ZIP فور انتهائها.** شكرًا لكم.

</div>
