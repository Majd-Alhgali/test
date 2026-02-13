# دليل اختبار أمان الشبكة / Network Security Testing Guide

## 🔒 Overview / نظرة عامة

هذا الدليل يشرح كيفية استخدام أداة تحليل أمان الشبكة لاكتشاف نقاط الضعف المحتملة في شبكات WiFi.

This guide explains how to use the network security analysis tool to discover potential vulnerabilities in WiFi networks.

---

## 📋 Requirements / المتطلبات

### البرامج المطلوبة / Required Software

- Python 3.x
- البيانات الناتجة من Airodump-ng أو Kismet / Data from Airodump-ng or Kismet

### الملفات المطلوبة / Required Files

- ملف CSV من Airodump-ng يحتوي على بيانات الشبكة / CSV file from Airodump-ng containing network data

---

## 🚀 Usage / الاستخدام

### الاستخدام الأساسي / Basic Usage

```bash
python3 network_security_analyzer.py <csv_file>
```

### مثال / Example

```bash
python3 network_security_analyzer.py ./-01.csv
```

---

## 📊 What the Tool Analyzes / ما تقوم الأداة بتحليله

### 1. تحليل التشفير / Encryption Analysis

الأداة تفحص نوع التشفير المستخدم وتكتشف:

The tool examines the encryption type used and detects:

- ❌ **WEP** - تشفير قديم جداً وسهل الاختراق / Very old and easily crackable (CRITICAL)
- ⚠️ **WPA** - تشفير قديم وعرضة للهجمات / Deprecated and vulnerable (HIGH)
- ⚠️ **Open Network** - شبكة مفتوحة بدون تشفير / No encryption (CRITICAL)
- ⚠️ **WPA2 with TKIP** - ضعيف مقارنة بـ AES / Weaker than AES (MEDIUM)
- ✅ **WPA2 with CCMP/AES** - تشفير جيد / Good encryption
- ✅ **WPA3** - أحدث وأقوى معيار / Latest and strongest standard

### 2. تحليل المصادقة / Authentication Analysis

- **PSK (Pre-Shared Key)** - عرضة لهجمات القاموس إذا كانت كلمة المرور ضعيفة
  - Vulnerable to dictionary attacks if password is weak

### 3. تحليل قوة الإشارة / Signal Strength Analysis

الأداة تفحص قوة الإشارة للكشف عن:

The tool examines signal strength to detect:

- إشارات قوية جداً قد تشير إلى نقطة وصول مزيفة / Very strong signals that may indicate evil twin
- إشارات ضعيفة من الأجهزة المتصلة / Weak signals from connected devices

### 4. تحليل الأجهزة المتصلة / Connected Devices Analysis

- عدد الأجهزة المتصلة / Number of connected devices
- الأجهزة ذات الإشارة الضعيفة / Devices with weak signals
- الأجهزة غير المعروفة / Unknown devices

### 5. فحص WPS / WPS Vulnerability Check

- التحقق من حالة WPS / Checking WPS status
- تحذير إذا كان WPS مفعلاً / Warning if WPS is enabled

### 6. تحليل سلوك الشبكة / Network Behavior Analysis

- عدد إشارات البث / Beacon count
- حركة البيانات / Data traffic
- الأنماط غير العادية / Unusual patterns

---

## 📈 Report Sections / أقسام التقرير

### 1. Executive Summary / الملخص التنفيذي

يعرض ملخصاً سريعاً للنتائج:

Shows a quick summary of findings:

- عدد نقاط الضعف الحرجة / Critical vulnerabilities count
- عدد المشاكل عالية الخطورة / High severity issues count
- عدد التحذيرات متوسطة الخطورة / Medium severity warnings count
- عدد التحذيرات منخفضة الخطورة / Low severity warnings count
- عدد المعلومات الإضافية / Informational items count

### 2. Critical & High Severity Vulnerabilities / نقاط الضعف الحرجة والعالية

تفاصيل عن المشاكل الأمنية الخطيرة التي تحتاج إلى معالجة فورية.

Details about serious security issues that need immediate attention.

### 3. Medium Severity Warnings / تحذيرات متوسطة الخطورة

مشاكل يُنصح بمعالجتها قريباً.

Issues that should be addressed soon.

### 4. Low Severity Warnings / تحذيرات منخفضة الخطورة

ملاحظات للتحسين والتطوير.

Notes for improvement and enhancement.

### 5. Informational / معلومات إضافية

معلومات عامة عن الشبكة والأجهزة المتصلة.

General information about the network and connected devices.

### 6. Security Recommendations / التوصيات الأمنية

قائمة بأفضل الممارسات الأمنية.

List of security best practices.

---

## 🛡️ Security Best Practices / أفضل الممارسات الأمنية

### 1. التشفير / Encryption

- استخدم WPA2 مع AES/CCMP كحد أدنى / Use WPA2 with AES/CCMP minimum
- انتقل إلى WPA3 إذا كان متاحاً / Migrate to WPA3 if available
- تجنب WEP و WPA تماماً / Avoid WEP and WPA completely

### 2. كلمات المرور / Passwords

- استخدم كلمات مرور قوية (12+ حرف) / Use strong passwords (12+ characters)
- اخلط بين الأحرف الكبيرة والصغيرة والأرقام والرموز / Mix uppercase, lowercase, numbers, and symbols
- تجنب الكلمات القاموسية / Avoid dictionary words
- غيّر كلمة المرور بانتظام / Change password regularly

### 3. إعدادات الراوتر / Router Settings

- غيّر بيانات الاعتماد الافتراضية / Change default credentials
- عطّل WPS إذا لم تحتاجه / Disable WPS if not needed
- عطّل الإدارة عن بعد / Disable remote management
- حدّث البرنامج الثابت بانتظام / Update firmware regularly

### 4. مراقبة الشبكة / Network Monitoring

- راقب الأجهزة المتصلة بانتظام / Monitor connected devices regularly
- تحقق من الأجهزة غير المعروفة / Check for unknown devices
- استخدم تصفية عناوين MAC / Use MAC address filtering
- راجع السجلات بشكل دوري / Review logs periodically

### 5. تقسيم الشبكة / Network Segmentation

- أنشئ شبكة ضيوف منفصلة / Create separate guest network
- استخدم VLAN للأجهزة المختلفة / Use VLANs for different devices
- عزل أجهزة IoT عن الأجهزة الرئيسية / Isolate IoT devices from main devices

---

## 🔍 Example Vulnerabilities / أمثلة على نقاط الضعف

### Critical - شبكة بدون تشفير / Open Network

```
Network: MyWiFi
Encryption: None (Open)
Risk: All traffic is visible - anyone can intercept data
الخطر: كل البيانات مرئية - يمكن لأي شخص اعتراض البيانات
```

### High - تشفير WEP

```
Network: OldRouter
Encryption: WEP
Risk: Can be cracked in minutes using readily available tools
الخطر: يمكن كسره في دقائق باستخدام أدوات متاحة بسهولة
```

### Medium - مصادقة PSK

```
Network: HomeWiFi
Authentication: PSK
Risk: Vulnerable to dictionary attacks if password is weak
الخطر: عرضة لهجمات القاموس إذا كانت كلمة المرور ضعيفة
```

---

## 📄 Sample Output / مثال على الإخراج

```
================================================================================
NETWORK SECURITY ANALYSIS REPORT
تقرير تحليل أمان الشبكة
================================================================================

Generated: 2026-02-13 18:44:17
Networks Analyzed: 1
Devices Detected: 5

================================================================================
EXECUTIVE SUMMARY / الملخص التنفيذي
================================================================================
Critical Vulnerabilities: 0
High Severity Issues: 0
Medium Severity Warnings: 1
Low Severity Warnings: 1
Informational Items: 5

================================================================================
MEDIUM SEVERITY WARNINGS / تحذيرات متوسطة الخطورة
================================================================================

[1] PSK Authentication
    Network: Taim Starlink
    BSSID: 80:AF:CA:CA:A3:D3
    Description: PSK authentication is vulnerable to dictionary and brute-force 
                 attacks if password is weak
    الوصف: مصادقة PSK عرضة لهجمات القاموس والقوة الغاشمة إذا كانت كلمة المرور ضعيفة
```

---

## ⚠️ Legal Warning / تحذير قانوني

### English

**IMPORTANT:** Only use these tools on networks you own or have explicit permission to test. Unauthorized network scanning and security testing may be illegal in your jurisdiction and could result in:

- Criminal charges
- Civil lawsuits
- Network service termination
- Academic or professional sanctions

Always obtain written permission before testing any network you don't own.

### العربية

**مهم:** استخدم هذه الأدوات فقط على الشبكات التي تملكها أو لديك إذن صريح بفحصها. الفحص الأمني غير المصرح به قد يكون غير قانوني في منطقتك وقد يؤدي إلى:

- اتهامات جنائية
- دعاوى مدنية
- إنهاء خدمة الشبكة
- عقوبات أكاديمية أو مهنية

احصل دائماً على إذن كتابي قبل فحص أي شبكة لا تملكها.

---

## 📞 Support / الدعم

لمزيد من المعلومات أو الإبلاغ عن مشاكل:

For more information or to report issues:

- GitHub Issues: [Create an issue](https://github.com/Majd-Alhgali/test/issues)
- Documentation: [README.md](README.md)
- Analysis: [ANALYSIS_AR.md](ANALYSIS_AR.md)

---

## 📚 References / المراجع

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/)
- [Kismet Wireless](https://www.kismetwireless.net/)
- [WiFi Security Standards (IEEE 802.11)](https://standards.ieee.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Last Updated:** February 13, 2026  
**Version:** 1.0.0
