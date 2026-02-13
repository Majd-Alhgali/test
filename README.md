# تحليل شبكات Wi-Fi / WiFi Network Analysis

## 📡 نظرة عامة / Overview

هذا المستودع يحتوي على نتائج فحص وتحليل شبكة Wi-Fi باستخدام أدوات Airodump-ng و Kismet، بالإضافة إلى أداة تحليل أمان الشبكة.

This repository contains Wi-Fi network scanning and analysis results using Airodump-ng and Kismet tools, plus a network security analysis tool.

## 🚀 Quick Start / البدء السريع

### Run Security Analysis / تشغيل تحليل الأمان

```bash
# Install Python 3 if not already installed / ثبّت Python 3 إذا لم يكن مثبتاً
python3 --version

# Run the security analyzer / شغّل محلل الأمان
python3 network_security_analyzer.py ./-01.csv

# The tool will generate a detailed security report
# ستنشئ الأداة تقريراً أمنياً مفصلاً
```

### What You'll Get / ما ستحصل عليه

- ✅ تحليل شامل للتشفير وأمان الشبكة / Comprehensive encryption and network security analysis  
- ✅ كشف نقاط الضعف المحتملة / Detection of potential vulnerabilities  
- ✅ تقرير مفصل بالعربية والإنجليزية / Detailed bilingual report (Arabic/English)  
- ✅ توصيات أمنية قابلة للتنفيذ / Actionable security recommendations


## 🔒 اختبار أمان الشبكة / Network Security Testing

### استخدام أداة تحليل الأمان / Using the Security Analyzer

لتحليل نقاط الضعف المحتملة في شبكة Wi-Fi، استخدم البرنامج النصي Python المضمن:

To analyze potential vulnerabilities in a WiFi network, use the included Python script:

```bash
python3 network_security_analyzer.py ./-01.csv
```

### الميزات / Features

الأداة تقوم بتحليل شامل للشبكة بما في ذلك:

The tool performs comprehensive network analysis including:

- ✅ **تحليل التشفير / Encryption Analysis** - كشف التشفير الضعيف (WEP، WPA) والتشفير القوي (WPA2، WPA3)
- ✅ **تحليل قوة الإشارة / Signal Strength Analysis** - تحديد الإشارات القوية جداً أو الضعيفة جداً
- ✅ **تحليل الأجهزة المتصلة / Connected Devices Analysis** - مراقبة الأجهزة المتصلة والنشاط المشبوه
- ✅ **فحص WPS / WPS Vulnerability Check** - التحقق من نقاط الضعف في WPS
- ✅ **تحليل سلوك الشبكة / Network Behavior Analysis** - اكتشاف الأنماط غير العادية
- ✅ **تقرير شامل ثنائي اللغة / Comprehensive Bilingual Report** - تقرير مفصل بالعربية والإنجليزية

### التقرير الأمني / Security Report

يقوم البرنامج بإنشاء تقرير أمني مفصل يتضمن:

The script generates a detailed security report including:

- 🔴 **نقاط الضعف الحرجة / Critical Vulnerabilities** - مشاكل أمنية تحتاج إلى معالجة فورية
- 🟠 **تحذيرات عالية الخطورة / High Severity Warnings** - مشاكل خطيرة يجب معالجتها قريباً
- 🟡 **تحذيرات متوسطة الخطورة / Medium Severity Warnings** - مشاكل يُنصح بمعالجتها
- 🟢 **تحذيرات منخفضة الخطورة / Low Severity Warnings** - ملاحظات للتحسين
- ℹ️ **معلومات إضافية / Informational** - معلومات عامة عن الشبكة
- 📋 **التوصيات الأمنية / Security Recommendations** - إرشادات لتحسين الأمان

### مثال على التقرير / Report Example

```
================================================================================
NETWORK SECURITY ANALYSIS REPORT
تقرير تحليل أمان الشبكة
================================================================================

Generated: 2026-02-13 18:43:25
Networks Analyzed: 1
Devices Detected: 5

EXECUTIVE SUMMARY / الملخص التنفيذي
- Medium Severity Warnings: 1
- Low Severity Warnings: 1
- Informational Items: 5
```

## 📁 الملفات / Files

- **`network_security_analyzer.py`** - أداة تحليل أمان الشبكة / Network security analysis tool
- **`-01.csv`** - ملف بيانات Airodump-ng الأساسي / Basic Airodump-ng data file
- **`-01.kismet.csv`** - بيانات Kismet بتنسيق CSV / Kismet data in CSV format
- **`-01.kismet.netxml`** - بيانات Kismet بتنسيق XML / Kismet data in XML format
- **`-01.log.csv`** - سجل مفصل (32,910 سجل) / Detailed log (32,910 records)
- **`ANALYSIS_AR.md`** - تحليل شامل بالعربية / Comprehensive analysis in Arabic

## 🔍 التحليل الكامل / Full Analysis

للحصول على تحليل مفصل وشامل لجميع الملفات بالعربية، يرجى الاطلاع على:

For a detailed and comprehensive analysis of all files in Arabic, please see:

👉 **[ANALYSIS_AR.md](ANALYSIS_AR.md)**

### 🛡️ دليل اختبار الأمان / Security Testing Guide

للحصول على دليل كامل حول كيفية استخدام أداة تحليل الأمان، يرجى الاطلاع على:

For a complete guide on how to use the security analysis tool, please see:

👉 **[SECURITY_TESTING.md](SECURITY_TESTING.md)**

## 📊 معلومات الفحص / Scan Information

- **الشبكة المفحوصة / Network Scanned:** Taim Starlink
- **التاريخ / Date:** February 13, 2026
- **المدة / Duration:** ~5 minutes (05:55:14 - 06:00:32)
- **القناة / Channel:** 9 (2.452 GHz)
- **التشفير / Encryption:** WPA2-PSK (CCMP/AES)
- **الأجهزة المتصلة / Connected Devices:** 5 devices
- **عدد السجلات / Total Records:** 32,910 entries

## ⚠️ تحذير قانوني / Legal Warning

يجب استخدام هذه الأدوات فقط على الشبكات التي تملك الإذن القانوني بفحصها. الفحص غير المصرح به قد يكون غير قانوني.

These tools should only be used on networks you have legal permission to scan. Unauthorized scanning may be illegal.

## 🛠️ الأدوات المستخدمة / Tools Used

- **Airodump-ng** - جزء من مجموعة Aircrack-ng / Part of Aircrack-ng suite
- **Kismet** - أداة متقدمة لكشف الشبكات اللاسلكية / Advanced wireless network detector