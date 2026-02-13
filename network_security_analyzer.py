#!/usr/bin/env python3
"""
Network Security Analyzer
تحليل أمان الشبكة

This script analyzes WiFi network scan data and identifies potential security vulnerabilities.
يقوم هذا البرنامج بتحليل بيانات فحص شبكة WiFi وتحديد نقاط الضعف الأمنية المحتملة.
"""

import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict
import os
import sys


class NetworkSecurityAnalyzer:
    """Analyze network security from WiFi scan data."""
    
    def __init__(self):
        self.vulnerabilities = []
        self.warnings = []
        self.info = []
        self.networks = []
        self.stations = []
        
    def load_airodump_csv(self, filepath):
        """Load and parse Airodump-ng CSV file."""
        print(f"[*] Loading Airodump-ng data from {filepath}...")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Split into networks and stations sections
            parts = content.split('\n\n')
            
            # Parse networks (Access Points)
            networks_section = parts[0].strip().split('\n')
            if len(networks_section) > 1:
                reader = csv.DictReader(networks_section)
                for row in reader:
                    # Strip whitespace from all values
                    cleaned_row = {k.strip(): v.strip() if isinstance(v, str) else v 
                                   for k, v in row.items()}
                    if cleaned_row.get('BSSID'):
                        self.networks.append(cleaned_row)
            
            # Parse stations (clients)
            if len(parts) > 1:
                stations_section = parts[1].strip().split('\n')
                if len(stations_section) > 1:
                    reader = csv.DictReader(stations_section)
                    for row in reader:
                        # Strip whitespace from all values
                        cleaned_row = {k.strip(): v.strip() if isinstance(v, str) else v 
                                       for k, v in row.items()}
                        if cleaned_row.get('Station MAC'):
                            self.stations.append(cleaned_row)
                            
            print(f"[+] Found {len(self.networks)} network(s) and {len(self.stations)} station(s)")
            return True
            
        except Exception as e:
            print(f"[!] Error loading CSV: {e}")
            return False
    
    def analyze_encryption(self):
        """Analyze encryption standards and identify vulnerabilities."""
        print("\n[*] Analyzing encryption standards...")
        
        for network in self.networks:
            bssid = network.get('BSSID', 'Unknown')
            essid = network.get('ESSID', 'Unknown')
            privacy = network.get('Privacy', 'Unknown')
            cipher = network.get('Cipher', 'Unknown')
            auth = network.get('Authentication', 'Unknown')
            
            # Check for WEP (highly vulnerable)
            if 'WEP' in privacy:
                self.vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'type': 'Weak Encryption',
                    'network': essid,
                    'bssid': bssid,
                    'description': 'WEP encryption is extremely vulnerable and can be cracked in minutes',
                    'description_ar': 'تشفير WEP ضعيف جداً ويمكن كسره في دقائق'
                })
            
            # Check for WPA (deprecated)
            elif privacy == 'WPA':
                self.vulnerabilities.append({
                    'severity': 'HIGH',
                    'type': 'Deprecated Encryption',
                    'network': essid,
                    'bssid': bssid,
                    'description': 'WPA is deprecated and vulnerable to attacks. Should use WPA2 or WPA3',
                    'description_ar': 'تشفير WPA قديم وعرضة للاختراق. يجب استخدام WPA2 أو WPA3'
                })
            
            # Check for Open network (no encryption)
            elif privacy == 'OPN' or not privacy:
                self.vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'type': 'No Encryption',
                    'network': essid,
                    'bssid': bssid,
                    'description': 'Network has no encryption - all traffic is visible',
                    'description_ar': 'الشبكة بدون تشفير - كل البيانات مرئية'
                })
            
            # Check for WPA2 with TKIP (weak)
            elif privacy == 'WPA2' and 'TKIP' in cipher:
                self.warnings.append({
                    'severity': 'MEDIUM',
                    'type': 'Weak Cipher',
                    'network': essid,
                    'bssid': bssid,
                    'description': 'WPA2 with TKIP is weaker than CCMP/AES. Should use AES only',
                    'description_ar': 'WPA2 مع TKIP أضعف من CCMP/AES. يجب استخدام AES فقط'
                })
            
            # WPA2 with CCMP/AES is good
            elif privacy == 'WPA2' and 'CCMP' in cipher:
                self.info.append({
                    'type': 'Good Encryption',
                    'network': essid,
                    'bssid': bssid,
                    'description': 'WPA2 with CCMP/AES - Good encryption standard',
                    'description_ar': 'WPA2 مع CCMP/AES - معيار تشفير جيد'
                })
            
            # Check for PSK (Pre-Shared Key) - vulnerable to dictionary attacks
            if 'PSK' in auth:
                self.warnings.append({
                    'severity': 'MEDIUM',
                    'type': 'PSK Authentication',
                    'network': essid,
                    'bssid': bssid,
                    'description': 'PSK authentication is vulnerable to dictionary and brute-force attacks if password is weak',
                    'description_ar': 'مصادقة PSK عرضة لهجمات القاموس والقوة الغاشمة إذا كانت كلمة المرور ضعيفة'
                })
    
    def analyze_signal_strength(self):
        """Analyze signal strength for potential security issues."""
        print("\n[*] Analyzing signal strength...")
        
        for network in self.networks:
            bssid = network.get('BSSID', '')
            essid = network.get('ESSID', '')
            power = network.get('Power', '')
            
            try:
                power_val = int(power)
                
                # Very strong signal might indicate close proximity or powerful antenna
                if power_val > -40:
                    self.warnings.append({
                        'severity': 'LOW',
                        'type': 'Very Strong Signal',
                        'network': essid,
                        'bssid': bssid,
                        'description': f'Very strong signal ({power} dBm) - may indicate unauthorized access point or evil twin',
                        'description_ar': f'إشارة قوية جداً ({power} dBm) - قد تشير إلى نقطة وصول غير مصرح بها'
                    })
            except (ValueError, TypeError):
                pass
    
    def analyze_connected_devices(self):
        """Analyze connected devices for suspicious activity."""
        print(f"\n[*] Analyzing {len(self.stations)} connected device(s)...")
        
        # Group stations by BSSID
        stations_by_network = defaultdict(list)
        for station in self.stations:
            bssid = station.get('BSSID', '')
            if bssid:
                stations_by_network[bssid].append(station)
        
        for bssid, stations in stations_by_network.items():
            # Find network name
            network_name = 'Unknown'
            for network in self.networks:
                if network.get('BSSID', '') == bssid:
                    network_name = network.get('ESSID', 'Unknown')
                    break
            
            # Check for many connected devices (potential security concern)
            if len(stations) >= 5:
                self.warnings.append({
                    'severity': 'LOW',
                    'type': 'Multiple Devices',
                    'network': network_name,
                    'bssid': bssid,
                    'description': f'{len(stations)} devices connected - verify all are authorized',
                    'description_ar': f'{len(stations)} جهاز متصل - تحقق من أن جميعها مصرح بها'
                })
            
            # Check for devices with weak signals (might be far away or using weak hardware)
            for station in stations:
                power = station.get('Power', '')
                mac = station.get('Station MAC', '')
                try:
                    power_val = int(power)
                    if power_val < -85:
                        self.info.append({
                            'type': 'Weak Client Signal',
                            'network': network_name,
                            'device': mac,
                            'description': f'Device {mac} has weak signal ({power} dBm) - may indicate distance or interference',
                            'description_ar': f'الجهاز {mac} له إشارة ضعيفة ({power} dBm) - قد يشير للمسافة أو التداخل'
                        })
                except (ValueError, TypeError):
                    pass
    
    def check_wps_vulnerability(self):
        """Check for WPS vulnerabilities."""
        print("\n[*] Checking for WPS vulnerabilities...")
        
        # Note: WPS status is not typically in basic Airodump-ng output
        # This is a placeholder for more advanced analysis
        self.info.append({
            'type': 'WPS Check',
            'description': 'WPS (WiFi Protected Setup) status unknown from this data. Recommend checking with wash or similar tools',
            'description_ar': 'حالة WPS (إعداد WiFi المحمي) غير معروفة من هذه البيانات. يُنصح بالفحص باستخدام أدوات مثل wash'
        })
    
    def analyze_network_behavior(self):
        """Analyze network behavior patterns."""
        print("\n[*] Analyzing network behavior patterns...")
        
        for network in self.networks:
            essid = network.get('ESSID', '')
            bssid = network.get('BSSID', '')
            beacons = network.get('# beacons', '')
            data_packets = network.get('# IV', '')
            channel = network.get('channel', '')
            
            try:
                beacon_count = int(beacons)
                data_count = int(data_packets)
                
                # Check for unusual beacon rate
                if beacon_count < 100:
                    self.warnings.append({
                        'severity': 'LOW',
                        'type': 'Low Beacon Count',
                        'network': essid,
                        'bssid': bssid,
                        'description': f'Low beacon count ({beacon_count}) - might indicate hidden SSID or unusual configuration',
                        'description_ar': f'عدد إشارات بث منخفض ({beacon_count}) - قد يشير إلى SSID مخفي أو إعداد غير عادي'
                    })
                
                # Check for high data traffic
                if data_count > 20000:
                    self.info.append({
                        'type': 'High Data Traffic',
                        'network': essid,
                        'bssid': bssid,
                        'description': f'High data packet count ({data_count}) - active network usage detected',
                        'description_ar': f'عدد حزم بيانات مرتفع ({data_count}) - تم اكتشاف استخدام نشط للشبكة'
                    })
                    
            except (ValueError, TypeError):
                pass
    
    def generate_report(self):
        """Generate comprehensive security report."""
        print("\n[*] Generating security report...")
        
        report = []
        report.append("=" * 80)
        report.append("NETWORK SECURITY ANALYSIS REPORT")
        report.append("تقرير تحليل أمان الشبكة")
        report.append("=" * 80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Networks Analyzed: {len(self.networks)}")
        report.append(f"Devices Detected: {len(self.stations)}")
        report.append("")
        
        # Summary
        report.append("=" * 80)
        report.append("EXECUTIVE SUMMARY / الملخص التنفيذي")
        report.append("=" * 80)
        report.append(f"Critical Vulnerabilities: {len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL'])}")
        report.append(f"High Severity Issues: {len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH'])}")
        report.append(f"Medium Severity Warnings: {len([w for w in self.warnings if w.get('severity') == 'MEDIUM'])}")
        report.append(f"Low Severity Warnings: {len([w for w in self.warnings if w.get('severity') == 'LOW'])}")
        report.append(f"Informational Items: {len(self.info)}")
        report.append("")
        
        # Critical and High severity vulnerabilities
        critical_high = [v for v in self.vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
        if critical_high:
            report.append("=" * 80)
            report.append("CRITICAL & HIGH SEVERITY VULNERABILITIES / نقاط الضعف الحرجة والعالية")
            report.append("=" * 80)
            for i, vuln in enumerate(critical_high, 1):
                report.append(f"\n[{i}] {vuln.get('severity')} - {vuln.get('type')}")
                report.append(f"    Network: {vuln.get('network', 'N/A')}")
                report.append(f"    BSSID: {vuln.get('bssid', 'N/A')}")
                report.append(f"    Description: {vuln.get('description')}")
                report.append(f"    الوصف: {vuln.get('description_ar')}")
            report.append("")
        
        # Medium severity warnings
        medium_warnings = [w for w in self.warnings if w.get('severity') == 'MEDIUM']
        if medium_warnings:
            report.append("=" * 80)
            report.append("MEDIUM SEVERITY WARNINGS / تحذيرات متوسطة الخطورة")
            report.append("=" * 80)
            for i, warn in enumerate(medium_warnings, 1):
                report.append(f"\n[{i}] {warn.get('type')}")
                report.append(f"    Network: {warn.get('network', 'N/A')}")
                report.append(f"    BSSID: {warn.get('bssid', 'N/A')}")
                report.append(f"    Description: {warn.get('description')}")
                report.append(f"    الوصف: {warn.get('description_ar')}")
            report.append("")
        
        # Low severity warnings
        low_warnings = [w for w in self.warnings if w.get('severity') == 'LOW']
        if low_warnings:
            report.append("=" * 80)
            report.append("LOW SEVERITY WARNINGS / تحذيرات منخفضة الخطورة")
            report.append("=" * 80)
            for i, warn in enumerate(low_warnings, 1):
                report.append(f"\n[{i}] {warn.get('type')}")
                report.append(f"    Network: {warn.get('network', 'N/A')}")
                if warn.get('bssid'):
                    report.append(f"    BSSID: {warn.get('bssid')}")
                if warn.get('device'):
                    report.append(f"    Device: {warn.get('device')}")
                report.append(f"    Description: {warn.get('description')}")
                if warn.get('description_ar'):
                    report.append(f"    الوصف: {warn.get('description_ar')}")
            report.append("")
        
        # Informational items
        if self.info:
            report.append("=" * 80)
            report.append("INFORMATIONAL / معلومات إضافية")
            report.append("=" * 80)
            for i, item in enumerate(self.info[:10], 1):  # Limit to first 10
                report.append(f"\n[{i}] {item.get('type')}")
                if item.get('network'):
                    report.append(f"    Network: {item.get('network')}")
                if item.get('device'):
                    report.append(f"    Device: {item.get('device')}")
                report.append(f"    {item.get('description')}")
                if item.get('description_ar'):
                    report.append(f"    {item.get('description_ar')}")
            if len(self.info) > 10:
                report.append(f"\n... and {len(self.info) - 10} more informational items")
            report.append("")
        
        # Recommendations
        report.append("=" * 80)
        report.append("SECURITY RECOMMENDATIONS / التوصيات الأمنية")
        report.append("=" * 80)
        
        recommendations = [
            ("1. Use WPA2-PSK with AES/CCMP or WPA3 for encryption",
             "1. استخدم WPA2-PSK مع AES/CCMP أو WPA3 للتشفير"),
            ("2. Use strong, complex passwords (12+ characters, mixed case, numbers, symbols)",
             "2. استخدم كلمات مرور قوية ومعقدة (12+ حرف، أحرف كبيرة وصغيرة، أرقام، رموز)"),
            ("3. Disable WPS (WiFi Protected Setup) if not needed",
             "3. عطّل WPS (إعداد WiFi المحمي) إذا لم يكن ضرورياً"),
            ("4. Change default router credentials immediately",
             "4. غيّر بيانات اعتماد الراوتر الافتراضية فوراً"),
            ("5. Enable MAC address filtering for additional security layer",
             "5. فعّل تصفية عناوين MAC لطبقة أمان إضافية"),
            ("6. Regularly update router firmware",
             "6. حدّث البرنامج الثابت للراوتر بانتظام"),
            ("7. Monitor connected devices regularly",
             "7. راقب الأجهزة المتصلة بانتظام"),
            ("8. Consider hiding SSID for additional obscurity (not primary security)",
             "8. فكّر في إخفاء SSID للتمويه الإضافي (ليس الأمان الأساسي)"),
            ("9. Implement network segmentation (guest network, IoT network)",
             "9. طبّق تقسيم الشبكة (شبكة ضيوف، شبكة IoT)"),
            ("10. Regularly conduct security audits",
             "10. أجرِ تدقيقات أمنية بانتظام")
        ]
        
        for eng, ar in recommendations:
            report.append(f"\n{eng}")
            report.append(f"{ar}")
        
        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT / نهاية التقرير")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def run_analysis(self, csv_file):
        """Run complete security analysis."""
        print("\n" + "=" * 80)
        print("Network Security Analyzer")
        print("محلل أمان الشبكة")
        print("=" * 80)
        
        if not self.load_airodump_csv(csv_file):
            print("[!] Failed to load data")
            return None
        
        self.analyze_encryption()
        self.analyze_signal_strength()
        self.analyze_connected_devices()
        self.check_wps_vulnerability()
        self.analyze_network_behavior()
        
        report = self.generate_report()
        
        # Save report to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"security_report_{timestamp}.txt"
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n[+] Report saved to: {report_file}")
        except Exception as e:
            print(f"[!] Error saving report: {e}")
        
        return report


def main():
    """Main function."""
    csv_file = "./-01.csv"
    
    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    
    if not os.path.exists(csv_file):
        print(f"[!] Error: File not found: {csv_file}")
        print(f"Usage: {sys.argv[0]} [csv_file]")
        print(f"Example: {sys.argv[0]} ./-01.csv")
        return 1
    
    analyzer = NetworkSecurityAnalyzer()
    report = analyzer.run_analysis(csv_file)
    
    if report:
        print("\n" + "=" * 80)
        print(report)
        print("\n[+] Analysis complete!")
        return 0
    else:
        print("\n[!] Analysis failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
