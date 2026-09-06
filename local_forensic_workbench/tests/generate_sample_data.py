"""
Sample Synthetic Data Generator for Local Forensic Data Correlation Workbench.
Generates test files with synthetic, non-real records for validation and testing.
"""

from pathlib import Path
import json


def generate_all_samples(base_dir: Path) -> None:
    sample_dir = base_dir / "data" / "sample"
    sample_dir.mkdir(parents=True, exist_ok=True)

    # 1. sample_001.txt
    txt_content = """[+] Email: alex.dev99@example.com
[+] Password: Str0ngP@ssw0rd!2024
[+] IP: 185.22.14.92
[+] Country: RU | City: Moscow
[+] App: Steam | Nick: DarkLord_99 | SteamID: STEAM_0:1:12345678
[+] Domain: example.com
---
user_ivan@mail.ru:Qwerty12345 | IP: 91.105.44.12 | VK_ID: id8839201 | Telegram: @ivan_dev
---
gamer_pro@hotmail.com | Pass: hunter2 | App: FreeFire | UID: 849201992 | Device: Xiaomi Redmi Note 10
"""
    with open(sample_dir / "sample_001.txt", "w", encoding="utf-8") as f:
        f.write(txt_content)

    # 2. sample_002.json
    json_obj = {
        "phone": "+79161234567",
        "fio": "Ivanov Ivan Ivanovich",
        "passport": "4510 123456",
        "passport_date": "2015-04-12",
        "snils": "123-456-789 00",
        "inn": "771234567890",
        "car_number": "А123БВ77",
        "vin": "XTA210930Y2123456",
        "address": "Moscow, Tverskaya st, 1, apt 4",
        "social": {
            "vk": "vk.com/id12345678",
            "telegram": "@ivan_official",
            "instagram": "ivan.msk.99"
        },
        "relatives": [
            {"role": "mother", "name": "Ivanova Maria Petrovna", "phone": "+79167654321"}
        ]
    }
    with open(sample_dir / "sample_002.json", "w", encoding="utf-8") as f:
        json.dump(json_obj, f, indent=2, ensure_ascii=False)

    # 3. sample_003.csv
    csv_content = """phone,name,tags,isp,alt_number,location
+919876543210,"Rahul Sharma","[""Delivery"",""Spam"",""Fraud""]","Jio 4G",+919876500000,"Delhi, India"
+14155552671,"John Doe","[""Business"",""Tech""]","Comcast",,"San Francisco, CA"
+442071838750,"London Pizza","[""Food""]","BT",,"London, UK"
"""
    with open(sample_dir / "sample_003.csv", "w", encoding="utf-8") as f:
        f.write(csv_content)

    # 4. sample_004.log
    log_content = """[2025-11-04 14:22:01] User login successful. 
User: nick_master88 | IP: 192.168.1.45 | Auth_Token: 8f7d9a2b3c4e5f6g7h8i9j0k
Profile: 
Name: Alex Mercer
Father: David Mercer
Mother: Sarah Mercer
DOB: 1992-08-14
SSN: 123-45-6789
Taxpayer_ID: 98-7654321
Document: DL-9928374
Network: AT&T Wireless
Link: https://portal.example.com/user/88392
"""
    with open(sample_dir / "sample_004.log", "w", encoding="utf-8") as f:
        f.write(log_content)

    # 5. sample_005.xml
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<audit_records>
  <record id="rec_001">
    <full_name>Marcus Vance</full_name>
    <email>m.vance@defense-grid.org</email>
    <phone>+1-202-555-0199</phone>
    <passport_number>A8829103</passport_number>
    <ip_address>10.14.220.88</ip_address>
    <company_name>Defense Grid Corp</company_name>
    <address>1200 Pennsylvania Ave NW, Washington, DC</address>
  </record>
  <record id="rec_002">
    <full_name>Elena Rostova</full_name>
    <email>elena.r@cyber-sentinel.io</email>
    <phone>+7-495-777-8899</phone>
    <passport_number>4508 998811</passport_number>
    <ip_address>195.88.24.10</ip_address>
    <company_name>Sentinel Analytics LLC</company_name>
    <address>Nevsky Prospekt, 28, St. Petersburg</address>
  </record>
</audit_records>
"""
    with open(sample_dir / "sample_005.xml", "w", encoding="utf-8") as f:
        f.write(xml_content)

    print(f"Sample test data generated successfully in {sample_dir}")


if __name__ == "__main__":
    current_dir = Path(__file__).resolve().parent.parent
    generate_all_samples(current_dir)
