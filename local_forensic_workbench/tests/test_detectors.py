"""
Unit tests for modular detectors in Local Forensic Data Correlation Workbench.
Tests email, phone, name, address, passport, SSN, IP, domain, social, vehicle, etc.
"""

import unittest
from pathlib import Path
import sys

current_dir = Path(__file__).resolve().parent
workbench_dir = current_dir.parent if (current_dir.parent / "app" / "database.py").exists() else current_dir.parent / "local_forensic_workbench"
if str(workbench_dir) not in sys.path:
    sys.path.insert(0, str(workbench_dir))

from app.detectors import DetectorEngine


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.engine = DetectorEngine()
        self.meta = {
            "source_file": "test_evidence.log",
            "container_id": "test_c01",
            "container_name": "Test Container",
            "context_snippet": "test surrounding context"
        }

    def test_email_detector(self):
        text = "Contact analyst at alex.dev99@example.com for incident verification."
        results = self.engine.scan_line(text, 1, self.meta)
        emails = [r for r in results if r.field_type == "email"]
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0].raw_value, "alex.dev99@example.com")
        self.assertEqual(emails[0].normalized_value, "alex.dev99@example.com")

    def test_phone_detector(self):
        text = "Emergency hotline: +1 415 555 2671 or WhatsApp: +79161234567"
        results = self.engine.scan_line(text, 2, self.meta)
        phones = [r for r in results if r.field_type in ["phone_number", "whatsapp_number"]]
        self.assertTrue(len(phones) >= 2)

    def test_ip_detector(self):
        text = "Suspicious connection from IP: 185.22.14.92 port 443"
        results = self.engine.scan_line(text, 3, self.meta)
        ips = [r for r in results if r.field_type == "ip_address"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0].raw_value, "185.22.14.92")

    def test_passport_detector(self):
        text = "Target record passport: 4510 123456 issued in Moscow"
        results = self.engine.scan_line(text, 4, self.meta)
        docs = [r for r in results if "passport" in r.field_type]
        self.assertTrue(len(docs) >= 1)

    def test_ssn_and_tax_detector(self):
        text = "Subject Profile SSN: 123-45-6789 | Taxpayer_ID: 98-7654321"
        results = self.engine.scan_line(text, 5, self.meta)
        ssns = [r for r in results if r.field_type == "ssn_pattern"]
        taxes = [r for r in results if r.field_type == "taxpayer_id_number"]
        self.assertEqual(len(ssns), 1)
        self.assertEqual(len(taxes), 1)

    def test_social_and_vehicle_detector(self):
        text = "Driver VIN: XTA210930Y2123456 | Plate: А123БВ77 | Telegram: @ivan_dev"
        results = self.engine.scan_line(text, 6, self.meta)
        vins = [r for r in results if r.field_type == "vin"]
        tgs = [r for r in results if r.field_type == "telegram_id"]
        cars = [r for r in results if r.field_type in ["car_number", "vehicle_registration_number"]]
        self.assertEqual(len(vins), 1)
        self.assertEqual(len(tgs), 1)
        self.assertTrue(len(cars) >= 1)


if __name__ == "__main__":
    unittest.main()
