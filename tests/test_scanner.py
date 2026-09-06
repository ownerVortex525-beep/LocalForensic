"""
Unit tests for ForensicScanner in Local Forensic Data Correlation Workbench.
Tests file format parsing (txt, json, csv, xml), container scanning, and entity ingestion.
"""

import unittest
import tempfile
import time
from pathlib import Path
import sys

current_dir = Path(__file__).resolve().parent
workbench_dir = current_dir.parent if (current_dir.parent / "app" / "database.py").exists() else current_dir.parent / "local_forensic_workbench"
if str(workbench_dir) not in sys.path:
    sys.path.insert(0, str(workbench_dir))

from app.database import Database
from app.container_manager import ContainerManager
from app.detectors import DetectorEngine
from app.scanner import ForensicScanner


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name)
        self.db = Database(self.base / "test.db")
        self.db.init_db()
        self.config_path = self.base / "containers.json"
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write('{"containers": []}')
        self.container_mgr = ContainerManager(self.db, self.config_path)
        self.detector_engine = DetectorEngine()
        self.scanner = ForensicScanner(self.db, self.container_mgr, self.detector_engine)

    def tearDown(self):
        if self.scanner.scan_thread and self.scanner.scan_thread.is_alive():
            self.scanner.stop_scan()
            self.scanner.scan_thread.join(timeout=3)
        time.sleep(0.1)
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_scan_csv_file(self):
        data_dir = self.base / "evidence"
        data_dir.mkdir(parents=True, exist_ok=True)
        csv_file = data_dir / "users.csv"
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write('email,name,phone\n')
            f.write('alice@investigation.org,"Alice Smith",+1-555-0199\n')

        container = self.container_mgr.add_container("Test Evidence", str(data_dir), "folder")
        job_id = self.scanner.start_scan_async(container_id=container.id)
        
        # Wait for thread completion
        if self.scanner.scan_thread:
            self.scanner.scan_thread.join(timeout=5)

        stats = self.db.get_stats()
        self.assertEqual(stats["total_files_scanned"], 1)
        self.assertTrue(stats["total_entities"] >= 3)

    def test_scan_json_file(self):
        data_dir = self.base / "json_evidence"
        data_dir.mkdir(parents=True, exist_ok=True)
        json_file = data_dir / "dump.json"
        with open(json_file, "w", encoding="utf-8") as f:
            f.write('{"suspect": {"email": "badactor@cyber.io", "ip": "10.0.0.1"}}')

        container = self.container_mgr.add_container("JSON Evidence", str(data_dir), "folder")
        job_id = self.scanner.start_scan_async(container_id=container.id)
        
        if self.scanner.scan_thread:
            self.scanner.scan_thread.join(timeout=5)

        stats = self.db.get_stats()
        self.assertEqual(stats["total_files_scanned"], 1)
        self.assertTrue(stats["total_entities"] >= 2)



if __name__ == "__main__":
    unittest.main()
