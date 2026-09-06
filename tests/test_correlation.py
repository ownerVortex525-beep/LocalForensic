"""
Unit tests for CorrelationEngine in Local Forensic Data Correlation Workbench.
Tests record clustering, entity links, redaction, and record reconstruction.
"""

import unittest
import tempfile
from pathlib import Path
import sys

current_dir = Path(__file__).resolve().parent
workbench_dir = current_dir.parent if (current_dir.parent / "app" / "database.py").exists() else current_dir.parent / "local_forensic_workbench"
if str(workbench_dir) not in sys.path:
    sys.path.insert(0, str(workbench_dir))

from app.database import Database
from app.correlation import CorrelationEngine


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name)
        self.db = Database(self.base / "corr_test.db")
        self.db.init_db()
        self.correlation = CorrelationEngine(self.db, redaction_enabled=False)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_record_cluster_creation_and_retrieval(self):
        rec_id = "rec_hash_12345"
        meta = {
            "record_id": rec_id,
            "source_file": "audit.log",
            "container_id": "c01",
            "container_name": "Container A",
            "context_snippet": "Email: user@domain.com | IP: 1.1.1.1"
        }

        # Ingest test entities
        e1 = self.db.insert_entity(
            record_id=rec_id, field_type="email", raw_value="user@domain.com",
            normalized_value="user@domain.com", source_file=meta["source_file"],
            container_id=meta["container_id"], container_name=meta["container_name"],
            line_number=10, context_snippet=meta["context_snippet"],
            confidence="high", detector_name="email_detector", pattern_id="pat1"
        )
        e2 = self.db.insert_entity(
            record_id=rec_id, field_type="ip_address", raw_value="1.1.1.1",
            normalized_value="1.1.1.1", source_file=meta["source_file"],
            container_id=meta["container_id"], container_name=meta["container_name"],
            line_number=10, context_snippet=meta["context_snippet"],
            confidence="high", detector_name="ip_detector", pattern_id="pat2"
        )

        cluster = self.correlation.get_record_cluster(rec_id)
        self.assertIsNotNone(cluster)
        self.assertEqual(cluster["record_id"], rec_id)
        self.assertEqual(len(cluster["all_entities"]), 2)
        self.assertIn("ip_address", cluster["connected_fields"])

    def test_redaction_mode(self):
        redacted_engine = CorrelationEngine(self.db, redaction_enabled=True)
        rec_id = "rec_redact_99"
        e = self.db.insert_entity(
            record_id=rec_id, field_type="email", raw_value="secret.agent@gov.org",
            normalized_value="secret.agent@gov.org", source_file="secret.log",
            container_id="c02", container_name="Secret C",
            line_number=5, context_snippet="secret context",
            confidence="high", detector_name="email_detector", pattern_id="pat1"
        )

        cluster = redacted_engine.get_record_cluster(rec_id)
        self.assertTrue("*" in cluster["primary_match"]["raw_value"])


if __name__ == "__main__":
    unittest.main()
