"""
Export Utilities for Local Forensic Data Correlation Workbench.
Generates structured JSON exports for forensic audit reporting.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from .database import Database


class ForensicExporter:
    def __init__(self, db: Database):
        self.db = db

    def export_search_results(self, search_payload: Dict[str, Any], output_path: Optional[Path] = None) -> str:
        """Exports search results dictionary into clean JSON string or writes to disk."""
        formatted_json = json.dumps(search_payload, indent=2, ensure_ascii=False)
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write(formatted_json)
        return formatted_json

    def export_record(self, record_cluster: Dict[str, Any], output_path: Optional[Path] = None) -> str:
        payload = {
            "export_type": "forensic_record_cluster",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "record": record_cluster
        }
        formatted_json = json.dumps(payload, indent=2, ensure_ascii=False)
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write(formatted_json)
        return formatted_json

    def export_full_report(self) -> Dict[str, Any]:
        """Generates comprehensive incident response audit report."""
        stats = self.db.get_stats()
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, path, type, enabled, file_count, status FROM containers")
            containers = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT field_type, COUNT(*) as count FROM entities GROUP BY field_type")
            field_distribution = {r["field_type"]: r["count"] for r in cursor.fetchall()}

            return {
                "report_title": "Local Forensic Data Correlation Audit Report",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "workbench_stats": stats,
                "containers": containers,
                "detected_field_distribution": field_distribution,
                "legal_disclaimer": "Authorized local data discovery and privacy audit workbench."
            }
        finally:
            conn.close()
