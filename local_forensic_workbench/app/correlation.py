"""
Record Correlation Engine for Local Forensic Data Correlation Workbench.
Groups nearby detected entities within a context window or file record into unified clusters,
links co-occurring entities, and produces correlated JSON record responses.
"""

from typing import List, Dict, Any, Optional
from .database import Database
from .models import EntityRecord
from .utils import apply_redaction


class CorrelationEngine:
    def __init__(self, db: Database, redaction_enabled: bool = False):
        self.db = db
        self.redaction_enabled = redaction_enabled

    def get_record_cluster(self, record_id: str, primary_entity_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves all entities associated with the given record_id and forms a correlated cluster.
        """
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, record_id, field_type, raw_value, normalized_value,
                       source_file, container_id, container_name, line_number,
                       context_snippet, confidence, detector_name, pattern_id, created_at
                FROM entities
                WHERE record_id = ?
                ORDER BY line_number ASC, id ASC
            """, (record_id,))
            rows = cursor.fetchall()
            if not rows:
                return None

            entities = [dict(r) for r in rows]

            # Determine primary match
            primary = None
            if primary_entity_id:
                for ent in entities:
                    if ent["id"] == primary_entity_id:
                        primary = ent
                        break
            if not primary and entities:
                primary = entities[0]

            connected_fields: Dict[str, str] = {}
            all_entities_list: List[Dict[str, Any]] = []

            for ent in entities:
                raw_val = ent["raw_value"]
                if self.redaction_enabled:
                    raw_val = apply_redaction(raw_val, ent["field_type"])

                # Group into connected_fields (latest or highest confidence wins for single key view)
                if ent["field_type"] not in connected_fields or ent["confidence"] == "high":
                    connected_fields[ent["field_type"]] = raw_val

                all_entities_list.append({
                    "id": ent["id"],
                    "field_type": ent["field_type"],
                    "raw_value": raw_val,
                    "normalized_value": ent["normalized_value"],
                    "line_number": ent["line_number"],
                    "confidence": ent["confidence"],
                    "detector_name": ent.get("detector_name"),
                    "pattern_id": ent.get("pattern_id")
                })

            prim_raw = primary["raw_value"]
            if self.redaction_enabled:
                prim_raw = apply_redaction(prim_raw, primary["field_type"])

            return {
                "record_id": record_id,
                "primary_match": {
                    "entity_id": primary["id"],
                    "field_type": primary["field_type"],
                    "raw_value": prim_raw,
                    "normalized_value": primary["normalized_value"],
                    "source_file": primary["source_file"],
                    "container_id": primary["container_id"],
                    "container_name": primary.get("container_name") or primary["container_id"],
                    "line_number": primary["line_number"],
                    "confidence": primary["confidence"],
                    "context_snippet": primary["context_snippet"]
                },
                "connected_fields": connected_fields,
                "all_entities": all_entities_list
            }
        finally:
            conn.close()

    def build_correlated_response(self, primary_entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Given a list of matched entities from search, builds the full correlated result structure.
        """
        results: List[Dict[str, Any]] = []
        seen_records = set()

        for ent in primary_entities:
            rec_id = ent.get("record_id")
            if not rec_id:
                continue

            cluster = self.get_record_cluster(rec_id, primary_entity_id=ent.get("id"))
            if cluster:
                # Deduplicate records so each unique record cluster appears once with primary match
                if rec_id not in seen_records:
                    seen_records.add(rec_id)
                    results.append(cluster)

        return results
