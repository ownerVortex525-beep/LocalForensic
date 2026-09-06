"""
Search Engine for Local Forensic Data Correlation Workbench.
Implements 15 specialized forensic search modes with normalization,
digit filtering, case-insensitivity, and correlated record clustering.
"""

import re
import time
from typing import List, Dict, Any, Optional
from .database import Database
from .correlation import CorrelationEngine


MODE_FIELD_MAPPING = {
    "global": None,  # All fields
    "email": ["email"],
    "number": [
        "phone_number", "whatsapp_number", "car_number", "vehicle_registration_number",
        "document_number", "passport_number", "passport_or_document_number",
        "national_id_number", "taxpayer_id_number", "ssn_pattern", "snils_or_social_reference_number"
    ],
    "name": ["full_name", "contact_person", "nickname", "username", "company_name"],
    "phone": ["phone_number", "whatsapp_number"],
    "address": ["address", "location_name"],
    "passport": ["passport_number", "passport_or_document_number", "document_number"],
    "username": ["username", "login", "nickname", "account_identifier"],
    "ip": ["ip_address"],
    "domain": ["domain_name", "url_link"],
    "company": ["company_name"],
    "vehicle": ["car_number", "vehicle_registration_number", "vin"],
    "social": ["vk_id", "steam_id", "facebook_id", "telegram_id", "instagram_identifier"],
    "auth": ["legacy_auth_string_or_hash", "login"],
}


class ForensicSearchEngine:
    def __init__(self, db: Database, correlation_engine: CorrelationEngine):
        self.db = db
        self.correlation = correlation_engine

    def execute_search(
        self,
        query: str,
        mode: str = "global",
        custom_field: Optional[str] = None,
        exact: bool = False,
        fuzzy: bool = False,
        limit: int = 100
    ) -> Dict[str, Any]:
        start_time = time.time()
        query_clean = query.strip()
        query_lower = query_clean.lower()
        query_digits = re.sub(r'\D', '', query_clean)

        # Determine target fields
        target_fields = None
        if custom_field:
            target_fields = [custom_field]
        elif mode in MODE_FIELD_MAPPING:
            target_fields = MODE_FIELD_MAPPING[mode]

        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            
            # Count total enabled sources
            cursor.execute("SELECT COUNT(*) FROM files")
            scan_sources = cursor.fetchone()[0]

            if not query_clean:
                return {
                    "query": "",
                    "search_mode": mode,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "result_count": 0,
                    "scan_sources": scan_sources,
                    "execution_time_ms": int((time.time() - start_time) * 1000),
                    "results": []
                }

            sql_conditions = []
            params: List[Any] = []

            # 1. Field type constraint
            if target_fields:
                placeholders = ",".join("?" for _ in target_fields)
                sql_conditions.append(f"field_type IN ({placeholders})")
                params.extend(target_fields)

            # 2. Value matching constraint
            if exact:
                sql_conditions.append("(LOWER(raw_value) = ? OR LOWER(normalized_value) = ?)")
                params.extend([query_lower, query_lower])
            else:
                like_expr = f"%{query_lower}%"
                if query_digits and len(query_digits) >= 4 and mode in ["number", "phone", "vehicle"]:
                    digits_like = f"%{query_digits}%"
                    sql_conditions.append(
                        "(LOWER(raw_value) LIKE ? OR LOWER(normalized_value) LIKE ? OR normalized_value LIKE ?)"
                    )
                    params.extend([like_expr, like_expr, digits_like])
                else:
                    sql_conditions.append(
                        "(LOWER(raw_value) LIKE ? OR LOWER(normalized_value) LIKE ? OR LOWER(context_snippet) LIKE ?)"
                    )
                    params.extend([like_expr, like_expr, like_expr])

            where_clause = " AND ".join(sql_conditions) if sql_conditions else "1=1"

            query_sql = f"""
                SELECT id, record_id, field_type, raw_value, normalized_value,
                       source_file, container_id, container_name, line_number,
                       context_snippet, confidence, detector_name, pattern_id, created_at
                FROM entities
                WHERE {where_clause}
                ORDER BY
                    CASE 
                        WHEN LOWER(raw_value) = ? OR LOWER(normalized_value) = ? THEN 1
                        WHEN LOWER(raw_value) LIKE ? OR LOWER(normalized_value) LIKE ? THEN 2
                        ELSE 3
                    END,
                    CASE confidence
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    id DESC
                LIMIT ?
            """
            params.extend([query_lower, query_lower, f"%{query_lower}%", f"%{query_lower}%", limit])

            cursor.execute(query_sql, params)
            matched_entities = [dict(row) for row in cursor.fetchall()]

            # Build correlated record clusters
            correlated_results = self.correlation.build_correlated_response(matched_entities)

            execution_ms = int((time.time() - start_time) * 1000)

            # Log search in audit log
            self.db.log_audit("search_executed", {
                "query": query_clean,
                "mode": mode,
                "custom_field": custom_field,
                "matches": len(correlated_results)
            })

            return {
                "query": query_clean,
                "search_mode": mode,
                "custom_field": custom_field,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "result_count": len(correlated_results),
                "scan_sources": scan_sources,
                "execution_time_ms": execution_ms,
                "results": correlated_results
            }

        finally:
            conn.close()
