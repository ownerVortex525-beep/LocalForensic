"""
SQLite Database Layer for Local Forensic Data Correlation Workbench.
Handles persistent index, entity storage, record clusters, fast lookup, and audit logs.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from .utils import get_base_dir


class Database:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = get_base_dir() / "data" / "index.db"
        else:
            self.db_path = Path(db_path)
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency between web server and scanner
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        conn = self.get_connection()
        try:
            with conn:
                conn.executescript("""
                CREATE TABLE IF NOT EXISTS containers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    type TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    tags TEXT,
                    file_count INTEGER DEFAULT 0,
                    last_scanned TEXT,
                    parse_errors INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'configured'
                );

                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    container_id TEXT NOT NULL,
                    file_path TEXT NOT NULL UNIQUE,
                    file_size INTEGER NOT NULL,
                    modified_time REAL NOT NULL,
                    file_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    entity_count INTEGER DEFAULT 0,
                    FOREIGN KEY (container_id) REFERENCES containers(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS records (
                    record_id TEXT PRIMARY KEY,
                    container_id TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL,
                    field_type TEXT NOT NULL,
                    raw_value TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    container_id TEXT NOT NULL,
                    container_name TEXT,
                    line_number INTEGER NOT NULL,
                    context_snippet TEXT,
                    confidence TEXT NOT NULL,
                    detector_name TEXT,
                    pattern_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (record_id) REFERENCES records(record_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS entity_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL,
                    source_entity_id INTEGER NOT NULL,
                    target_entity_id INTEGER NOT NULL,
                    link_type TEXT DEFAULT 'context_cooccurrence',
                    FOREIGN KEY (record_id) REFERENCES records(record_id) ON DELETE CASCADE,
                    FOREIGN KEY (source_entity_id) REFERENCES entities(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_entity_id) REFERENCES entities(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    container_id TEXT,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    files_scanned INTEGER DEFAULT 0,
                    entities_found INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    log_output TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    operator TEXT DEFAULT 'analyst',
                    details TEXT,
                    timestamp TEXT NOT NULL
                );

                -- Performance Indexes
                CREATE INDEX IF NOT EXISTS idx_entities_record_id ON entities(record_id);
                CREATE INDEX IF NOT EXISTS idx_entities_field_type ON entities(field_type);
                CREATE INDEX IF NOT EXISTS idx_entities_norm_val ON entities(normalized_value);
                CREATE INDEX IF NOT EXISTS idx_entities_raw_val ON entities(raw_value);
                CREATE INDEX IF NOT EXISTS idx_entities_container ON entities(container_id);
                CREATE INDEX IF NOT EXISTS idx_files_path ON files(file_path);
                CREATE INDEX IF NOT EXISTS idx_files_container ON files(container_id);
                CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
                """)
        finally:
            conn.close()

    def log_audit(self, action: str, details: Any, operator: str = "analyst") -> None:
        conn = self.get_connection()
        try:
            with conn:
                det_str = json.dumps(details) if not isinstance(details, str) else details
                conn.execute(
                    "INSERT INTO audit_logs (action, operator, details, timestamp) VALUES (?, ?, ?, datetime('now'))",
                    (action, operator, det_str)
                )
        except Exception:
            pass
        finally:
            conn.close()

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_stats(self) -> Dict[str, Any]:
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM containers WHERE enabled = 1")
            active_containers = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM containers")
            total_containers = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM files")
            total_files = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM entities")
            total_entities = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM records")
            total_records = cursor.fetchone()[0]

            cursor.execute("SELECT completed_at FROM scan_jobs WHERE status = 'completed' ORDER BY started_at DESC LIMIT 1")
            last_scan_row = cursor.fetchone()
            last_scan = last_scan_row[0] if last_scan_row and last_scan_row[0] else None

            return {
                "active_containers": active_containers,
                "total_containers": total_containers,
                "total_files_scanned": total_files,
                "total_entities": total_entities,
                "total_records": total_records,
                "last_scan_time": last_scan or "Never",
                "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0
            }
        finally:
            conn.close()

    def insert_entity(
        self,
        record_id: str,
        field_type: str,
        raw_value: str,
        normalized_value: str,
        source_file: str,
        container_id: str,
        container_name: str,
        line_number: int,
        context_snippet: str,
        confidence: str = "high",
        detector_name: str = "test",
        pattern_id: str = "test"
    ) -> int:
        conn = self.get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO records (record_id, container_id, source_file, line_number, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    (record_id, container_id, source_file, line_number)
                )
                cur = conn.execute("""
                    INSERT INTO entities (
                        record_id, field_type, raw_value, normalized_value,
                        source_file, container_id, container_name, line_number,
                        context_snippet, confidence, detector_name, pattern_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (
                    record_id, field_type, raw_value, normalized_value,
                    source_file, container_id, container_name, line_number,
                    context_snippet, confidence, detector_name, pattern_id
                ))
                return cur.lastrowid
        finally:
            conn.close()

