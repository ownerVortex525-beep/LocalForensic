"""
High-Performance Local File Scanner for Local Forensic Data Correlation Workbench.
Streams text files, parses CSV/JSON/XML/Logs, applies modular detectors, groups records,
and writes indexed entities to SQLite with change detection.
"""

import os
import csv
import json
import time
import logging
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from xml.etree import ElementTree as ET

from .database import Database
from .models import ContainerModel
from .container_manager import ContainerManager
from .detectors import DetectorEngine
from .detectors.base import DetectionResult
from .utils import is_binary_file, read_file_safely, compute_file_hash, generate_record_id, get_base_dir

logger = logging.getLogger(__name__)


class ForensicScanner:
    def __init__(self, db: Database, container_mgr: ContainerManager, detector_engine: Optional[DetectorEngine] = None):
        self.db = db
        self.container_mgr = container_mgr
        self.detector_engine = detector_engine or DetectorEngine()
        self.is_scanning = False
        self.stop_requested = False
        self.scan_thread: Optional[threading.Thread] = None
        self.current_job: Dict[str, Any] = {
            "status": "idle",
            "progress_pct": 0,
            "current_file": "",
            "files_scanned": 0,
            "total_files": 0,
            "entities_found": 0,
            "errors_count": 0,
            "started_at": None,
            "elapsed_seconds": 0
        }
        self._lock = threading.Lock()

    def get_scan_status(self) -> Dict[str, Any]:
        with self._lock:
            status_copy = dict(self.current_job)
            if self.is_scanning and status_copy.get("started_at"):
                status_copy["elapsed_seconds"] = round(time.time() - status_copy["started_at"], 1)
            return status_copy

    def stop_scan(self) -> None:
        with self._lock:
            if self.is_scanning:
                self.stop_requested = True
                self.current_job["status"] = "stopping"

    def start_scan_async(self, container_id: Optional[str] = None, force: bool = False, context_window: int = 15) -> str:
        with self._lock:
            if self.is_scanning:
                return "Scan is already in progress"
            self.is_scanning = True
            self.stop_requested = False
            job_id = f"job_{int(time.time())}"
            self.current_job = {
                "job_id": job_id,
                "status": "running",
                "progress_pct": 0,
                "current_file": "Initializing scan...",
                "files_scanned": 0,
                "total_files": 0,
                "entities_found": 0,
                "errors_count": 0,
                "started_at": time.time(),
                "elapsed_seconds": 0
            }

        thread = threading.Thread(
            target=self._run_scan_worker,
            args=(job_id, container_id, force, context_window),
            daemon=True
        )
        self.scan_thread = thread
        thread.start()
        return job_id

    def _run_scan_worker(self, job_id: str, target_container_id: Optional[str], force: bool, context_window: int) -> None:
        start_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self.db.get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO scan_jobs (job_id, container_id, status, started_at) VALUES (?, ?, 'running', ?)",
                    (job_id, target_container_id or "all", start_ts)
                )
        finally:
            conn.close()

        containers = self.container_mgr.load_containers()
        if target_container_id:
            containers = [c for c in containers if c.id == target_container_id]
        else:
            containers = [c for c in containers if c.enabled]

        # Gather target files
        all_targets: List[tuple[ContainerModel, Path]] = []
        for c in containers:
            c_path = Path(c.path)
            if not c_path.exists():
                logger.warning(f"Container path does not exist: {c_path}")
                continue
            if c_path.is_file():
                all_targets.append((c, c_path))
            elif c_path.is_dir():
                for root, _, filenames in os.walk(c_path):
                    for fname in filenames:
                        f_path = Path(root) / fname
                        all_targets.append((c, f_path))

        with self._lock:
            self.current_job["total_files"] = len(all_targets)

        total_files = len(all_targets)
        scanned_count = 0
        entities_count = 0
        errors_count = 0

        for idx, (container, file_path) in enumerate(all_targets):
            if self.stop_requested:
                break

            with self._lock:
                self.current_job["current_file"] = str(file_path)
                self.current_job["files_scanned"] = scanned_count
                self.current_job["progress_pct"] = int((idx / max(total_files, 1)) * 100)

            try:
                # 1. Skip binary files
                if is_binary_file(file_path):
                    continue

                # 2. Incremental check
                stat_info = file_path.stat()
                file_size = stat_info.st_size
                mod_time = stat_info.st_mtime
                current_hash = compute_file_hash(file_path)

                if not force:
                    conn = self.db.get_connection()
                    try:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT modified_time, file_hash FROM files WHERE file_path = ?",
                            (str(file_path),)
                        )
                        existing = cursor.fetchone()
                        if existing and existing["modified_time"] == mod_time and existing["file_hash"] == current_hash:
                            scanned_count += 1
                            continue
                    finally:
                        conn.close()

                # 3. Parse and extract entities
                file_entities = self._scan_single_file(file_path, container, context_window)
                
                # 4. Save to database in batch
                self._save_file_scan_results(file_path, container, file_size, mod_time, current_hash, file_entities)
                
                entities_count += len(file_entities)
                scanned_count += 1
                with self._lock:
                    self.current_job["entities_found"] = entities_count

            except Exception as e:
                errors_count += 1
                logger.error(f"Error scanning {file_path}: {e}")
                with self._lock:
                    self.current_job["errors_count"] = errors_count

        # Complete job
        end_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        final_status = "stopped" if self.stop_requested else "completed"
        with self._lock:
            self.is_scanning = False
            self.current_job["status"] = final_status
            self.current_job["progress_pct"] = 100
            self.current_job["files_scanned"] = scanned_count
            self.current_job["current_file"] = "Scan finished"

        conn = self.db.get_connection()
        try:
            with conn:
                conn.execute("""
                    UPDATE scan_jobs
                    SET status = ?, completed_at = ?, files_scanned = ?, entities_found = ?, errors_count = ?
                    WHERE job_id = ?
                """, (final_status, end_ts, scanned_count, entities_count, errors_count, job_id))
        finally:
            conn.close()

        # Update container stats
        for c in containers:
            conn = self.db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM files WHERE container_id = ?", (c.id,))
                cnt = cursor.fetchone()[0]
                self.container_mgr.update_container_stats(c.id, cnt, errors_count, end_ts)
            finally:
                conn.close()

        self.db.log_audit("scan_job_finished", {
            "job_id": job_id,
            "status": final_status,
            "files_scanned": scanned_count,
            "entities_found": entities_count
        })

    def _scan_single_file(self, file_path: Path, container: ContainerModel, context_window: int) -> List[DetectionResult]:
        ext = file_path.suffix.lower()
        if ext == ".json":
            return self._scan_json_file(file_path, container)
        elif ext == ".csv":
            return self._scan_csv_file(file_path, container)
        elif ext in [".xml", ".html", ".htm"]:
            return self._scan_xml_file(file_path, container)
        else:
            return self._scan_text_file(file_path, container, context_window)

    def _scan_text_file(self, file_path: Path, container: ContainerModel, context_window: int) -> List[DetectionResult]:
        """Scans plain text with sliding window context buffering."""
        results: List[DetectionResult] = []
        lines_buffer: List[tuple[int, str]] = []

        for line_no, line in read_file_safely(file_path):
            lines_buffer.append((line_no, line))
            if len(lines_buffer) > (context_window * 2 + 1):
                lines_buffer.pop(0)

            # Build surrounding context window
            snippet = "".join([l[1] for l in lines_buffer[-10:]])
            meta = {
                "source_file": str(file_path),
                "container_id": container.id,
                "container_name": container.name,
                "context_snippet": snippet
            }
            matches = self.detector_engine.scan_line(line, line_no, meta)
            results.extend(matches)

        return results

    def _scan_json_file(self, file_path: Path, container: ContainerModel) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            def recurse_json(node: Any, path_prefix: str, line_est: int):
                if isinstance(node, dict):
                    # Group whole dict as one record context
                    snippet = json.dumps(node, ensure_ascii=False)[:300]
                    for k, v in node.items():
                        meta = {
                            "source_file": str(file_path),
                            "container_id": container.id,
                            "container_name": container.name,
                            "context_snippet": snippet
                        }
                        if isinstance(v, (dict, list)):
                            recurse_json(v, f"{path_prefix}.{k}", line_est + 1)
                        else:
                            text_repr = f"{k}: {v}"
                            matches = self.detector_engine.scan_line(text_repr, line_est, meta)
                            results.extend(matches)
                elif isinstance(node, list):
                    for idx, item in enumerate(node):
                        recurse_json(item, f"{path_prefix}[{idx}]", line_est + idx + 1)

            recurse_json(data, "root", 1)
        except Exception:
            # Fallback to plain text scan if JSON is malformed
            return self._scan_text_file(file_path, container, context_window=10)

        return results

    def _scan_csv_file(self, file_path: Path, container: ContainerModel) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                headers = []
                for row_idx, row in enumerate(reader, start=1):
                    if row_idx == 1:
                        headers = row
                        continue
                    # Group row fields with headers
                    row_text_parts = []
                    for c_idx, cell in enumerate(row):
                        header_name = headers[c_idx] if c_idx < len(headers) else f"col_{c_idx}"
                        row_text_parts.append(f"{header_name}: {cell}")
                    
                    row_line = " | ".join(row_text_parts)
                    meta = {
                        "source_file": str(file_path),
                        "container_id": container.id,
                        "container_name": container.name,
                        "context_snippet": row_line[:300]
                    }
                    matches = self.detector_engine.scan_line(row_line, row_idx, meta)
                    results.extend(matches)
        except Exception:
            return self._scan_text_file(file_path, container, context_window=10)

        return results

    def _scan_xml_file(self, file_path: Path, container: ContainerModel) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                tree = ET.parse(f)
                root = tree.getroot()

                for idx, elem in enumerate(root.iter(), start=1):
                    elem_text = elem.text.strip() if elem.text else ""
                    tag_line = f"{elem.tag}: {elem_text}"
                    if elem.attrib:
                        tag_line += f" {json.dumps(elem.attrib)}"
                    
                    meta = {
                        "source_file": str(file_path),
                        "container_id": container.id,
                        "container_name": container.name,
                        "context_snippet": tag_line[:300]
                    }
                    matches = self.detector_engine.scan_line(tag_line, idx, meta)
                    results.extend(matches)
        except Exception:
            return self._scan_text_file(file_path, container, context_window=10)

        return results

    def _save_file_scan_results(self, file_path: Path, container: ContainerModel, file_size: int,
                                mod_time: float, file_hash: str, entities: List[DetectionResult]) -> None:
        scan_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self.db.get_connection()
        try:
            with conn:
                # Remove previous entries for this file to support clean update
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM files WHERE file_path = ?", (str(file_path),))
                prev = cursor.fetchone()
                if prev:
                    conn.execute("DELETE FROM entities WHERE source_file = ?", (str(file_path),))
                    conn.execute("DELETE FROM records WHERE source_file = ?", (str(file_path),))

                conn.execute("""
                    INSERT INTO files (container_id, file_path, file_size, modified_time, file_hash, status, scanned_at, entity_count)
                    VALUES (?, ?, ?, ?, ?, 'indexed', ?, ?)
                    ON CONFLICT(file_path) DO UPDATE SET
                        container_id=excluded.container_id,
                        file_size=excluded.file_size,
                        modified_time=excluded.modified_time,
                        file_hash=excluded.file_hash,
                        status='indexed',
                        scanned_at=excluded.scanned_at,
                        entity_count=excluded.entity_count
                """, (container.id, str(file_path), file_size, mod_time, file_hash, scan_ts, len(entities)))

                if not entities:
                    return

                # Group entities into record clusters based on line proximity
                # Entities within 15 lines of each other in same file share record_id
                entities.sort(key=lambda e: e.line_number)
                clusters: List[List[DetectionResult]] = []
                current_cluster: List[DetectionResult] = []

                for ent in entities:
                    if not current_cluster:
                        current_cluster.append(ent)
                    else:
                        prev_line = current_cluster[-1].line_number
                        if abs(ent.line_number - prev_line) <= 15:
                            current_cluster.append(ent)
                        else:
                            clusters.append(current_cluster)
                            current_cluster = [ent]
                if current_cluster:
                    clusters.append(current_cluster)

                # Insert records and entities
                records_data = []
                entities_data = []

                for cluster in clusters:
                    lead_ent = cluster[0]
                    rec_id = generate_record_id(
                        str(file_path), container.id, lead_ent.line_number, lead_ent.raw_value
                    )
                    records_data.append((
                        rec_id, container.id, str(file_path), lead_ent.line_number, scan_ts
                    ))

                    for ent in cluster:
                        entities_data.append((
                            rec_id, ent.field_type, ent.raw_value, ent.normalized_value,
                            ent.source_file, ent.container_id, ent.container_name,
                            ent.line_number, ent.context_snippet, ent.confidence,
                            ent.detector_name, ent.pattern_id, scan_ts
                        ))

                conn.executemany("""
                    INSERT OR IGNORE INTO records (record_id, container_id, source_file, line_number, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, records_data)

                conn.executemany("""
                    INSERT INTO entities (
                        record_id, field_type, raw_value, normalized_value, source_file,
                        container_id, container_name, line_number, context_snippet,
                        confidence, detector_name, pattern_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, entities_data)
        finally:
            conn.close()
