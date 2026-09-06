"""
Container Manager for Local Forensic Data Correlation Workbench.
Manages storage containers (file and folder paths) stored in config/containers.json.
Supports 500+ containers, path validation, enabled/disabled toggles, and metadata tracking.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from .models import ContainerModel
from .database import Database
from .utils import get_base_dir

logger = logging.getLogger(__name__)


class ContainerManager:
    def __init__(self, db: Database, config_file: Optional[Path] = None):
        self.db = db
        if config_file is None:
            self.config_file = get_base_dir() / "config" / "containers.json"
        else:
            self.config_file = Path(config_file)
        
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_config_exists()
        self.sync_to_db()

    def _ensure_config_exists(self) -> None:
        if not self.config_file.exists():
            default_data = {
                "containers": [
                    {
                        "id": "container_sample_01",
                        "name": "Local Sample Data",
                        "path": str(get_base_dir() / "data" / "sample"),
                        "type": "folder",
                        "enabled": True,
                        "tags": ["sample", "audit", "local"]
                    }
                ]
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=2)

    def load_containers(self) -> List[ContainerModel]:
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            containers_list: List[ContainerModel] = []
            for item in data.get("containers", []):
                p = Path(item.get("path", ""))
                status = "ready" if p.exists() else "path_not_found"
                containers_list.append(ContainerModel(
                    id=item.get("id"),
                    name=item.get("name", "Unnamed Container"),
                    path=item.get("path", ""),
                    type=item.get("type", "folder"),
                    enabled=item.get("enabled", True),
                    tags=item.get("tags", []),
                    file_count=item.get("file_count", 0),
                    last_scanned=item.get("last_scanned"),
                    parse_errors=item.get("parse_errors", 0),
                    status=status
                ))
            return containers_list
        except Exception as e:
            logger.error(f"Error loading containers from {self.config_file}: {e}")
            return []

    def save_containers(self, containers: List[ContainerModel]) -> None:
        data = {
            "containers": [
                {
                    "id": c.id,
                    "name": c.name,
                    "path": c.path,
                    "type": c.type,
                    "enabled": c.enabled,
                    "tags": c.tags,
                    "file_count": c.file_count,
                    "last_scanned": c.last_scanned,
                    "parse_errors": c.parse_errors
                }
                for c in containers
            ]
        }
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.sync_to_db()

    def sync_to_db(self) -> None:
        containers = self.load_containers()
        conn = self.db.get_connection()
        try:
            with conn:
                for c in containers:
                    conn.execute("""
                        INSERT INTO containers (id, name, path, type, enabled, tags, file_count, last_scanned, parse_errors, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            name=excluded.name,
                            path=excluded.path,
                            type=excluded.type,
                            enabled=excluded.enabled,
                            tags=excluded.tags,
                            file_count=excluded.file_count,
                            last_scanned=excluded.last_scanned,
                            parse_errors=excluded.parse_errors,
                            status=excluded.status
                    """, (
                        c.id, c.name, c.path, c.type, 1 if c.enabled else 0,
                        json.dumps(c.tags), c.file_count, c.last_scanned,
                        c.parse_errors, c.status
                    ))
        finally:
            conn.close()

    def add_container(self, name: str, path: str, c_type: str = "folder", tags: Optional[List[str]] = None, enabled: bool = True) -> ContainerModel:
        containers = self.load_containers()
        new_id = f"container_{len(containers) + 1:03d}"
        
        # Check if ID already exists
        existing_ids = {c.id for c in containers}
        counter = len(containers) + 1
        while new_id in existing_ids:
            counter += 1
            new_id = f"container_{counter:03d}"

        p = Path(path)
        status = "ready" if p.exists() else "path_not_found"

        new_c = ContainerModel(
            id=new_id,
            name=name,
            path=str(p.resolve() if p.exists() else p),
            type=c_type,
            enabled=enabled,
            tags=tags or ["local"],
            file_count=0,
            last_scanned=None,
            parse_errors=0,
            status=status
        )
        containers.append(new_c)
        self.save_containers(containers)
        self.db.log_audit("container_added", {"id": new_id, "name": name, "path": path})
        return new_c

    def remove_container(self, container_id: str) -> bool:
        containers = self.load_containers()
        filtered = [c for c in containers if c.id != container_id]
        if len(filtered) == len(containers):
            return False
        self.save_containers(filtered)
        conn = self.db.get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM containers WHERE id = ?", (container_id,))
                conn.execute("DELETE FROM files WHERE container_id = ?", (container_id,))
                conn.execute("DELETE FROM entities WHERE container_id = ?", (container_id,))
        finally:
            conn.close()
        self.db.log_audit("container_removed", {"id": container_id})
        return True

    def toggle_container(self, container_id: str, enabled: bool) -> bool:
        containers = self.load_containers()
        found = False
        for c in containers:
            if c.id == container_id:
                c.enabled = enabled
                found = True
                break
        if found:
            self.save_containers(containers)
            self.db.log_audit("container_toggled", {"id": container_id, "enabled": enabled})
        return found

    def update_container_stats(self, container_id: str, file_count: int, parse_errors: int, last_scanned: str) -> None:
        containers = self.load_containers()
        for c in containers:
            if c.id == container_id:
                c.file_count = file_count
                c.parse_errors = parse_errors
                c.last_scanned = last_scanned
                break
        self.save_containers(containers)
