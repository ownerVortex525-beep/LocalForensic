"""
Data models and schemas for Local Forensic Data Correlation Workbench.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import time


@dataclass
class ContainerModel:
    id: str
    name: str
    path: str
    type: str  # 'folder' or 'file'
    enabled: bool
    tags: List[str]
    file_count: int = 0
    last_scanned: Optional[str] = None
    parse_errors: int = 0
    status: str = "configured"  # 'configured', 'ready', 'path_not_found', 'error'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileRecord:
    id: Optional[int]
    container_id: str
    file_path: str
    file_size: int
    modified_time: float
    file_hash: str
    status: str
    scanned_at: str
    entity_count: int = 0


@dataclass
class EntityRecord:
    id: Optional[int]
    record_id: str
    field_type: str
    raw_value: str
    normalized_value: str
    source_file: str
    container_id: str
    line_number: int
    context_snippet: str
    confidence: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
