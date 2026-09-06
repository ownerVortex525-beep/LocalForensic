"""
Base Detector Module for Local Forensic Data Correlation Workbench.
Provides the DetectionResult model and the BaseDetector abstract class.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import re


@dataclass
class DetectionResult:
    field_type: str
    raw_value: str
    normalized_value: str
    source_file: str
    container_id: str
    container_name: str
    line_number: int
    context_snippet: str
    confidence: str  # 'high', 'medium', 'low'
    detector_name: str
    pattern_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseDetector:
    detector_name: str = "base_detector"
    field_types: List[str] = []

    def __init__(self, enabled_fields: Optional[List[str]] = None):
        self.enabled_fields = enabled_fields or self.field_types

    def is_field_enabled(self, field_type: str) -> bool:
        if not self.enabled_fields:
            return True
        return field_type in self.enabled_fields

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        """
        Inspect the given line of text and return detected items.
        source_meta must contain:
          - source_file: str
          - container_id: str
          - container_name: str
          - context_snippet: str (surrounding context)
        """
        raise NotImplementedError("Subclasses must implement detect()")

    @staticmethod
    def clean_snippet(text: str, max_length: int = 240) -> str:
        snippet = " ".join(text.split())
        if len(snippet) > max_length:
            return snippet[:max_length] + "..."
        return snippet
