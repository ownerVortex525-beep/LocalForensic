"""
Application and Device Identifier Detector for Local Forensic Data Correlation Workbench.
Extracts software application names, mobile packages, device models, and hardware identifiers.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class AppDetector(BaseDetector):
    detector_name = "app_detector"
    field_types = ["app_identifier", "device_identifier"]

    APP_LABELS = re.compile(
        r'(?i)\b(?:app(?:lication)?|software|client[_\s]?app|package)[\s:=_-]+["\']?([a-zA-Z0-9_.\s-]{2,40})["\']?'
    )

    DEVICE_LABELS = re.compile(
        r'(?i)\b(?:device|hardware|model|phone[_\s]?model|handset|device[_\s]?id|imei)[\s:=_-]+["\']?([a-zA-Z0-9_.\s-]{3,50})["\']?'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. App identifier
        if self.is_field_enabled("app_identifier"):
            for match in self.APP_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-|")
                if 2 <= len(raw) <= 40 and not any(w in raw.lower() for w in ["none", "null", "unknown", "open", "running"]):
                    results.append(DetectionResult(
                        field_type="app_identifier",
                        raw_value=raw,
                        normalized_value=" ".join(raw.split()),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="app_labeled_01"
                    ))

        # 2. Device identifier
        if self.is_field_enabled("device_identifier"):
            for match in self.DEVICE_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-|")
                if 3 <= len(raw) <= 50 and not any(w in raw.lower() for w in ["none", "null", "unknown"]):
                    results.append(DetectionResult(
                        field_type="device_identifier",
                        raw_value=raw,
                        normalized_value=" ".join(raw.split()),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="device_labeled_02"
                    ))

        return results
