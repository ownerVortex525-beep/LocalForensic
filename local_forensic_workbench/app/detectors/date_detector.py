"""
Record Date & Timestamp Detector for Local Forensic Data Correlation Workbench.
Extracts event dates, DOBs, timestamps, and log timestamps.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class DateDetector(BaseDetector):
    detector_name = "date_detector"
    field_types = ["record_date"]

    DATE_LABELS = re.compile(
        r'(?i)\b(?:dob|date[_\s]?of[_\s]?birth|record[_\s]?date|timestamp|passport[_\s]?date|event[_\s]?date)[\s:=_-]+["\']?([0-9]{2,4}[-/.][0-9]{1,2}[-/.][0-9]{1,4}(?:\s+[0-9]{2}:[0-9]{2}:[0-9]{2})?)["\']?'
    )

    # Standard ISO timestamps e.g. [2025-11-04 14:22:01] or 2025-11-04T14:22:01
    TIMESTAMP_LOG = re.compile(
        r'\[?(\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]?'
    )

    ISO_DATE = re.compile(r'\b(\d{4}-\d{2}-\d{2})\b')

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        if not self.is_field_enabled("record_date"):
            return []

        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Labeled date
        for match in self.DATE_LABELS.finditer(text):
            raw = match.group(1).strip()
            results.append(DetectionResult(
                field_type="record_date",
                raw_value=raw,
                normalized_value=raw,
                source_file=source_meta.get("source_file", ""),
                container_id=source_meta.get("container_id", ""),
                container_name=source_meta.get("container_name", ""),
                line_number=line_number,
                context_snippet=self.clean_snippet(snippet),
                confidence="high",
                detector_name=self.detector_name,
                pattern_id="date_labeled_01"
            ))

        # 2. Log timestamps
        for match in self.TIMESTAMP_LOG.finditer(text):
            raw = match.group(1).strip()
            if not any(r.raw_value == raw for r in results):
                results.append(DetectionResult(
                    field_type="record_date",
                    raw_value=raw,
                    normalized_value=raw,
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="timestamp_log_02"
                ))

        return results
