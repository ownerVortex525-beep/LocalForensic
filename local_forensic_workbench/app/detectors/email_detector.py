"""
Email Detector for Local Forensic Data Correlation Workbench.
Extracts and normalizes email addresses.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class EmailDetector(BaseDetector):
    detector_name = "email_detector"
    field_types = ["email"]

    # RFC-compliant practical email regex
    EMAIL_REGEX = re.compile(
        r'(?i)\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        if not self.is_field_enabled("email"):
            return []

        results: List[DetectionResult] = []
        for match in self.EMAIL_REGEX.finditer(text):
            raw = match.group(1).strip(".,;:()")
            if not raw or ".." in raw or raw.endswith("."):
                continue

            # Check if domain has at least one period
            parts = raw.split("@")
            if len(parts) != 2 or "." not in parts[1]:
                continue

            normalized = raw.lower()
            snippet = source_meta.get("context_snippet", text)

            results.append(DetectionResult(
                field_type="email",
                raw_value=raw,
                normalized_value=normalized,
                source_file=source_meta.get("source_file", ""),
                container_id=source_meta.get("container_id", ""),
                container_name=source_meta.get("container_name", ""),
                line_number=line_number,
                context_snippet=self.clean_snippet(snippet),
                confidence="high",
                detector_name=self.detector_name,
                pattern_id="email_standard_01"
            ))

        return results
