"""
Company & Organization Detector for Local Forensic Data Correlation Workbench.
Extracts company names, employers, ISPs, and organization identifiers.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class CompanyDetector(BaseDetector):
    detector_name = "company_detector"
    field_types = ["company_name"]

    COMPANY_LABELS = re.compile(
        r'(?i)\b(?:company[_\s]?name|company|organization|org|employer|isp|network|carrier|business)[\s:=_-]+["\']?([^"\r\n,;|]{3,60})["\']?'
    )

    CORP_SUFFIX = re.compile(
        r'(?i)\b([A-Z][a-zA-Z0-9\s&.-]{2,40}\s+(?:Inc\.?|LLC|Corp\.?|Ltd\.?|GmbH|Co\.?|Technologies|Group|Wireless|Telecom))\b'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        if not self.is_field_enabled("company_name"):
            return []

        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Labeled company / ISP / Network
        for match in self.COMPANY_LABELS.finditer(text):
            raw = match.group(1).strip(" ,.-")
            if 3 <= len(raw) <= 50 and not any(w in raw.lower() for w in ["none", "null", "unknown", "n/a", "false", "true"]):
                results.append(DetectionResult(
                    field_type="company_name",
                    raw_value=raw,
                    normalized_value=" ".join(raw.split()).title(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="company_labeled_01"
                ))

        # 2. Corporate suffix heuristics
        for match in self.CORP_SUFFIX.finditer(text):
            raw = match.group(1).strip(" ,.-")
            if not any(r.raw_value == raw for r in results):
                results.append(DetectionResult(
                    field_type="company_name",
                    raw_value=raw,
                    normalized_value=" ".join(raw.split()).title(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="medium",
                    detector_name=self.detector_name,
                    pattern_id="company_suffix_02"
                ))

        return results
