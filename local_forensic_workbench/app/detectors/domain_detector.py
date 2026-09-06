"""
Domain and URL Detector for Local Forensic Data Correlation Workbench.
Extracts fully qualified domain names and HTTP/HTTPS URLs.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from .base import BaseDetector, DetectionResult


class DomainDetector(BaseDetector):
    detector_name = "domain_detector"
    field_types = ["domain_name", "url_link"]

    URL_PATTERN = re.compile(
        r'(?i)\b(https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\'>]*)?)\b'
    )

    # Valid domain extensions to prevent catching file names like foo.txt, config.json
    COMMON_TLDS = (
        "com|org|net|edu|gov|mil|io|co|ai|dev|app|ru|uk|de|fr|ca|au|in|cn|jp|me|info|biz|site|online|xyz"
    )

    DOMAIN_PATTERN = re.compile(
        r'(?i)\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:' + COMMON_TLDS + r')\b'
    )

    DOMAIN_LABEL = re.compile(
        r'(?i)\b(?:domain|host|website|portal)[\s:=_-]+["\']?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,10})["\']?'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. URL Links
        if self.is_field_enabled("url_link"):
            for match in self.URL_PATTERN.finditer(text):
                raw = match.group(1).rstrip(".,;)>'\"")
                results.append(DetectionResult(
                    field_type="url_link",
                    raw_value=raw,
                    normalized_value=raw.strip(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="url_http_01"
                ))

        # 2. Domains
        if self.is_field_enabled("domain_name"):
            # Labeled domain
            for match in self.DOMAIN_LABEL.finditer(text):
                raw = match.group(1).strip()
                if not any(r.raw_value == raw for r in results):
                    results.append(DetectionResult(
                        field_type="domain_name",
                        raw_value=raw,
                        normalized_value=raw.lower(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="domain_labeled_02"
                    ))

            # Pattern domain
            for match in self.DOMAIN_PATTERN.finditer(text):
                raw = match.group(0).strip(".,;:/")
                # Exclude if it was part of an email address
                if f"@{raw}" in text or raw.startswith("@"):
                    continue
                # Exclude common false positives
                if any(raw.lower().endswith(ext) for ext in [".txt", ".json", ".xml", ".csv", ".log", ".py", ".js"]):
                    continue
                if not any(r.raw_value == raw for r in results):
                    results.append(DetectionResult(
                        field_type="domain_name",
                        raw_value=raw,
                        normalized_value=raw.lower(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="medium",
                        detector_name=self.detector_name,
                        pattern_id="domain_pattern_03"
                    ))

        return results
