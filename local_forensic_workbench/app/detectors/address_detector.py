"""
Address & Location Detector for Local Forensic Data Correlation Workbench.
Extracts residential, postal addresses and geographic location names.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class AddressDetector(BaseDetector):
    detector_name = "address_detector"
    field_types = ["address", "location_name"]

    ADDRESS_LABELS = re.compile(
        r'(?i)\b(?:address|addr|residence|location|street[_\s]?address)[\s:=_-]+["\']?([^"\n\r;]{8,120})["\']?'
    )

    LOCATION_LABELS = re.compile(
        r'(?i)\b(?:city|country|state|region|location|province)[\s:=_-]+["\']?([^"\n\r;|]{2,50})["\']?'
    )

    # Street keywords: Street, St, Avenue, Ave, Blvd, Road, Rd, Way, Drive, Dr, Lane, Ln, Apt, Flat
    STREET_PATTERN = re.compile(
        r'(?i)\b\d{1,5}\s+[A-Za-z0-9\s.,#-]{4,60}\s+(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Way|Drive|Dr\.?|Lane|Ln\.?|Highway|Hwy\.?)\b'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Labeled addresses
        if self.is_field_enabled("address"):
            for match in self.ADDRESS_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-")
                if len(raw) >= 6 and not any(w in raw.lower() for w in ["unknown", "null", "none", "http", "api/"]):
                    results.append(DetectionResult(
                        field_type="address",
                        raw_value=raw,
                        normalized_value=" ".join(raw.split()),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="address_labeled_01"
                    ))

            # 2. Structural street pattern
            for match in self.STREET_PATTERN.finditer(text):
                raw = match.group(0).strip(" ,.-")
                if not any(r.raw_value == raw for r in results):
                    results.append(DetectionResult(
                        field_type="address",
                        raw_value=raw,
                        normalized_value=" ".join(raw.split()),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="medium",
                        detector_name=self.detector_name,
                        pattern_id="address_street_regex_02"
                    ))

        # 3. Location / City / Country names
        if self.is_field_enabled("location_name"):
            for match in self.LOCATION_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-|")
                if 2 <= len(raw) <= 50 and not any(w in raw.lower() for w in ["unknown", "null", "none", "true", "false"]):
                    # Avoid duplicated address matches
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="location_name",
                            raw_value=raw,
                            normalized_value=" ".join(raw.split()).title(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="location_labeled_03"
                        ))

        return results
