"""
Name & Contact Person Detector for Local Forensic Data Correlation Workbench.
Extracts individual full names, Russian FIOs, and contact persons.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class NameDetector(BaseDetector):
    detector_name = "name_detector"
    field_types = ["full_name", "contact_person"]

    NAME_LABELS = re.compile(
        r'(?i)\b(?:full[_\s]?name|fio|name|contact[_\s]?person|customer|profile[_\s]?name|client)[\s:=_-]+["\']?([A-Za-z\u0400-\u04FF]{2,30}(?:\s+[A-Za-z\u0400-\u04FF]{1,30}){1,3})["\']?'
    )

    CONTACT_LABELS = re.compile(
        r'(?i)\b(?:contact[_\s]?person|contact|representative|agent)[\s:=_-]+["\']?([A-Za-z\u0400-\u04FF]{2,30}(?:\s+[A-Za-z\u0400-\u04FF]{1,30}){1,3})["\']?'
    )

    # Relative or named roles: Mother: Sarah Mercer, Father: David Mercer
    RELATION_LABELS = re.compile(
        r'(?i)\b(?:mother|father|relative|spouse|partner)[\s:=_-]+["\']?([A-Za-z\u0400-\u04FF]{2,30}(?:\s+[A-Za-z\u0400-\u04FF]{1,30}){1,3})["\']?'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Contact person
        if self.is_field_enabled("contact_person"):
            for match in self.CONTACT_LABELS.finditer(text):
                raw = match.group(1).strip()
                if 3 <= len(raw) <= 50 and not any(w in raw.lower() for w in ["unknown", "n/a", "none", "null", "admin"]):
                    results.append(DetectionResult(
                        field_type="contact_person",
                        raw_value=raw,
                        normalized_value=" ".join(raw.split()).title(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="name_contact_label_01"
                    ))

        # 2. Full Name from labeled attributes
        if self.is_field_enabled("full_name"):
            for match in self.NAME_LABELS.finditer(text):
                raw = match.group(1).strip()
                if 3 <= len(raw) <= 50 and not any(w in raw.lower() for w in ["unknown", "n/a", "none", "null", "true", "false"]):
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="full_name",
                            raw_value=raw,
                            normalized_value=" ".join(raw.split()).title(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="name_labeled_02"
                        ))

            for match in self.RELATION_LABELS.finditer(text):
                raw = match.group(1).strip()
                if 3 <= len(raw) <= 50:
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="full_name",
                            raw_value=raw,
                            normalized_value=" ".join(raw.split()).title(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="medium",
                            detector_name=self.detector_name,
                            pattern_id="name_relation_03"
                        ))

        return results
