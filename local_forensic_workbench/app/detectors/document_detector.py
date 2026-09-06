"""
Passport and Identity Document Detector for Local Forensic Data Correlation Workbench.
Extracts passport numbers, national passports, driver's licenses, and document IDs.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class DocumentDetector(BaseDetector):
    detector_name = "document_detector"
    field_types = [
        "passport_number",
        "passport_or_document_number",
        "document_number"
    ]

    PASSPORT_LABELS = re.compile(
        r'(?i)\b(?:passport|pass[_\s]?no|passport[_\s]?num(?:ber)?)[\s:=_-]+["\']?([A-Za-z0-9\s-]{6,20})["\']?'
    )

    DOCUMENT_LABELS = re.compile(
        r'(?i)\b(?:document|doc[_\s]?no|doc|driver[_\s]?license|dl|license)[\s:=_-]+["\']?([A-Za-z0-9\s-]{5,25})["\']?'
    )

    # Russian internal passport series/number: 4 digits, space/dash, 6 digits
    RU_PASSPORT = re.compile(r'\b(\d{2}\s?\d{2}[\s-]\d{6})\b')

    # Standard international passport pattern: letter followed by 7-9 digits
    INTL_PASSPORT = re.compile(r'\b([A-Z][0-9]{7,9})\b')

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Labeled Passports
        if self.is_field_enabled("passport_number") or self.is_field_enabled("passport_or_document_number"):
            for match in self.PASSPORT_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-")
                if 5 <= len(raw) <= 20 and not any(w in raw.lower() for w in ["none", "null", "unknown", "valid"]):
                    norm = re.sub(r'[\s-]', '', raw).upper()
                    target_field = "passport_number" if self.is_field_enabled("passport_number") else "passport_or_document_number"
                    results.append(DetectionResult(
                        field_type=target_field,
                        raw_value=raw,
                        normalized_value=norm,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="passport_labeled_01"
                    ))

        # 2. Labeled general documents / driver licenses
        if self.is_field_enabled("document_number") or self.is_field_enabled("passport_or_document_number"):
            for match in self.DOCUMENT_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-")
                if 5 <= len(raw) <= 25 and not any(w in raw.lower() for w in ["none", "null", "unknown", "open", "file"]):
                    norm = re.sub(r'[\s]', '', raw).upper()
                    target_field = "document_number" if self.is_field_enabled("document_number") else "passport_or_document_number"
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type=target_field,
                            raw_value=raw,
                            normalized_value=norm,
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="doc_labeled_02"
                        ))

        # 3. Contextual Regex (Russian passport or International passport)
        if self.is_field_enabled("passport_number") or self.is_field_enabled("passport_or_document_number"):
            for match in self.RU_PASSPORT.finditer(text):
                raw = match.group(1).strip()
                if not any(r.raw_value == raw for r in results):
                    # Higher confidence if passport word in context
                    conf = "high" if "passport" in text.lower() or "пасп" in text.lower() else "medium"
                    target_field = "passport_number" if self.is_field_enabled("passport_number") else "passport_or_document_number"
                    results.append(DetectionResult(
                        field_type=target_field,
                        raw_value=raw,
                        normalized_value=re.sub(r'[\s-]', '', raw),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence=conf,
                        detector_name=self.detector_name,
                        pattern_id="passport_ru_format_03"
                    ))

        return results
