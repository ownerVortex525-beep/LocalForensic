"""
Phone & WhatsApp Detector for Local Forensic Data Correlation Workbench.
Extracts phone numbers and WhatsApp identifiers with digit normalization.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class PhoneDetector(BaseDetector):
    detector_name = "phone_detector"
    field_types = ["phone_number", "whatsapp_number"]

    # International and national phone patterns
    PHONE_REGEX = re.compile(
        r'(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,5}\b'
    )
    
    WHATSAPP_LABEL = re.compile(r'(?i)\b(?:whatsapp|wa|wapp)[\s:=_-]*([+]?[\d\s().-]{7,20})')
    PHONE_LABEL = re.compile(r'(?i)\b(?:phone|tel|mobile|cell|contact|fone)[\s:=_-]*([+]?[\d\s().-]{7,20})')

    def normalize_phone(self, raw: str) -> str:
        has_plus = raw.strip().startswith("+")
        digits = re.sub(r'\D', '', raw)
        return f"+{digits}" if has_plus else digits

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. WhatsApp with explicit keyword
        if self.is_field_enabled("whatsapp_number"):
            for match in self.WHATSAPP_LABEL.finditer(text):
                raw = match.group(1).strip()
                normalized = self.normalize_phone(raw)
                digits = re.sub(r'\D', '', raw)
                if 7 <= len(digits) <= 15:
                    results.append(DetectionResult(
                        field_type="whatsapp_number",
                        raw_value=raw,
                        normalized_value=normalized,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="phone_whatsapp_label_01"
                    ))

        # 2. Labeled phone numbers
        if self.is_field_enabled("phone_number"):
            for match in self.PHONE_LABEL.finditer(text):
                raw = match.group(1).strip()
                normalized = self.normalize_phone(raw)
                digits = re.sub(r'\D', '', raw)
                if 7 <= len(digits) <= 15:
                    # Avoid duplicate if already matched by whatsapp
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="phone_number",
                            raw_value=raw,
                            normalized_value=normalized,
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="phone_labeled_02"
                        ))

            # 3. Formatted standalone phone patterns (e.g. +79161234567, +1-555-000-0000, (415) 555-2671)
            for match in self.PHONE_REGEX.finditer(text):
                raw = match.group(0).strip(".,;:- ")
                digits = re.sub(r'\D', '', raw)
                if 9 <= len(digits) <= 15:
                    # Filter out dates or version numbers or simple long numbers without punctuation if not international
                    if not (raw.startswith("+") or "-" in raw or "(" in raw or " " in raw or "." in raw):
                        continue
                    if any(r.raw_value == raw for r in results):
                        continue
                    # Ensure it doesn't look like an IP or date
                    if re.match(r'^\d{4}[-/.]\d{2}[-/.]\d{2}', raw):
                        continue
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', raw):
                        continue

                    normalized = self.normalize_phone(raw)
                    conf = "high" if raw.startswith("+") else "medium"
                    results.append(DetectionResult(
                        field_type="phone_number",
                        raw_value=raw,
                        normalized_value=normalized,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence=conf,
                        detector_name=self.detector_name,
                        pattern_id="phone_intl_format_03"
                    ))

        return results
