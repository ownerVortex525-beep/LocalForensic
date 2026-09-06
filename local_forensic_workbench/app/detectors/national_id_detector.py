"""
National ID, SSN, Taxpayer ID, and SNILS Detector for Local Forensic Data Correlation Workbench.
Extracts social security numbers, taxpayer IDs (EIN/INN), SNILS, and national identification numbers.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class NationalIdDetector(BaseDetector):
    detector_name = "national_id_detector"
    field_types = [
        "national_id_number",
        "ssn_pattern",
        "taxpayer_id_number",
        "snils_or_social_reference_number"
    ]

    # US SSN regex: 3 digits - 2 digits - 4 digits
    SSN_REGEX = re.compile(r'\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b')
    SSN_LABELS = re.compile(r'(?i)\b(?:ssn|social[_\s]?security)[\s:=_-]+([0-9-]{9,11})')

    # SNILS regex: 123-456-789 00 or 123-456-789-00
    SNILS_REGEX = re.compile(r'\b(\d{3}-\d{3}-\d{3}[\s-]\d{2})\b')
    SNILS_LABELS = re.compile(r'(?i)\b(?:snils|снилс)[\s:=_-]+["\']?([0-9\s-]{11,14})["\']?')

    # Taxpayer ID (EIN: 12-3456789 or Russian INN: 10 or 12 digits)
    EIN_REGEX = re.compile(r'\b(\d{2}-\d{7})\b')
    TAX_LABELS = re.compile(r'(?i)\b(?:taxpayer[_\s]?id|tax[_\s]?id|ein|inn|инн)[\s:=_-]+["\']?([0-9-]{9,15})["\']?')

    # National ID label
    NAT_ID_LABELS = re.compile(r'(?i)\b(?:national[_\s]?id|id[_\s]?card|citizen[_\s]?id|identity[_\s]?no)[\s:=_-]+["\']?([A-Za-z0-9-]{6,20})["\']?')

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. SSN
        if self.is_field_enabled("ssn_pattern"):
            for match in self.SSN_REGEX.finditer(text):
                raw = match.group(0).strip()
                conf = "high" if any(k in text.lower() for k in ["ssn", "social", "security"]) else "medium"
                results.append(DetectionResult(
                    field_type="ssn_pattern",
                    raw_value=raw,
                    normalized_value=re.sub(r'\D', '', raw),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence=conf,
                    detector_name=self.detector_name,
                    pattern_id="ssn_standard_01"
                ))

            for match in self.SSN_LABELS.finditer(text):
                raw = match.group(1).strip()
                digits = re.sub(r'\D', '', raw)
                if len(digits) == 9 and not any(r.raw_value == raw for r in results):
                    results.append(DetectionResult(
                        field_type="ssn_pattern",
                        raw_value=raw,
                        normalized_value=digits,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="ssn_labeled_02"
                    ))

        # 2. SNILS / Social reference
        if self.is_field_enabled("snils_or_social_reference_number"):
            for match in self.SNILS_REGEX.finditer(text):
                raw = match.group(1).strip()
                results.append(DetectionResult(
                    field_type="snils_or_social_reference_number",
                    raw_value=raw,
                    normalized_value=re.sub(r'\D', '', raw),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="snils_regex_03"
                ))

            for match in self.SNILS_LABELS.finditer(text):
                raw = match.group(1).strip()
                digits = re.sub(r'\D', '', raw)
                if len(digits) == 11 and not any(r.raw_value == raw for r in results):
                    results.append(DetectionResult(
                        field_type="snils_or_social_reference_number",
                        raw_value=raw,
                        normalized_value=digits,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="snils_labeled_04"
                    ))

        # 3. Taxpayer ID / INN / EIN
        if self.is_field_enabled("taxpayer_id_number"):
            for match in self.TAX_LABELS.finditer(text):
                raw = match.group(1).strip()
                digits = re.sub(r'\D', '', raw)
                if 9 <= len(digits) <= 12:
                    results.append(DetectionResult(
                        field_type="taxpayer_id_number",
                        raw_value=raw,
                        normalized_value=digits,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="tax_labeled_05"
                    ))

            for match in self.EIN_REGEX.finditer(text):
                raw = match.group(1).strip()
                if any(k in text.lower() for k in ["tax", "ein", "irs", "company", "biz"]):
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="taxpayer_id_number",
                            raw_value=raw,
                            normalized_value=re.sub(r'\D', '', raw),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="ein_regex_06"
                        ))

        # 4. National ID
        if self.is_field_enabled("national_id_number"):
            for match in self.NAT_ID_LABELS.finditer(text):
                raw = match.group(1).strip()
                if 6 <= len(raw) <= 20 and not any(w in raw.lower() for w in ["unknown", "none", "null"]):
                    results.append(DetectionResult(
                        field_type="national_id_number",
                        raw_value=raw,
                        normalized_value=re.sub(r'[\s-]', '', raw).upper(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="national_id_labeled_07"
                    ))

        return results
