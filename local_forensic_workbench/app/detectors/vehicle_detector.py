"""
Vehicle & VIN Detector for Local Forensic Data Correlation Workbench.
Extracts vehicle license plates, registration numbers, and 17-character VINs.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class VehicleDetector(BaseDetector):
    detector_name = "vehicle_detector"
    field_types = ["car_number", "vehicle_registration_number", "vin"]

    # 17-character VIN pattern (excludes I, O, Q)
    VIN_REGEX = re.compile(r'\b([A-HJ-NPR-Z0-9]{17})\b')
    VIN_LABELS = re.compile(r'(?i)\b(?:vin|vehicle_id)[\s:=_-]+["\']?([A-HJ-NPR-Z0-9]{17})["\']?')

    CAR_LABELS = re.compile(
        r'(?i)\b(?:car[_\s]?number|car|license[_\s]?plate|plate|auto[_\s]?number|vehicle_reg)[\s:=_-]+["\']?([A-Za-z\u0400-\u04FF0-9\s-]{4,15})["\']?'
    )

    # Russian license plate pattern (e.g. А123БВ77, A123BC77)
    RU_PLATE_REGEX = re.compile(
        r'\b([А-ЯA-Z]{1}\d{3}[А-ЯA-Z]{2}\d{2,3})\b'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. VIN
        if self.is_field_enabled("vin"):
            for match in self.VIN_LABELS.finditer(text):
                raw = match.group(1).strip()
                results.append(DetectionResult(
                    field_type="vin",
                    raw_value=raw,
                    normalized_value=raw.upper(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="vin_labeled_01"
                ))

            if "vin" in text.lower():
                for match in self.VIN_REGEX.finditer(text):
                    raw = match.group(1).strip()
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="vin",
                            raw_value=raw,
                            normalized_value=raw.upper(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="vin_format_02"
                        ))

        # 2. Car number / Registration
        target_car = "car_number" if self.is_field_enabled("car_number") else "vehicle_registration_number"
        if self.is_field_enabled("car_number") or self.is_field_enabled("vehicle_registration_number"):
            for match in self.CAR_LABELS.finditer(text):
                raw = match.group(1).strip(" ,.-")
                if 4 <= len(raw) <= 15 and not any(w in raw.lower() for w in ["none", "null", "unknown", "valid"]):
                    results.append(DetectionResult(
                        field_type=target_car,
                        raw_value=raw,
                        normalized_value=re.sub(r'[\s-]', '', raw).upper(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="car_labeled_03"
                    ))

            # Russian format plate when car/vehicle context or direct match
            if any(k in text.lower() for k in ["car", "auto", "vehicle", "plate", "госномер", "авто"]):
                for match in self.RU_PLATE_REGEX.finditer(text):
                    raw = match.group(1).strip()
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type=target_car,
                            raw_value=raw,
                            normalized_value=raw.upper(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="car_plate_ru_04"
                        ))

        return results
