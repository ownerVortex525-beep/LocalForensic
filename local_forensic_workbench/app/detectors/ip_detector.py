"""
IP Address Detector for Local Forensic Data Correlation Workbench.
Extracts IPv4 and IPv6 addresses and validates octet boundaries.
"""

import re
import ipaddress
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class IpDetector(BaseDetector):
    detector_name = "ip_detector"
    field_types = ["ip_address"]

    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    IPV6_PATTERN = re.compile(
        r'(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b'
    )

    IP_LABEL = re.compile(
        r'(?i)\b(?:ip|ip_address|client_ip|host_ip|remote_ip)[\s:=_-]+([0-9a-fA-F:.]+)'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        if not self.is_field_enabled("ip_address"):
            return []

        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Labeled IP match
        for match in self.IP_LABEL.finditer(text):
            raw = match.group(1).strip(" ,;")
            try:
                ip_obj = ipaddress.ip_address(raw)
                results.append(DetectionResult(
                    field_type="ip_address",
                    raw_value=raw,
                    normalized_value=str(ip_obj),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="ip_labeled_01"
                ))
            except ValueError:
                pass

        # 2. Raw IPv4 matches
        for match in self.IPV4_PATTERN.finditer(text):
            raw = match.group(0).strip()
            # Ignore standard subnet masks or loopback unless labeled
            if raw in ["0.0.0.0", "255.255.255.0", "255.255.255.255"]:
                continue
            if not any(r.raw_value == raw for r in results):
                try:
                    ip_obj = ipaddress.ip_address(raw)
                    results.append(DetectionResult(
                        field_type="ip_address",
                        raw_value=raw,
                        normalized_value=str(ip_obj),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="ipv4_standard_02"
                    ))
                except ValueError:
                    pass

        # 3. IPv6 matches
        for match in self.IPV6_PATTERN.finditer(text):
            raw = match.group(0).strip()
            if not any(r.raw_value == raw for r in results):
                try:
                    ip_obj = ipaddress.ip_address(raw)
                    results.append(DetectionResult(
                        field_type="ip_address",
                        raw_value=raw,
                        normalized_value=str(ip_obj),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="ipv6_standard_03"
                    ))
                except ValueError:
                    pass

        return results
