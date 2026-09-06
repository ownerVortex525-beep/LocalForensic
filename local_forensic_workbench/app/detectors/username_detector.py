"""
Username, Nickname, and Account Identifier Detector for Local Forensic Data Correlation Workbench.
Extracts usernames, handles, nicknames, and system account identifiers.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class UsernameDetector(BaseDetector):
    detector_name = "username_detector"
    field_types = ["username", "nickname", "account_identifier"]

    USER_LABELS = re.compile(
        r'(?i)\b(?:username|user|user_name|login_name|account_name)[\s:=_-]+["\']?([a-zA-Z0-9_.-]{3,35})["\']?'
    )

    NICK_LABELS = re.compile(
        r'(?i)\b(?:nickname|nick|handle|screen_name|alias)[\s:=_-]+["\']?([a-zA-Z0-9_.-]{3,35})["\']?'
    )

    ACCOUNT_LABELS = re.compile(
        r'(?i)\b(?:uid|account[_\s]?id|account_no|member_id|client_id)[\s:=_-]+["\']?([a-zA-Z0-9_.-]{4,40})["\']?'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Nickname
        if self.is_field_enabled("nickname"):
            for match in self.NICK_LABELS.finditer(text):
                raw = match.group(1).strip()
                if not any(w in raw.lower() for w in ["none", "null", "unknown", "admin"]):
                    results.append(DetectionResult(
                        field_type="nickname",
                        raw_value=raw,
                        normalized_value=raw.lower(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="nick_labeled_01"
                    ))

        # 2. Username
        if self.is_field_enabled("username"):
            for match in self.USER_LABELS.finditer(text):
                raw = match.group(1).strip()
                if not any(w in raw.lower() for w in ["none", "null", "unknown", "login", "successful"]):
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="username",
                            raw_value=raw,
                            normalized_value=raw.lower(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="user_labeled_02"
                        ))

        # 3. Account identifier
        if self.is_field_enabled("account_identifier"):
            for match in self.ACCOUNT_LABELS.finditer(text):
                raw = match.group(1).strip()
                if not any(r.raw_value == raw for r in results):
                    results.append(DetectionResult(
                        field_type="account_identifier",
                        raw_value=raw,
                        normalized_value=raw.lower(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="account_labeled_03"
                    ))

        return results
