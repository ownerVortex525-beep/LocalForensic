"""
Authentication Artifact and Hash Detector for Local Forensic Data Correlation Workbench.
Extracts legacy authentication strings, tokens, credentials, and hash artifacts for forensic review.
Does not perform any active validation or cracking.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class AuthDetector(BaseDetector):
    detector_name = "auth_detector"
    field_types = ["legacy_auth_string_or_hash", "login"]

    AUTH_LABELS = re.compile(
        r'(?i)\b(?:password|pass|passwd|pwd|auth_token|token|secret|api_key|hash|md5|sha256|auth)[\s:=_-]+["\']?([^"\s\r\n|;,]{4,128})["\']?'
    )

    # Common combo format: user:password or email:password
    COMBO_PATTERN = re.compile(
        r'(?i)\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9_.-]{3,32}):([^\s:]{4,64})\b'
    )

    # Common hash strings: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

    LOGIN_LABELS = re.compile(
        r'(?i)\b(?:login|user_login|log_in|signin)[\s:=_-]+["\']?([a-zA-Z0-9_.@-]{3,40})["\']?'
    )

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. Login field
        if self.is_field_enabled("login"):
            for match in self.LOGIN_LABELS.finditer(text):
                raw = match.group(1).strip()
                if 3 <= len(raw) <= 40 and not any(w in raw.lower() for w in ["successful", "failed", "attempt", "true", "false"]):
                    results.append(DetectionResult(
                        field_type="login",
                        raw_value=raw,
                        normalized_value=raw.lower(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="login_labeled_01"
                    ))

        # 2. Labeled auth string or token
        if self.is_field_enabled("legacy_auth_string_or_hash"):
            for match in self.AUTH_LABELS.finditer(text):
                raw = match.group(1).strip()
                if 4 <= len(raw) <= 128 and not any(w in raw.lower() for w in ["null", "none", "required", "true", "false", "undefined"]):
                    results.append(DetectionResult(
                        field_type="legacy_auth_string_or_hash",
                        raw_value=raw,
                        normalized_value=raw,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="auth_labeled_02"
                    ))

            # Combo pattern: user:pass
            for match in self.COMBO_PATTERN.finditer(text):
                user_part, pass_part = match.group(1), match.group(2)
                # Ensure pass_part is not part of a URL (http://...)
                if "http" in text.lower() and ("://" in text):
                    continue
                if not any(r.raw_value == pass_part for r in results):
                    results.append(DetectionResult(
                        field_type="legacy_auth_string_or_hash",
                        raw_value=pass_part,
                        normalized_value=pass_part,
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="auth_combo_03"
                    ))

            # Hex hashes when context contains hash/digest keywords
            lower_text = text.lower()
            if any(k in lower_text for k in ["hash", "md5", "sha1", "sha256", "digest", "ntlm"]):
                for match in self.SHA256_PATTERN.finditer(text):
                    raw = match.group(0)
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="legacy_auth_string_or_hash",
                            raw_value=raw,
                            normalized_value=raw.lower(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="auth_sha256_04"
                        ))

                for match in self.MD5_PATTERN.finditer(text):
                    raw = match.group(0)
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="legacy_auth_string_or_hash",
                            raw_value=raw,
                            normalized_value=raw.lower(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="medium",
                            detector_name=self.detector_name,
                            pattern_id="auth_md5_05"
                        ))

        return results
