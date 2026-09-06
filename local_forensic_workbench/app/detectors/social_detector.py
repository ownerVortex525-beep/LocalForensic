"""
Social Identifier Detector for Local Forensic Data Correlation Workbench.
Extracts VK IDs, Steam IDs, Telegram handles, Facebook IDs, and Instagram handles.
Local pattern extraction only; never contacts external platforms.
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionResult


class SocialDetector(BaseDetector):
    detector_name = "social_detector"
    field_types = [
        "vk_id",
        "steam_id",
        "facebook_id",
        "telegram_id",
        "instagram_identifier"
    ]

    VK_PATTERN = re.compile(r'(?i)\b(?:vk[_\s]?id|vk)[\s:=_-]+["\']?(?:vk\.com/)?(id\d+|\d+|[a-zA-Z0-9_.]+)["\']?')
    STEAM_PATTERN = re.compile(r'(?i)\b(?:steam[_\s]?id|steamid)[\s:=_-]+["\']?([a-zA-Z0-9_:\[\]]+)["\']?')
    STEAM_STANDARD = re.compile(r'\b(STEAM_[0-5]:[01]:\d+|\[U:1:\d+\]|\d{17})\b')
    FB_PATTERN = re.compile(r'(?i)\b(?:facebook[_\s]?id|facebook|fb[_\s]?id|fb)[\s:=_-]+["\']?(?:facebook\.com/)?([a-zA-Z0-9_.]+)["\']?')
    TELEGRAM_PATTERN = re.compile(r'(?i)\b(?:telegram|tg)[\s:=_-]+["\']?(?:t\.me/)?(@?[a-zA-Z0-9_]{3,35})["\']?')
    INSTAGRAM_PATTERN = re.compile(r'(?i)\b(?:instagram|insta|ig)[\s:=_-]+["\']?(?:instagram\.com/)?(@?[a-zA-Z0-9_.-]{3,35})["\']?')

    def detect(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        snippet = source_meta.get("context_snippet", text)

        # 1. VK ID
        if self.is_field_enabled("vk_id"):
            for match in self.VK_PATTERN.finditer(text):
                raw = match.group(1).strip()
                if 2 <= len(raw) <= 40:
                    results.append(DetectionResult(
                        field_type="vk_id",
                        raw_value=raw,
                        normalized_value=raw.lower(),
                        source_file=source_meta.get("source_file", ""),
                        container_id=source_meta.get("container_id", ""),
                        container_name=source_meta.get("container_name", ""),
                        line_number=line_number,
                        context_snippet=self.clean_snippet(snippet),
                        confidence="high",
                        detector_name=self.detector_name,
                        pattern_id="vk_id_label_01"
                    ))

        # 2. Steam ID
        if self.is_field_enabled("steam_id"):
            for match in self.STEAM_PATTERN.finditer(text):
                raw = match.group(1).strip()
                results.append(DetectionResult(
                    field_type="steam_id",
                    raw_value=raw,
                    normalized_value=raw.upper(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="steam_id_label_02"
                ))

            if "steam" in text.lower():
                for match in self.STEAM_STANDARD.finditer(text):
                    raw = match.group(1).strip()
                    if not any(r.raw_value == raw for r in results):
                        results.append(DetectionResult(
                            field_type="steam_id",
                            raw_value=raw,
                            normalized_value=raw.upper(),
                            source_file=source_meta.get("source_file", ""),
                            container_id=source_meta.get("container_id", ""),
                            container_name=source_meta.get("container_name", ""),
                            line_number=line_number,
                            context_snippet=self.clean_snippet(snippet),
                            confidence="high",
                            detector_name=self.detector_name,
                            pattern_id="steam_id_format_03"
                        ))

        # 3. Telegram ID
        if self.is_field_enabled("telegram_id"):
            for match in self.TELEGRAM_PATTERN.finditer(text):
                raw = match.group(1).strip()
                norm = raw if raw.startswith("@") else f"@{raw}"
                results.append(DetectionResult(
                    field_type="telegram_id",
                    raw_value=raw,
                    normalized_value=norm.lower(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="telegram_label_04"
                ))

        # 4. Instagram
        if self.is_field_enabled("instagram_identifier"):
            for match in self.INSTAGRAM_PATTERN.finditer(text):
                raw = match.group(1).strip()
                norm = raw.lstrip("@").lower()
                results.append(DetectionResult(
                    field_type="instagram_identifier",
                    raw_value=raw,
                    normalized_value=norm,
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="instagram_label_05"
                ))

        # 5. Facebook ID
        if self.is_field_enabled("facebook_id"):
            for match in self.FB_PATTERN.finditer(text):
                raw = match.group(1).strip()
                results.append(DetectionResult(
                    field_type="facebook_id",
                    raw_value=raw,
                    normalized_value=raw.lower(),
                    source_file=source_meta.get("source_file", ""),
                    container_id=source_meta.get("container_id", ""),
                    container_name=source_meta.get("container_name", ""),
                    line_number=line_number,
                    context_snippet=self.clean_snippet(snippet),
                    confidence="high",
                    detector_name=self.detector_name,
                    pattern_id="facebook_label_06"
                ))

        return results
