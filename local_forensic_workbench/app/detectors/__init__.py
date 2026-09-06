"""
Detector Engine Registry for Local Forensic Data Correlation Workbench.
Loads and coordinates all modular detectors across plain text, logs, and structured documents.
"""

from typing import List, Dict, Any, Optional
from .base import BaseDetector, DetectionResult
from .email_detector import EmailDetector
from .phone_detector import PhoneDetector
from .name_detector import NameDetector
from .address_detector import AddressDetector
from .document_detector import DocumentDetector
from .national_id_detector import NationalIdDetector
from .auth_detector import AuthDetector
from .username_detector import UsernameDetector
from .ip_detector import IpDetector
from .domain_detector import DomainDetector
from .social_detector import SocialDetector
from .vehicle_detector import VehicleDetector
from .company_detector import CompanyDetector
from .app_detector import AppDetector
from .date_detector import DateDetector

ALL_FIELD_TYPES = [
    "email",
    "full_name",
    "phone_number",
    "address",
    "username",
    "login",
    "nickname",
    "legacy_auth_string_or_hash",
    "passport_number",
    "passport_or_document_number",
    "document_number",
    "national_id_number",
    "ssn_pattern",
    "taxpayer_id_number",
    "vk_id",
    "steam_id",
    "facebook_id",
    "telegram_id",
    "instagram_identifier",
    "whatsapp_number",
    "ip_address",
    "domain_name",
    "url_link",
    "company_name",
    "contact_person",
    "car_number",
    "vehicle_registration_number",
    "vin",
    "snils_or_social_reference_number",
    "app_identifier",
    "device_identifier",
    "account_identifier",
    "record_date",
    "location_name"
]


class DetectorEngine:
    def __init__(self, enabled_fields: Optional[List[str]] = None):
        self.enabled_fields = enabled_fields if enabled_fields is not None else list(ALL_FIELD_TYPES)
        self.detectors: List[BaseDetector] = [
            EmailDetector(self.enabled_fields),
            PhoneDetector(self.enabled_fields),
            NameDetector(self.enabled_fields),
            AddressDetector(self.enabled_fields),
            DocumentDetector(self.enabled_fields),
            NationalIdDetector(self.enabled_fields),
            AuthDetector(self.enabled_fields),
            UsernameDetector(self.enabled_fields),
            IpDetector(self.enabled_fields),
            DomainDetector(self.enabled_fields),
            SocialDetector(self.enabled_fields),
            VehicleDetector(self.enabled_fields),
            CompanyDetector(self.enabled_fields),
            AppDetector(self.enabled_fields),
            DateDetector(self.enabled_fields),
        ]

    def update_enabled_fields(self, enabled_fields: List[str]) -> None:
        self.enabled_fields = enabled_fields
        for detector in self.detectors:
            detector.enabled_fields = enabled_fields

    def scan_line(self, text: str, line_number: int, source_meta: Dict[str, Any]) -> List[DetectionResult]:
        """Runs all enabled detectors against a line or text segment."""
        matches: List[DetectionResult] = []
        if not text or not text.strip():
            return matches

        for detector in self.detectors:
            try:
                found = detector.detect(text, line_number, source_meta)
                if found:
                    matches.extend(found)
            except Exception:
                # Keep scanner robust against regex timeouts or malformed patterns
                continue

        return matches
