"""
Utility helpers for Local Forensic Data Correlation Workbench.
Cross-platform file I/O, binary detection, hashing, and redaction.
"""

import os
import hashlib
from pathlib import Path
from typing import Optional, Generator, Tuple


def get_base_dir() -> Path:
    """Returns root directory of local_forensic_workbench."""
    return Path(__file__).resolve().parent.parent


def is_binary_file(file_path: Path, sample_size: int = 4096) -> bool:
    """
    Safely inspect file prefix to detect binary/executable/compressed formats.
    Returns True if null bytes or excessive non-printable control characters are found.
    """
    try:
        if not file_path.exists() or file_path.is_dir():
            return False
        
        # Check known binary extensions
        bin_extensions = {
            ".exe", ".dll", ".so", ".bin", ".iso", ".zip", ".tar", ".gz",
            ".7z", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf",
            ".docx", ".xlsx", ".pptx", ".mp3", ".mp4", ".wav", ".avi",
            ".mkv", ".pyc", ".class", ".o", ".obj", ".wasm"
        }
        if file_path.suffix.lower() in bin_extensions:
            return True

        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            if not chunk:
                return False
            # Check for null byte
            if b"\x00" in chunk:
                return True
            # Check ratio of non-printable bytes
            text_characters = bytes(range(32, 127)) + b"\n\r\t\b"
            non_text = sum(1 for byte in chunk if byte not in text_characters)
            if non_text / len(chunk) > 0.30:
                return True
            return False
    except Exception:
        return True


def read_file_safely(file_path: Path) -> Generator[Tuple[int, str], None, None]:
    """
    Safely stream lines from a file using UTF-8 with fallback to latin-1.
    Never loads entire massive files into memory at once.
    Yields (line_number, line_content).
    """
    encodings = ["utf-8", "latin-1", "cp1252", "cp1251"]
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc, errors="replace") as f:
                for line_no, line in enumerate(f, start=1):
                    yield line_no, line
            return
        except Exception:
            continue


def compute_file_hash(file_path: Path, max_bytes: int = 1024 * 1024) -> str:
    """Computes quick SHA256 of file header and size for change detection."""
    try:
        hasher = hashlib.sha256()
        file_size = file_path.stat().st_size
        hasher.update(str(file_size).encode("utf-8"))
        with open(file_path, "rb") as f:
            hasher.update(f.read(max_bytes))
        return hasher.hexdigest()
    except Exception:
        return ""


def generate_record_id(source_file: str, container_id: str, line_no: int, seed_value: str = "") -> str:
    """Creates a stable local hash for record cluster identification."""
    data = f"{container_id}:{source_file}:{line_no}:{seed_value}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:24]


def apply_redaction(value: str, field_type: str) -> str:
    """
    Redacts sensitive values when redaction toggle is active.
    Default behavior is unredacted as specified in Section 3 & 15.
    """
    if not value or len(value) <= 4:
        return "****"
    if "@" in value:
        user, domain = value.split("@", 1)
        return f"{user[:2]}***@{domain}"
    if field_type in ["legacy_auth_string_or_hash", "ssn_pattern", "passport_number"]:
        return f"{value[:2]}******{value[-2:]}"
    return f"{value[:3]}***{value[-2:]}"
