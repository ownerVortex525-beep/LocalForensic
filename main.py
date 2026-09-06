#!/usr/bin/env python3
"""
Root entrypoint delegating to local_forensic_workbench.
"""
import sys
from pathlib import Path

pkg_dir = Path(__file__).resolve().parent / "local_forensic_workbench"
sys.path.insert(0, str(pkg_dir))

from main import main

if __name__ == "__main__":
    main()
