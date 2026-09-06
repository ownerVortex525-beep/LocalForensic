"""
Command Line Interface for Local Forensic Data Correlation Workbench.
Provides interactive menu, container controls, scanning engine, forensic lookups,
correlation viewer, and exporters with Rich support and pure Python fallback.
"""

import sys
import os
import time
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

from .database import Database
from .container_manager import ContainerManager
from .scanner import ForensicScanner
from .correlation import CorrelationEngine
from .search import ForensicSearchEngine
from .exporters import ForensicExporter
from .detectors import ALL_FIELD_TYPES, DetectorEngine
from .utils import get_base_dir

# Optional Rich support with fallback
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None


def print_cyber_header():
    title = """
========================================================================
     LOCAL FORENSIC DATA CORRELATION WORKBENCH v1.0.0
     Authorized Digital Forensics, Discovery & Privacy Audit System
========================================================================
    """
    if HAS_RICH:
        console.print(Panel(
            Text("LOCAL FORENSIC DATA CORRELATION WORKBENCH\nAuthorized Digital Forensics, Discovery & Privacy Audit System", justify="center", style="bold cyan"),
            border_style="bright_blue"
        ))
    else:
        print(title)


def print_table(title: str, headers: List[str], rows: List[List[str]]):
    if HAS_RICH:
        table = Table(title=title, border_style="blue", show_header=True, header_style="bold bright_cyan")
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        console.print(table)
    else:
        print(f"\n--- {title} ---")
        header_line = " | ".join(f"{h:<20}" for h in headers)
        print(header_line)
        print("-" * len(header_line))
        for row in rows:
            print(" | ".join(f"{str(cell):<20}" for cell in row))
        print()


class CLIController:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or get_base_dir()
        self.db = Database(self.base_dir / "data" / "index.db")
        self.container_mgr = ContainerManager(self.db, self.base_dir / "config" / "containers.json")
        self.detector_engine = DetectorEngine()
        self.correlation_engine = CorrelationEngine(self.db)
        self.scanner = ForensicScanner(self.db, self.container_mgr, self.detector_engine)
        self.search_engine = ForensicSearchEngine(self.db, self.correlation_engine)
        self.exporter = ForensicExporter(self.db)

    def init_workbench(self):
        print("[*] Initializing workbench directories and config...")
        (self.base_dir / "config").mkdir(parents=True, exist_ok=True)
        (self.base_dir / "data" / "sample").mkdir(parents=True, exist_ok=True)
        (self.base_dir / "logs").mkdir(parents=True, exist_ok=True)
        self.db.init_db()
        self.container_mgr._ensure_config_exists()
        
        # Generate sample data
        try:
            from tests.generate_sample_data import generate_all_samples
            generate_all_samples(self.base_dir)
        except ImportError:
            try:
                import importlib.util
                gen_path = self.base_dir / "tests" / "generate_sample_data.py"
                spec = importlib.util.spec_from_file_location("generate_sample_data", str(gen_path))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    mod.generate_all_samples(self.base_dir)
            except Exception as e:
                print(f"[-] Note: sample generation warning: {e}")
        print("[+] Initialization complete. Ready to scan or start server.")

    def show_status(self):
        stats = self.db.get_stats()
        rows = [
            ["Total Storage Containers", str(stats["total_containers"])],
            ["Active Enabled Containers", str(stats["active_containers"])],
            ["Total Files Indexed", str(stats["total_files_scanned"])],
            ["Total Entities Extracted", str(stats["total_entities"])],
            ["Correlated Record Clusters", str(stats["total_records"])],
            ["Last Scan Time", str(stats["last_scan_time"])],
            ["Database Size", f"{stats['db_size_bytes'] / 1024:.1f} KB"]
        ]
        print_table("SYSTEM STATUS & FORENSIC INDEX", ["Metric", "Value"], rows)

    def container_cmd(self, action: str, args: argparse.Namespace):
        if action == "list":
            containers = self.container_mgr.load_containers()
            rows = []
            for c in containers:
                status_str = "[OK] Ready" if c.status == "ready" else "[!] Path Not Found"
                enabled_str = "YES" if c.enabled else "NO"
                rows.append([c.id, c.name, c.path, c.type, enabled_str, str(c.file_count), status_str])
            print_table("MANAGED STORAGE CONTAINERS (500+ Capacity)", ["ID", "Name", "Path", "Type", "Enabled", "Files", "Status"], rows)

        elif action == "add":
            if not getattr(args, "path", None):
                print("[-] Error: --path is required to add container.")
                return
            name = getattr(args, "name", None) or Path(args.path).name or "Container"
            c_type = "file" if Path(args.path).is_file() else "folder"
            c = self.container_mgr.add_container(name, args.path, c_type)
            print(f"[+] Container created: {c.id} ({c.name}) -> {c.path}")

        elif action == "remove":
            c_id = getattr(args, "id", None)
            if not c_id:
                print("[-] Error: --id is required.")
                return
            if self.container_mgr.remove_container(c_id):
                print(f"[+] Container {c_id} removed.")
            else:
                print(f"[-] Container {c_id} not found.")

        elif action == "enable":
            c_id = getattr(args, "id", None)
            if self.container_mgr.toggle_container(c_id, True):
                print(f"[+] Container {c_id} enabled.")
            else:
                print(f"[-] Container {c_id} not found.")

        elif action == "disable":
            c_id = getattr(args, "id", None)
            if self.container_mgr.toggle_container(c_id, False):
                print(f"[+] Container {c_id} disabled.")
            else:
                print(f"[-] Container {c_id} not found.")

    def run_scan(self, container_id: Optional[str] = None, force: bool = False):
        print(f"[*] Launching forensic scan (force={force}, container={container_id or 'all enabled'})...")
        job_id = self.scanner.start_scan_async(container_id=container_id, force=force)

        # Monitor in CLI with progress reporting
        while True:
            status = self.scanner.get_scan_status()
            if status.get("status") in ["completed", "stopped", "error"]:
                break
            pct = status.get("progress_pct", 0)
            scanned = status.get("files_scanned", 0)
            total = status.get("total_files", 0)
            found = status.get("entities_found", 0)
            cur = status.get("current_file", "")
            if len(cur) > 50:
                cur = "..." + cur[-47:]
            sys.stdout.write(f"\r[*] Progress: {pct}% | Files: {scanned}/{total} | Entities: {found} | {cur:<50}")
            sys.stdout.flush()
            time.sleep(0.3)

        print("\n[+] Scan finished successfully.")
        self.show_status()

    def run_search(self, query: str, mode: str = "global", as_json: bool = False, limit: int = 50):
        result = self.search_engine.execute_search(query, mode=mode, limit=limit)
        if as_json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return

        print(f"\n[*] Query: '{query}' | Mode: {mode.upper()} | Execution: {result['execution_time_ms']}ms | Matches: {result['result_count']}")
        if not result["results"]:
            print("[-] No correlated matches found.")
            return

        for idx, rec in enumerate(result["results"], start=1):
            prim = rec["primary_match"]
            print(f"\n[{idx}] RECORD CLUSTER ID: {rec['record_id']}")
            print(f"    Primary Match : [{prim['field_type'].upper()}] {prim['raw_value']} (Confidence: {prim['confidence'].upper()})")
            print(f"    Source File   : {prim['source_file']}:{prim['line_number']} (Container: {prim['container_name']})")
            print("    Connected Data:")
            for field, val in rec.get("connected_fields", {}).items():
                if field != prim["field_type"]:
                    print(f"      * {field:<24}: {val}")
            print(f"    Context Snippet: {prim['context_snippet'][:120]}...")

    def show_record(self, record_id: str, as_json: bool = False):
        cluster = self.correlation_engine.get_record_cluster(record_id)
        if not cluster:
            print(f"[-] Record not found: {record_id}")
            return
        if as_json:
            print(json.dumps(cluster, indent=2, ensure_ascii=False))
            return

        print(f"\n================ CORRELATED RECORD: {record_id} ================")
        prim = cluster["primary_match"]
        print(f"Primary Source: {prim['source_file']} (Line {prim['line_number']})")
        print(f"Container     : {prim['container_name']} ({prim['container_id']})")
        print(f"Snippet       :\n    {prim['context_snippet']}\n")
        
        rows = []
        for ent in cluster["all_entities"]:
            rows.append([ent["field_type"], ent["raw_value"], ent["confidence"], str(ent["line_number"])])
        print_table("EXTRACTED RECORD ENTITIES", ["Field Type", "Raw Value", "Confidence", "Line"], rows)

    def export_cmd(self, query: Optional[str] = None, mode: str = "global", record_id: Optional[str] = None, out_path: Optional[str] = None):
        if record_id:
            cluster = self.correlation_engine.get_record_cluster(record_id)
            if not cluster:
                print(f"[-] Record not found: {record_id}")
                return
            json_str = self.exporter.export_record(cluster, Path(out_path) if out_path else None)
        elif query:
            res = self.search_engine.execute_search(query, mode=mode, limit=500)
            json_str = self.exporter.export_search_results(res, Path(out_path) if out_path else None)
        else:
            rep = self.exporter.export_full_report()
            json_str = json.dumps(rep, indent=2, ensure_ascii=False)
            if out_path:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(json_str)

        if out_path:
            print(f"[+] Forensic export written to: {out_path}")
        else:
            print(json_str)

    def show_logs(self, limit: int = 50):
        logs = self.db.get_audit_logs(limit)
        rows = []
        for l in logs:
            rows.append([str(l["id"]), l["timestamp"], l["action"], str(l["details"])[:60]])
        print_table("LOCAL AUDIT & INVESTIGATION LOGS", ["ID", "Timestamp", "Action", "Details"], rows)

    def interactive_menu(self):
        print_cyber_header()
        while True:
            print("\nCOMMAND MENU:")
            print("  1. Dashboard & Status")
            print("  2. Manage Containers (List / Add / Remove / Toggle)")
            print("  3. Run Forensic Scan")
            print("  4. Global Search")
            print("  5. Field-Specific Lookup (Email / Phone / Name / Document / etc.)")
            print("  6. View Record Cluster by ID")
            print("  7. Export Audit Results")
            print("  8. Start Web Server (127.0.0.1:8080)")
            print("  9. View Local Audit Logs")
            print("  0. Exit")
            choice = input("\nSelect option [0-9]: ").strip()

            if choice == "1":
                self.show_status()
            elif choice == "2":
                self.container_cmd("list", argparse.Namespace())
                sub = input("Action (a: add, r: remove, e: enable, d: disable, Enter: back): ").strip().lower()
                if sub == "a":
                    p = input("Path to file or folder: ").strip()
                    n = input("Container name: ").strip()
                    self.container_cmd("add", argparse.Namespace(path=p, name=n))
                elif sub == "r":
                    cid = input("Container ID: ").strip()
                    self.container_cmd("remove", argparse.Namespace(id=cid))
                elif sub == "e":
                    cid = input("Container ID: ").strip()
                    self.container_cmd("enable", argparse.Namespace(id=cid))
                elif sub == "d":
                    cid = input("Container ID: ").strip()
                    self.container_cmd("disable", argparse.Namespace(id=cid))
            elif choice == "3":
                force = input("Force full rescan? (y/N): ").strip().lower() == "y"
                self.run_scan(force=force)
            elif choice == "4":
                q = input("Search query: ").strip()
                if q:
                    self.run_search(q, mode="global")
            elif choice == "5":
                print("Modes: email, phone, name, address, passport, username, ip, domain, social, auth, vehicle, number")
                m = input("Select mode: ").strip().lower() or "global"
                q = input("Query: ").strip()
                if q:
                    self.run_search(q, mode=m)
            elif choice == "6":
                rid = input("Record ID: ").strip()
                if rid:
                    self.show_record(rid)
            elif choice == "7":
                q = input("Query to export (or leave empty for full report): ").strip()
                out = input("Output file path (e.g. audit_export.json): ").strip() or "audit_export.json"
                self.export_cmd(query=q if q else None, out_path=out)
            elif choice == "8":
                port = input("Port [default 8080]: ").strip()
                p_num = int(port) if port.isdigit() else 8080
                from .server import run_server
                run_server(port=p_num)
            elif choice == "9":
                self.show_logs()
            elif choice == "0":
                print("[*] Exiting workbench. Goodbye.")
                break
            else:
                print("[-] Invalid selection.")
