"""
Fast JSON IPC Bridge for Local Forensic Data Correlation Workbench.
Allows web frontends (Next.js / Node.js) to query Python forensic engines with zero external networking.
"""

import sys
import json
import argparse
from pathlib import Path

# Add package directory to sys.path
base_dir = Path(__file__).resolve().parent.parent
if str(base_dir) not in sys.path:
    sys.path.insert(0, str(base_dir))

from app.database import Database
from app.container_manager import ContainerManager
from app.detectors import ALL_FIELD_TYPES, DetectorEngine
from app.correlation import CorrelationEngine
from app.scanner import ForensicScanner
from app.search import ForensicSearchEngine
from app.exporters import ForensicExporter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", help="Bridge action")
    parser.add_argument("--payload", help="JSON payload string")
    parser.add_argument("--query", default="")
    parser.add_argument("--mode", default="global")
    parser.add_argument("--field", default=None)
    parser.add_argument("--record-id", default="")
    parser.add_argument("--container-id", default="")
    parser.add_argument("--name", default="")
    parser.add_argument("--path", default="")
    parser.add_argument("--type", default="folder")
    parser.add_argument("--exact", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--enable", default="true")
    parser.add_argument("--limit", type=int, default=100)

    args = parser.parse_args()

    db = Database(base_dir / "data" / "index.db")
    container_mgr = ContainerManager(db, base_dir / "config" / "containers.json")
    detector_engine = DetectorEngine()
    correlation_engine = CorrelationEngine(db)
    scanner = ForensicScanner(db, container_mgr, detector_engine)
    search_engine = ForensicSearchEngine(db, correlation_engine)
    exporter = ForensicExporter(db)

    try:
        if args.action == "status":
            stats = db.get_stats()
            scan_status = scanner.get_scan_status()
            res = {
                "system": "Local Forensic Data Correlation Workbench",
                "version": "1.0.0",
                "stats": stats,
                "scan_status": scan_status,
                "field_types": ALL_FIELD_TYPES
            }
            print(json.dumps(res))

        elif args.action == "containers_list":
            containers = container_mgr.load_containers()
            print(json.dumps([c.to_dict() for c in containers]))

        elif args.action == "container_add":
            c = container_mgr.add_container(args.name or Path(args.path).name, args.path, args.type)
            print(json.dumps(c.to_dict()))

        elif args.action == "container_toggle":
            is_en = args.enable.lower() == "true"
            success = container_mgr.toggle_container(args.container_id, is_en)
            print(json.dumps({"success": success, "id": args.container_id, "enabled": is_en}))

        elif args.action == "container_remove":
            success = container_mgr.remove_container(args.container_id)
            print(json.dumps({"success": success, "id": args.container_id}))

        elif args.action == "scan_sync":
            # Run scan synchronously and output result
            job_id = scanner.start_scan_async(container_id=args.container_id or None, force=args.force)
            if scanner.scan_thread:
                scanner.scan_thread.join(timeout=30)
            status = scanner.get_scan_status()
            stats = db.get_stats()
            print(json.dumps({"job_id": job_id, "status": status, "stats": stats}))

        elif args.action == "scan_status":
            print(json.dumps(scanner.get_scan_status()))

        elif args.action == "search":
            results = search_engine.execute_search(
                query=args.query,
                mode=args.mode,
                custom_field=args.field,
                exact=args.exact,
                limit=args.limit
            )
            print(json.dumps(results))

        elif args.action == "record":
            cluster = correlation_engine.get_record_cluster(args.record_id)
            print(json.dumps(cluster or {"error": "Record not found"}))

        elif args.action == "export_report":
            rep = exporter.export_full_report()
            print(json.dumps(rep))

        elif args.action == "logs":
            logs = db.get_audit_logs(args.limit)
            print(json.dumps(logs))

        elif args.action == "init_samples":
            from tests.generate_sample_data import generate_all_samples
            generate_all_samples(base_dir)
            # Re-scan to index
            job_id = scanner.start_scan_async(force=True)
            if scanner.scan_thread:
                scanner.scan_thread.join(timeout=30)
            print(json.dumps({"status": "initialized", "stats": db.get_stats()}))

        else:
            print(json.dumps({"error": f"Unknown action {args.action}"}))

    except Exception as e:
        print(json.dumps({"error": str(e)}))


if __name__ == "__main__":
    main()
