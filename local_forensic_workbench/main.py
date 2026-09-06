#!/usr/bin/env python3
"""
Local Forensic Data Correlation Workbench
Main Entrypoint for CLI and Server Operations.
"""

import sys
import argparse
from pathlib import Path

# Add current directory to python path
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from app.cli import CLIController
from app.server import run_server


def main():
    parser = argparse.ArgumentParser(
        description="Local Forensic Data Correlation Workbench - Authorized Digital Forensics & Audit System"
    )
    subparsers = parser.add_subparsers(dest="command", help="Workbench Command")

    # menu
    subparsers.add_parser("menu", help="Show interactive command menu")

    # init
    subparsers.add_parser("init", help="Initialize folders, configuration, database, and synthetic sample data")

    # status
    subparsers.add_parser("status", help="Show database status, containers, files, and entity statistics")

    # logs
    subparsers.add_parser("logs", help="Display local audit logs")

    # sample
    subparsers.add_parser("sample", help="Generate synthetic sample test files")

    # container
    container_parser = subparsers.add_parser("container", help="Container management")
    container_sub = container_parser.add_subparsers(dest="action")
    container_sub.add_parser("list", help="List all configured containers")
    
    add_p = container_sub.add_parser("add", help="Add a new container")
    add_p.add_argument("--path", required=True, help="Path to file or directory")
    add_p.add_argument("--name", default=None, help="Descriptive container name")

    rem_p = container_sub.add_parser("remove", help="Remove container by ID")
    rem_p.add_argument("--id", required=True, help="Container ID")

    en_p = container_sub.add_parser("enable", help="Enable container by ID")
    en_p.add_argument("--id", required=True, help="Container ID")

    dis_p = container_sub.add_parser("disable", help="Disable container by ID")
    dis_p.add_argument("--id", required=True, help="Container ID")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan storage containers")
    scan_p.add_argument("--force", action="store_true", help="Force rescan of all files regardless of modification time")
    scan_p.add_argument("--container", default=None, help="Scan a specific container ID only")

    # search
    search_p = subparsers.add_parser("search", help="Execute forensic query")
    search_p.add_argument("query", help="Query string")
    search_p.add_argument("--mode", default="global", help="Search mode (global, email, phone, name, address, passport, username, ip, domain, social, auth, vehicle, number)")
    search_p.add_argument("--json", action="store_true", help="Output raw JSON")

    # lookup shortcuts
    lookup_p = subparsers.add_parser("lookup", help="Shortcuts for field lookups")
    lookup_p.add_argument("--email", default=None, help="Lookup email")
    lookup_p.add_argument("--phone", default=None, help="Lookup phone")
    lookup_p.add_argument("--passport", default=None, help="Lookup passport/document")
    lookup_p.add_argument("--address", default=None, help="Lookup address")

    # correlate
    correlate_p = subparsers.add_parser("correlate", help="Show connected record graph")
    correlate_p.add_argument("--record", required=True, help="Record ID hash")
    correlate_p.add_argument("--json", action="store_true", help="Output raw JSON")

    # export
    export_p = subparsers.add_parser("export", help="Export forensic results or records")
    export_p.add_argument("--query", default=None, help="Query to export")
    export_p.add_argument("--mode", default="global", help="Search mode for query")
    export_p.add_argument("--record", default=None, help="Record ID to export")
    export_p.add_argument("--out", default=None, help="Output file path (e.g. results.json)")

    # server
    server_p = subparsers.add_parser("server", help="Start local web server")
    server_p.add_argument("--port", type=int, default=8080, help="Local port (default: 8080)")
    server_p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")

    args = parser.parse_args()
    cli = CLIController(current_dir)

    if not args.command or args.command == "menu":
        cli.interactive_menu()
    elif args.command == "init":
        cli.init_workbench()
    elif args.command == "status":
        cli.show_status()
    elif args.command == "logs":
        cli.show_logs()
    elif args.command == "sample":
        from tests.generate_sample_data import generate_all_samples
        generate_all_samples(current_dir)
    elif args.command == "container":
        if not getattr(args, "action", None) or args.action == "list":
            cli.container_cmd("list", args)
        else:
            cli.container_cmd(args.action, args)
    elif args.command == "scan":
        cli.run_scan(container_id=args.container, force=args.force)
    elif args.command == "search":
        cli.run_search(args.query, mode=args.mode, as_json=args.json)
    elif args.command == "lookup":
        if args.email:
            cli.run_search(args.email, mode="email")
        elif args.phone:
            cli.run_search(args.phone, mode="phone")
        elif args.passport:
            cli.run_search(args.passport, mode="passport")
        elif args.address:
            cli.run_search(args.address, mode="address")
        else:
            print("[-] Specify --email, --phone, --passport, or --address")
    elif args.command == "correlate":
        cli.show_record(args.record, as_json=args.json)
    elif args.command == "export":
        cli.export_cmd(query=args.query, mode=args.mode, record_id=args.record, out_path=args.out)
    elif args.command == "server":
        run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
