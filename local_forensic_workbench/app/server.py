"""
Local Flask Web Server for Local Forensic Data Correlation Workbench.
Provides RESTful APIs and serves the cybersecurity forensic analyst dashboard.
Binds strictly to localhost by default.
"""

import os
import json
import time
from pathlib import Path
from flask import Flask, request, jsonify, render_template, send_file, Response

from .database import Database
from .container_manager import ContainerManager
from .scanner import ForensicScanner
from .correlation import CorrelationEngine
from .search import ForensicSearchEngine
from .exporters import ForensicExporter
from .detectors import ALL_FIELD_TYPES, DetectorEngine
from .utils import get_base_dir


def create_app(base_dir: Path = None) -> Flask:
    if base_dir is None:
        base_dir = get_base_dir()

    template_dir = base_dir / "web" / "templates"
    static_dir = base_dir / "web" / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir)
    )

    db = Database(base_dir / "data" / "index.db")
    container_mgr = ContainerManager(db, base_dir / "config" / "containers.json")
    
    settings_path = base_dir / "config" / "settings.json"
    settings = {}
    if settings_path.exists():
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except Exception:
            settings = {}

    enabled_detectors = settings.get("enabled_detectors", ALL_FIELD_TYPES)
    redaction_enabled = settings.get("redaction_enabled", False)

    detector_engine = DetectorEngine(enabled_detectors)
    correlation_engine = CorrelationEngine(db, redaction_enabled=redaction_enabled)
    scanner = ForensicScanner(db, container_mgr, detector_engine)
    search_engine = ForensicSearchEngine(db, correlation_engine)
    exporter = ForensicExporter(db)

    # UI Pages
    @app.route("/")
    def dashboard():
        return render_template("dashboard.html", active_page="dashboard")

    @app.route("/search")
    def search_page():
        return render_template("search.html", active_page="search", field_types=ALL_FIELD_TYPES)

    @app.route("/field-search")
    def field_search_page():
        return render_template("field_search.html", active_page="field_search", field_types=ALL_FIELD_TYPES)

    @app.route("/containers")
    def containers_page():
        return render_template("containers.html", active_page="containers")

    @app.route("/scanner")
    def scanner_page():
        return render_template("scanner.html", active_page="scanner")

    @app.route("/record/<record_id>")
    def record_page(record_id):
        return render_template("record.html", active_page="record", record_id=record_id)

    @app.route("/export")
    def export_page():
        return render_template("export.html", active_page="export")

    @app.route("/settings")
    def settings_page():
        return render_template("settings.html", active_page="settings", all_fields=ALL_FIELD_TYPES)

    @app.route("/logs")
    def logs_page():
        return render_template("logs.html", active_page="logs")

    # REST APIs
    @app.route("/api/status", methods=["GET"])
    def api_status():
        stats = db.get_stats()
        scan_status = scanner.get_scan_status()
        return jsonify({
            "system": "Local Forensic Data Correlation Workbench",
            "version": "1.0.0",
            "status": "operational",
            "stats": stats,
            "scan_status": scan_status,
            "security": {
                "local_only": True,
                "remote_telemetry": False,
                "redaction_active": correlation_engine.redaction_enabled
            }
        })

    @app.route("/api/containers", methods=["GET", "POST"])
    def api_containers():
        if request.method == "GET":
            containers = container_mgr.load_containers()
            return jsonify([c.to_dict() for c in containers])
        else:
            data = request.get_json() or {}
            name = data.get("name", "New Container").strip()
            path = data.get("path", "").strip()
            c_type = data.get("type", "folder")
            tags = data.get("tags", ["local"])
            if not path:
                return jsonify({"error": "Path is required"}), 400
            new_c = container_mgr.add_container(name, path, c_type, tags)
            return jsonify(new_c.to_dict()), 201

    @app.route("/api/containers/remove", methods=["POST"])
    def api_containers_remove():
        data = request.get_json() or {}
        c_id = data.get("id")
        if not c_id:
            return jsonify({"error": "Container ID is required"}), 400
        success = container_mgr.remove_container(c_id)
        return jsonify({"success": success, "removed_id": c_id})

    @app.route("/api/containers/enable", methods=["POST"])
    def api_containers_enable():
        data = request.get_json() or {}
        c_id = data.get("id")
        if not c_id:
            return jsonify({"error": "Container ID is required"}), 400
        success = container_mgr.toggle_container(c_id, True)
        return jsonify({"success": success, "enabled": True})

    @app.route("/api/containers/disable", methods=["POST"])
    def api_containers_disable():
        data = request.get_json() or {}
        c_id = data.get("id")
        if not c_id:
            return jsonify({"error": "Container ID is required"}), 400
        success = container_mgr.toggle_container(c_id, False)
        return jsonify({"success": success, "enabled": False})

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        data = request.get_json() or {}
        container_id = data.get("container_id")
        force = data.get("force", False)
        context_window = data.get("context_window", 15)
        job_id = scanner.start_scan_async(container_id, force=force, context_window=context_window)
        return jsonify({"status": "started", "job_id": job_id})

    @app.route("/api/scan/stop", methods=["POST"])
    def api_scan_stop():
        scanner.stop_scan()
        return jsonify({"status": "stop_signal_sent"})

    @app.route("/api/scan/status", methods=["GET"])
    def api_scan_status():
        return jsonify(scanner.get_scan_status())

    @app.route("/api/search", methods=["GET"])
    def api_search():
        q = request.args.get("q", "")
        mode = request.args.get("mode", "global")
        custom_field = request.args.get("field")
        exact = request.args.get("exact", "false").lower() == "true"
        fuzzy = request.args.get("fuzzy", "false").lower() == "true"
        limit = int(request.args.get("limit", 100))

        results = search_engine.execute_search(
            query=q,
            mode=mode,
            custom_field=custom_field,
            exact=exact,
            fuzzy=fuzzy,
            limit=limit
        )
        return jsonify(results)

    @app.route("/api/record/<record_id>", methods=["GET"])
    def api_record(record_id):
        cluster = correlation_engine.get_record_cluster(record_id)
        if not cluster:
            return jsonify({"error": "Record not found", "record_id": record_id}), 404
        return jsonify(cluster)

    @app.route("/api/export", methods=["GET"])
    def api_export():
        q = request.args.get("q", "")
        mode = request.args.get("mode", "global")
        rec_id = request.args.get("record_id")

        if rec_id:
            cluster = correlation_engine.get_record_cluster(rec_id)
            if not cluster:
                return jsonify({"error": "Record not found"}), 404
            content = exporter.export_record(cluster)
            filename = f"forensic_record_{rec_id}.json"
        elif q:
            results = search_engine.execute_search(q, mode=mode, limit=500)
            content = exporter.export_search_results(results)
            filename = f"forensic_search_{mode}_{int(time.time())}.json"
        else:
            report = exporter.export_full_report()
            content = json.dumps(report, indent=2, ensure_ascii=False)
            filename = f"forensic_full_audit_report_{int(time.time())}.json"

        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )

    @app.route("/api/logs", methods=["GET"])
    def api_logs():
        limit = int(request.args.get("limit", 100))
        logs = db.get_audit_logs(limit)
        return jsonify(logs)

    @app.route("/api/settings", methods=["GET", "POST"])
    def api_settings():
        nonlocal settings
        if request.method == "GET":
            return jsonify(settings)
        else:
            new_settings = request.get_json() or {}
            settings.update(new_settings)
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)

            # Update live engine components
            if "enabled_detectors" in settings:
                detector_engine.update_enabled_fields(settings["enabled_detectors"])
            if "redaction_enabled" in settings:
                correlation_engine.redaction_enabled = settings["redaction_enabled"]

            db.log_audit("settings_updated", new_settings)
            return jsonify({"status": "saved", "settings": settings})

    return app


def run_server(host: str = "127.0.0.1", port: int = 8080):
    app = create_app()
    print(f"[*] Local Forensic Data Correlation Workbench starting on http://{host}:{port}")
    print(f"[*] Bound strictly to {host} for local forensic safety.")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_server()
