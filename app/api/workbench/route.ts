import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";

const WORKBENCH_ROOT = path.resolve(process.cwd(), "local_forensic_workbench");
const BRIDGE_SCRIPT = path.join(WORKBENCH_ROOT, "app", "bridge.py");

function runBridge(args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    execFile("python3", [BRIDGE_SCRIPT, ...args], { cwd: process.cwd() }, (err, stdout, stderr) => {
      if (err) {
        return resolve({ error: err.message, stderr: stderr });
      }
      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (parseErr) {
        resolve({ error: "Failed to parse bridge output", raw: stdout, stderr: stderr });
      }
    });
  });
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const action = searchParams.get("action") || "status";

  if (action === "status") {
    const data = await runBridge(["status"]);
    return NextResponse.json(data);
  }

  if (action === "containers") {
    const data = await runBridge(["containers_list"]);
    return NextResponse.json(data);
  }

  if (action === "scan_status") {
    const data = await runBridge(["scan_status"]);
    return NextResponse.json(data);
  }

  if (action === "logs") {
    const limit = searchParams.get("limit") || "100";
    const data = await runBridge(["logs", "--limit", limit]);
    return NextResponse.json(data);
  }

  if (action === "record") {
    const recordId = searchParams.get("id") || "";
    const data = await runBridge(["record", "--record-id", recordId]);
    return NextResponse.json(data);
  }

  if (action === "export") {
    const data = await runBridge(["export_report"]);
    return NextResponse.json(data);
  }

  return NextResponse.json({ error: "Unknown action" }, { status: 400 });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body.action;

    if (action === "search") {
      const args = ["search", "--query", body.query || "", "--mode", body.mode || "global"];
      if (body.field) {
        args.push("--field", body.field);
      }
      if (body.exact) {
        args.push("--exact");
      }
      const data = await runBridge(args);
      return NextResponse.json(data);
    }

    if (action === "container_add") {
      const args = [
        "container_add",
        "--name", body.name || "",
        "--path", body.path || "",
        "--type", body.type || "folder"
      ];
      const data = await runBridge(args);
      return NextResponse.json(data);
    }

    if (action === "container_toggle") {
      const args = [
        "container_toggle",
        "--container-id", body.id || "",
        "--enable", body.enabled ? "true" : "false"
      ];
      const data = await runBridge(args);
      return NextResponse.json(data);
    }

    if (action === "container_remove") {
      const args = ["container_remove", "--container-id", body.id || ""];
      const data = await runBridge(args);
      return NextResponse.json(data);
    }

    if (action === "scan_start") {
      const args = ["scan_sync"];
      if (body.force) args.push("--force");
      if (body.container_id) args.push("--container-id", body.container_id);
      const data = await runBridge(args);
      return NextResponse.json(data);
    }

    if (action === "init_samples") {
      const data = await runBridge(["init_samples"]);
      return NextResponse.json(data);
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
