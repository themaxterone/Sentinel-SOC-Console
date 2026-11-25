import concurrent.futures
import ipaddress
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from soc_core import (
    ABUSEIPDB_API_KEYS,
    DIR_ABUSEIP,
    DIR_SENTINEL,
    DIR_SIGNINS,
    DEFAULT_SENTINEL_WORKSPACE_ID,
    EMAIL_REGEX,
    SID_REGEX,
    check_single_key,
    discover_sentinel_workspaces,
    extract_workspace_guid,
)
from soc_workers import SOCWorkers


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


class Job:
    def __init__(self, name):
        self.id = uuid.uuid4().hex
        self.name = name
        self.created = time.time()
        self.status = "Starting"
        self.progress = 0.0
        self.state = "running"
        self.logs = []
        self.result = None
        self.lock = threading.RLock()

    def log(self, message, tag=None):
        with self.lock:
            self.logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "message": str(message),
                "tag": tag or "default",
            })

    def snapshot(self, since=0):
        with self.lock:
            return {
                "id": self.id,
                "name": self.name,
                "status": self.status,
                "progress": self.progress,
                "state": self.state,
                "logs": self.logs[max(0, since):],
                "log_count": len(self.logs),
                "result": self.result,
                "artifacts": self.artifacts(),
            }

    def artifacts(self):
        files = []
        for folder_name, folder_path in (
            ("signins", DIR_SIGNINS),
            ("sentinel", DIR_SENTINEL),
            ("abuseip", DIR_ABUSEIP),
        ):
            try:
                for filename in os.listdir(folder_path):
                    path = os.path.join(folder_path, filename)
                    if os.path.isfile(path) and os.path.getmtime(path) >= self.created:
                        files.append({
                            "name": filename,
                            "folder": folder_name,
                            "url": f"/api/files/{folder_name}/{filename}",
                        })
            except OSError:
                continue
        return sorted(files, key=lambda item: item["name"])


class JobManager:
    def __init__(self):
        self.jobs = {}
        self.lock = threading.RLock()

    def start(self, name, operation):
        job = Job(name)
        with self.lock:
            self.jobs[job.id] = job
        thread = threading.Thread(target=self._run, args=(job, operation), daemon=True)
        thread.start()
        return job

    @staticmethod
    def _run(job, operation):
        try:
            operation(job)
            with job.lock:
                if job.state == "running":
                    job.state = "error" if job.status.startswith("Error") else "completed"
                    if job.state == "completed":
                        job.progress = 1.0
        except Exception as error:
            job.log(f"[!] ERROR: {error}", "danger")
            with job.lock:
                job.status = "Error"
                job.state = "error"

    def get(self, job_id):
        with self.lock:
            return self.jobs.get(job_id)


jobs = JobManager()
_risk_lock = threading.RLock()
_last_risky_users = []
_last_risk_level = "High"


class ValueWidget:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value


class JobWidget:
    def __init__(self, job, field):
        self.job = job
        self.field = field

    def configure(self, **kwargs):
        key = "status" if self.field == "status" else None
        if key and "text" in kwargs:
            with self.job.lock:
                self.job.status = str(kwargs["text"])

    def set(self, value):
        with self.job.lock:
            self.job.progress = max(0.0, min(1.0, float(value)))


class WorkerContext(SOCWorkers):
    def __init__(self, job, workspace="", engine="Sentinel Workspace"):
        self.job = job
        self.discovered_risky_users = []
        self.last_scanned_risk_level = "High"
        self.combo_workspace = ValueWidget(workspace)
        self.seg_sentinel_engine = ValueWidget(engine)
        self.lbl_status_risky = JobWidget(job, "status")
        self.lbl_status_sentinel = JobWidget(job, "status")
        self.lbl_status_ip = JobWidget(job, "status")
        self.prog_risky = JobWidget(job, "progress")
        self.prog_sentinel = JobWidget(job, "progress")
        self.prog_ip = JobWidget(job, "progress")
        self.btn_scan_risky = JobWidget(job, "control")
        self.btn_run_kql = JobWidget(job, "control")
        self.btn_discover_ws = JobWidget(job, "control")
        self.btn_run_ipsearch = JobWidget(job, "control")
        self.btn_audit_risky = JobWidget(job, "control")

    def log_risky(self, message, tag=None):
        self.job.log(message, tag)

    def log_sentinel(self, message, tag=None):
        self.job.log(message, tag)

    def log_ip(self, message, tag=None):
        self.job.log(message, tag)


def _json_body():
    body = request.get_json(silent=True)
    if body is None and request.form:
        body = request.form.to_dict()
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object.")
    return body


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _integer(value, label, minimum=0):
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be an integer.")
    if result < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    return result


def _job_response(job):
    return jsonify({"job_id": job.id}), 202


@app.errorhandler(ValueError)
def handle_value_error(error):
    return jsonify({"error": str(error)}), 400


@app.errorhandler(413)
def handle_large_upload(_error):
    return jsonify({"error": "The uploaded file exceeds the 16 MB limit."}), 413


@app.before_request
def validate_api_origin():
    if request.method != "POST" or not request.path.startswith("/api/"):
        return None
    origin = request.headers.get("Origin")
    if not origin:
        return None
    parsed_origin = urlsplit(origin)
    if parsed_origin.scheme != request.scheme or parsed_origin.netloc.lower() != request.host.lower():
        return jsonify({"error": "Cross-origin requests are not allowed."}), 403
    return None


@app.get("/")
def home():
    return render_template(
        "index.html",
        workspace=DEFAULT_SENTINEL_WORKSPACE_ID,
    )


@app.post("/api/signins")
def start_signins():
    body = _json_body()
    single_mode = body.get("mode", "single") == "single"
    only_sid = _as_bool(body.get("only_sid"))
    use_abuse = _as_bool(body.get("use_abuse"), True)
    target_inputs = []
    uploaded = request.files.get("file")

    if single_mode:
        target = str(body.get("target", "")).strip()
        if not (EMAIL_REGEX.fullmatch(target) or SID_REGEX.fullmatch(target)):
            raise ValueError("Enter a valid corporate email address or AD SID.")
        target_inputs = [target]
    else:
        if uploaded:
            contents = uploaded.read().decode("utf-8", errors="ignore")
        else:
            contents = str(body.get("targets", ""))
        seen = set()
        for target in EMAIL_REGEX.findall(contents) + SID_REGEX.findall(contents):
            if target.lower() not in seen:
                seen.add(target.lower())
                target_inputs.append(target)
        if not target_inputs:
            raise ValueError("No valid email addresses or SIDs were found.")

    if only_sid:
        use_abuse = False
        days = 15
    else:
        days = _integer(body.get("days", 15), "Days", 0)

    def operation(job):
        worker = WorkerContext(job, workspace=str(body.get("workspace", "")))
        worker.worker_signins_generic(
            target_inputs,
            days,
            use_abuse,
            "single" if single_mode else "bulk",
            job.log,
            worker.prog_ip,
            worker.lbl_status_ip,
            worker.btn_run_ipsearch,
            only_sid,
        )

    return _job_response(jobs.start("User sign-ins audit", operation))


@app.post("/api/risky/scan")
def start_risky_scan():
    global _last_risky_users, _last_risk_level
    body = _json_body()
    level = str(body.get("level", "High")).title()
    if level not in ("High", "Medium", "Low", "All"):
        raise ValueError("Risk level must be High, Medium, Low, or All.")
    updated_days = _integer(body.get("updated_days", 7), "Risk updated days", 0)

    def operation(job):
        global _last_risky_users, _last_risk_level
        worker = WorkerContext(job)
        worker.worker_scan_risky(level, updated_days)
        with _risk_lock:
            _last_risky_users = list(worker.discovered_risky_users)
            _last_risk_level = level
            job.result = {"accounts": _last_risky_users}

    return _job_response(jobs.start("Risky users scan", operation))


@app.post("/api/risky/audit")
def start_risky_audit():
    body = _json_body()
    days = _integer(body.get("days", 15), "Sign-ins audit days", 0)
    use_abuse = _as_bool(body.get("use_abuse"), True)
    with _risk_lock:
        targets = list(_last_risky_users)
        level = _last_risk_level
    if not targets:
        raise ValueError("Run a risky-users scan first; no accounts are available to audit.")

    def operation(job):
        worker = WorkerContext(job)
        worker.worker_signins_generic(
            targets,
            days,
            use_abuse,
            f"risky_{level.lower()}",
            job.log,
            worker.prog_risky,
            worker.lbl_status_risky,
            worker.btn_scan_risky,
            False,
        )

    return _job_response(jobs.start("Audit risky users", operation))


@app.post("/api/sentinel/discover")
def discover_workspaces():
    def operation(job):
        job.status = "Discovering Azure workspaces..."
        job.progress = 0.2
        workspaces = discover_sentinel_workspaces(job.log)
        job.result = {"workspaces": workspaces}
        job.log(f"[+] Found {len(workspaces)} workspace(s).", "success")
        job.progress = 1.0
        job.status = "Workspace discovery completed."

    return _job_response(jobs.start("Discover Sentinel workspaces", operation))


@app.post("/api/sentinel/query")
def start_sentinel_query():
    body = _json_body()
    engine = str(body.get("engine", "Sentinel Workspace"))
    if engine not in ("Sentinel Workspace", "Defender XDR (Graph)"):
        raise ValueError("Choose Sentinel Workspace or Defender XDR (Graph).")
    kql = str(body.get("kql", "")).strip()
    if not kql:
        raise ValueError("Enter a KQL query.")
    raw_workspace = str(body.get("workspace", "")).strip()
    workspace_guid = extract_workspace_guid(raw_workspace)
    if engine == "Sentinel Workspace" and not workspace_guid:
        raise ValueError("Enter a valid Sentinel Workspace GUID or discover a workspace.")

    def operation(job):
        worker = WorkerContext(job, workspace=raw_workspace, engine=engine)
        worker.worker_sentinel_query(
            engine,
            workspace_guid,
            raw_workspace,
            kql,
            _as_bool(body.get("use_abuse"), True),
        )

    return _job_response(jobs.start("Sentinel / XDR KQL hunt", operation))


@app.post("/api/ipsearch")
def start_ip_search():
    body = _json_body()
    mode = str(body.get("mode", "single"))
    if mode not in ("single", "bulk", "sentinel"):
        raise ValueError("Choose a single IP, bulk file, or weekly Sentinel search.")
    use_intigriti = _as_bool(body.get("use_intigriti"), True)
    workspace = str(body.get("workspace", "")).strip()
    sentinel_days = _integer(body.get("sentinel_days", 30), "Lookback days", 1)
    uploaded = request.files.get("file")
    temporary_path = None

    if mode == "single":
        target = str(body.get("target", "")).strip()
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ValueError("Enter a valid IP address.")
    elif mode == "bulk":
        if not uploaded or not uploaded.filename:
            raise ValueError("Select a .txt file containing IP addresses.")
        if not uploaded.filename.lower().endswith(".txt"):
            raise ValueError("Bulk input must be a .txt file.")
        input_dir = os.path.join(os.path.dirname(__file__), "uploads")
        os.makedirs(input_dir, exist_ok=True)
        safe_name = secure_filename(uploaded.filename) or "ip-list.txt"
        temporary_path = os.path.join(input_dir, f"{uuid.uuid4().hex}_{safe_name}")
        uploaded.save(temporary_path)
        target = temporary_path
    else:
        target = extract_workspace_guid(workspace)
        if not target:
            raise ValueError("Enter a valid workspace GUID or discover a workspace.")

    def operation(job):
        try:
            worker = WorkerContext(job, workspace=workspace)
            worker.worker_ip_search(mode, target, use_intigriti, sentinel_days)
        finally:
            if temporary_path and os.path.exists(temporary_path):
                os.remove(temporary_path)

    return _job_response(jobs.start("IP threat intelligence search", operation))


@app.post("/api/keys/check")
def start_key_check():
    def operation(job):
        if not ABUSEIPDB_API_KEYS:
            raise ValueError("No AbuseIPDB API keys are configured.")
        job.status = "Checking API keys..."
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(check_single_key, index, key)
                for index, key in enumerate(ABUSEIPDB_API_KEYS, start=1)
            ]
            for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                results.append(future.result())
                job.progress = index / len(futures)
        results.sort(key=lambda result: result["index"])
        total_remaining = sum(
            result["remaining"]
            for result in results
            if isinstance(result["remaining"], int)
        )
        total_limit = sum(
            result["limit"]
            for result in results
            if isinstance(result["limit"], int)
        )
        job.result = {
            "keys": results,
            "remaining": total_remaining,
            "limit": total_limit,
        }
        for result in results:
            job.log(
                f"Key #{result['index']} {result['key']}: {result['status']} — "
                f"{result['remaining']} / {result['limit']} remaining",
                "success" if result["status"] == "Active" else "warn",
            )
        job.status = f"Key check complete — {total_remaining} / {total_limit} queries available."

    return _job_response(jobs.start("AbuseIPDB API key status", operation))


@app.get("/api/jobs/<job_id>")
def get_job(job_id):
    job = jobs.get(job_id)
    if job is None:
        return jsonify({"error": "Job not found."}), 404
    try:
        since = max(0, int(request.args.get("since", "0")))
    except ValueError:
        return jsonify({"error": "Invalid log offset."}), 400
    return jsonify(job.snapshot(since))


@app.get("/api/files/<folder>/<path:filename>")
def download_file(folder, filename):
    folders = {
        "signins": DIR_SIGNINS,
        "sentinel": DIR_SENTINEL,
        "abuseip": DIR_ABUSEIP,
    }
    if folder not in folders:
        return jsonify({"error": "File not found."}), 404
    return send_from_directory(folders[folder], filename, as_attachment=True)
