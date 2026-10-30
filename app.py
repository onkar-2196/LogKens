from flask import Flask, jsonify, render_template
import json
from pathlib import Path

app = Flask(__name__)

REPORT_FILE = Path(__file__).with_name("analysis_report.json")


def load_report():
    if not REPORT_FILE.exists():
        return []

    try:
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


@app.route("/")
def home():
    return jsonify({
        "project": "LogLens",
        "status": "running",
        "message": "Security Log Analysis API"
    })

@app.route("/dashboard")
def dashboard():
    logs = load_report()

    total_logs = len(logs)
    suspicious_ips = {
        log.get("ip")
        for log in logs
        if log.get("attacks")
    }

    attack_counts = {}
    for log in logs:
        for attack in log.get("attacks", []):
            attack_counts[attack] = (
                attack_counts.get(attack, 0) + 1
            )

    return render_template(
        "dashboard.html",
        total_logs=total_logs,
        suspicious_ip_count=len(suspicious_ips),
        attack_counts=attack_counts,
        logs=logs
    )


@app.route("/api/logs")
def get_logs():
    return jsonify(load_report())


@app.route("/api/summary")
def get_summary():
    logs = load_report()

    attack_counts = {}
    suspicious_ips = set()

    for log in logs:
        for attack in log.get("attacks", []):
            attack_counts[attack] = attack_counts.get(attack, 0) + 1
            suspicious_ips.add(log.get("ip", "unknown"))

    return jsonify({
        "total_logs": len(logs),
        "suspicious_ip_count": len(suspicious_ips),
        "attack_counts": attack_counts
    })


if __name__ == "__main__":
    app.run(debug=True)
