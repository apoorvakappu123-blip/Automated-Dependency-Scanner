import subprocess
import json
import os


def scan_project(project_path, report_path="reports/scan-report.json"):

    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    command = [
        "trivy",
        "fs",
        "--scanners", "vuln",
        "--format", "json",
        "--output", report_path,
        project_path
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "message": result.stderr
            }

        with open(report_path, "r") as file:
            report = json.load(file)

        return {
            "status": "success",
            "report": report,
            "report_path": report_path
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "Trivy is not installed or not available in PATH."
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }