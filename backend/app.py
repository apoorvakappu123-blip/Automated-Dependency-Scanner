from flask import Flask, request, jsonify
from dotenv import load_dotenv
from flask_cors import CORS
from pathlib import Path, PurePosixPath
from werkzeug.exceptions import RequestEntityTooLarge
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib.utils import simpleSplit
import os
import tempfile
import zipfile
import stat
import shutil
import json
import urllib.request
import urllib.error


from scanner import scan_project
from analyzer import analyze_report
from database import init_db, save_scan_history, SessionLocal, ScanHistory


app = Flask(__name__)
frontend_origin = os.getenv("FRONTEND_URL", "http://127.0.0.1:8000")
CORS(app, resources={r"/api/*": {"origins": frontend_origin}})

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(Path(__file__).resolve().parent / ".env")

# Initialize PostgreSQL tables when the application starts
init_db()
# GitHub Actions Configuration
GITHUB_OWNER = "apoorvakappu123-blip"
GITHUB_REPO = "Automated-Dependency-Scanner"

GITHUB_ARTIFACT_NAME = "dependency-security-report"
GITHUB_REPORT_NAME = "trivy-results.json"
# ==========================================
# GITHUB ACTIONS SECURITY REPORT ENDPOINT
# ==========================================

@app.route("/api/github-report", methods=["GET"])
def github_report():

    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        return jsonify({
            "status": "error",
            "message": "GitHub API token is not configured."
        }), 500

    try:

        # STEP 1: Retrieve GitHub artifacts

        api_url = (
            f"https://api.github.com/repos/"
            f"{GITHUB_OWNER}/{GITHUB_REPO}/actions/artifacts"
            f"?name={GITHUB_ARTIFACT_NAME}&per_page=100"
        )

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Automated-Dependency-Scanner"
        }

        request_obj = urllib.request.Request(
            api_url,
            headers=headers
        )

        with urllib.request.urlopen(
            request_obj,
            timeout=30
        ) as response:

            artifact_data = json.loads(response.read())

        artifacts = artifact_data.get("artifacts", [])

        # STEP 2: Ignore expired artifacts

        valid_artifacts = [
            artifact for artifact in artifacts
            if not artifact.get("expired", True)
        ]

        if not valid_artifacts:
            return jsonify({
                "status": "error",
                "message": "No valid GitHub security report found."
            }), 404

        # STEP 3: Select latest artifact

        latest_artifact = max(
            valid_artifacts,
            key=lambda item: item.get("created_at", "")
        )

        artifact_id = latest_artifact["id"]

        # STEP 4: Download artifact ZIP

        download_url = (
            f"https://api.github.com/repos/"
            f"{GITHUB_OWNER}/{GITHUB_REPO}/actions/artifacts/"
            f"{artifact_id}/zip"
        )

        download_request = urllib.request.Request(
            download_url,
            headers=headers
        )

        # Prevent GitHub token from being forwarded to Azure.

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):

            def redirect_request(
                self, req, fp, code, msg, headers, newurl
            ):
                return None

        opener = urllib.request.build_opener(
            NoRedirectHandler
        )

        try:

            with opener.open(
                download_request,
                timeout=60
            ) as response:

                zip_data = response.read()

        except urllib.error.HTTPError as redirect_error:

            if redirect_error.code not in (301, 302, 303, 307, 308):
                raise

            redirect_url = redirect_error.headers.get("Location")

            if not redirect_url:
                raise Exception(
                    "GitHub artifact download redirect URL is missing."
                )

            # Download from Azure without sending GitHub token.

            redirect_request = urllib.request.Request(
                redirect_url,
                headers={
                    "User-Agent": "Automated-Dependency-Scanner"
                }
            )

            with urllib.request.urlopen(
                redirect_request,
                timeout=60
            ) as response:

                zip_data = response.read()

        # STEP 5: Read Trivy JSON report

        with zipfile.ZipFile(BytesIO(zip_data)) as archive:

            report_file = next(
                (
                    name for name in archive.namelist()
                    if PurePosixPath(name).name == GITHUB_REPORT_NAME
                ),
                None
            )

            if report_file is None:
                return jsonify({
                    "status": "error",
                    "message": "Trivy JSON report not found in artifact."
                }), 404

            report_data = json.loads(
                archive.read(report_file)
            )

        # STEP 6: Analyze using existing analyzer

        analysis = analyze_report(report_data)

        return jsonify({
            "status": "success",
            "source": "GitHub Actions",
            "repository": f"{GITHUB_OWNER}/{GITHUB_REPO}",
            "artifact": GITHUB_ARTIFACT_NAME,
            "scan_date": latest_artifact.get("created_at"),
            "analysis": analysis
        })

    except urllib.error.HTTPError as e:

        error_details = e.read().decode(
            "utf-8",
            errors="replace"
        )

        app.logger.error(
            "GitHub API HTTP %s: %s",
            e.code,
            error_details
        )

        return jsonify({
            "status": "error",
            "message": f"GitHub API returned HTTP {e.code}.",
            "details": error_details
        }), 502

    except Exception:

        app.logger.exception(
            "GitHub report retrieval failed"
        )

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve GitHub security report."
        }), 500

# Maximum uploaded ZIP size: 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

MAX_FILES = 5000
MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
# Dependency files supported by our scanner
SUPPORTED_DEPENDENCY_FILES = {
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "composer.lock",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "pom.xml",
    "gradle.lockfile",
    "packages.lock.json"
}


def find_dependency_files(project_path):

    found_files = []

    for file_path in Path(project_path).rglob("*"):

        if not file_path.is_file():
            continue

        if file_path.name in SUPPORTED_DEPENDENCY_FILES:
            found_files.append(
                str(file_path.relative_to(project_path))
            )

    return found_files


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    return jsonify({
        "status": "error",
        "message": "ZIP file exceeds the 50 MB upload limit."
    }), 413


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "success",
        "message": "Automated Dependency Scanner API is running"
    })


# EXISTING PROJECT SCANNER
@app.route("/api/scan", methods=["POST"])
def scan():

    data = request.get_json(silent=True) or {}

    project_name = data.get("project", "test-project")

    project_path = (BASE_DIR / project_name).resolve()

    if not project_path.is_relative_to(BASE_DIR):
        return jsonify({
            "status": "error",
            "message": "Invalid project path"
        }), 400

    if not project_path.is_dir():
        return jsonify({
            "status": "error",
            "message": "Project directory not found"
        }), 404

    report_path = BASE_DIR / "reports" / "scan-report.json"

    scan_result = scan_project(
        str(project_path),
        str(report_path)
    )

    if scan_result["status"] != "success":
        return jsonify(scan_result), 500

    analysis = analyze_report(scan_result["report"])

    # Save folder scan history to PostgreSQL
    try:
        save_scan_history(
            project_name,
            "folder",
            analysis
        )
    except Exception:
        app.logger.exception("Failed to save folder scan history")

    return jsonify({
        "status": "success",
        "project": project_name,
        "analysis": analysis
    })


# NEW ZIP UPLOAD ENDPOINT
@app.route("/api/upload", methods=["POST"])
def upload_project():

    if "file" not in request.files:
        return jsonify({
            
            "status": "error",
            "message": "No ZIP file uploaded."
        }), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({
            "status": "error",
            "message": "Please select a ZIP file."
        }), 400

    if not uploaded_file.filename.lower().endswith(".zip"):
        return jsonify({
            "status": "error",
            "message": "Only ZIP files are allowed."
        }), 400

    try:

        # Create temporary workspace
        with tempfile.TemporaryDirectory(
            prefix="dependency_scan_"
        ) as temp_dir:

            workspace = Path(temp_dir)

            zip_path = workspace / "uploaded_project.zip"
            extract_dir = workspace / "extracted"
            report_path = workspace / "scan-report.json"

            extract_dir.mkdir()

            # Save uploaded ZIP
            uploaded_file.save(zip_path)

            # Validate ZIP archive
            if not zipfile.is_zipfile(zip_path):
                return jsonify({
                    "status": "error",
                    "message": "Invalid or corrupted ZIP file."
                }), 400

            # Inspect ZIP contents
            with zipfile.ZipFile(zip_path, "r") as archive:

                entries = archive.infolist()

                if len(entries) > MAX_FILES:
                    return jsonify({
                        "status": "error",
                        "message": "ZIP contains too many files."
                    }), 400

                total_size = 0
                seen_paths = set()

                for entry in entries:

                    raw_name = entry.filename

                    # Normalize Windows separators
                    normalized = raw_name.replace("\\", "/")
                    member = PurePosixPath(normalized)

                    # Reject unsafe paths
                    if (
                        member.is_absolute()
                        or ".." in member.parts
                        or ":" in member.parts[0]
                    ):
                        return jsonify({
                            "status": "error",
                            "message": "Unsafe ZIP file path detected."
                        }), 400

                    target = (
                        extract_dir / Path(*member.parts)
                    ).resolve()

                    if not target.is_relative_to(extract_dir.resolve()):
                        return jsonify({
                            "status": "error",
                            "message": "ZIP path traversal detected."
                        }), 400

                    # Reject duplicate paths
                    path_key = normalized.casefold()

                    if path_key in seen_paths:
                        return jsonify({
                            "status": "error",
                            "message": "Duplicate ZIP entries detected."
                        }), 400

                    seen_paths.add(path_key)

                    # Reject symbolic links
                    mode = entry.external_attr >> 16

                    if stat.S_ISLNK(mode):
                        return jsonify({
                            "status": "error",
                            "message": "Symbolic links are not allowed."
                        }), 400

                    total_size += entry.file_size

                    if total_size > MAX_UNCOMPRESSED_SIZE:
                        return jsonify({
                            "status": "error",
                            "message": "Extracted ZIP size exceeds the allowed limit."
                        }), 400

                    # Reject suspicious compression ratios
                    if (
                        entry.file_size > 0
                        and entry.compress_size == 0
                    ):
                        return jsonify({
                            "status": "error",
                            "message": "Suspicious ZIP compression detected."
                        }), 400

                    if (
                        entry.compress_size > 0
                        and entry.file_size / entry.compress_size > 1000
                    ):
                        return jsonify({
                            "status": "error",
                            "message": "ZIP compression ratio is too high."
                        }), 400

                # Extract files manually after validation
                for entry in entries:

                    normalized = entry.filename.replace("\\", "/")
                    member = PurePosixPath(normalized)

                    target = (
                        extract_dir / Path(*member.parts)
                    ).resolve()

                    if entry.is_dir():
                        target.mkdir(
                            parents=True,
                            exist_ok=True
                        )
                        continue

                    target.parent.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    with archive.open(entry, "r") as source:
                        with open(target, "wb") as destination:
                            shutil.copyfileobj(
                                source,
                                destination
                            )

            # Run existing Trivy scanner
            # Check whether the uploaded project contains dependencies
            dependency_files = find_dependency_files(extract_dir)
            if not dependency_files:
                return jsonify({
                    "status": "error",
                    "message": (
                        "No supported dependency files found. "
                        "Please upload a software project containing "
                        "files such as requirements.txt, package-lock.json, "
                        "pom.xml or Cargo.lock."
                    )
                }), 400

            # Run existing Trivy scanner
            scan_result = scan_project(
                str(extract_dir),
                str(report_path)
            )
            

            if scan_result["status"] != "success":
                return jsonify(scan_result), 500

            # Analyze vulnerability report
            analysis = analyze_report(
                scan_result["report"]
            )

            # Save ZIP scan history to PostgreSQL
            try:
                save_scan_history(
                    uploaded_file.filename,
                    "zip",
                    analysis
                )
            except Exception:
                app.logger.exception("Failed to save ZIP scan history")

            return jsonify({
                "status": "success",
                "message": "Project scanned successfully.",
                "project": uploaded_file.filename,
                "analysis": analysis
            })

    except zipfile.BadZipFile:
        return jsonify({
            "status": "error",
            "message": "Invalid ZIP archive."
        }), 400

    except Exception as e:
        app.logger.exception("ZIP upload scanning failed")

        return jsonify({
            "status": "error",
            "message": "Unable to process uploaded project."
        }), 500



    # ==========================================
# PDF SECURITY REPORT DOWNLOAD ENDPOINT
# ==========================================

@app.route("/api/download-pdf", methods=["POST"])
def download_pdf():

    data = request.get_json(silent=True) or {}

    analysis = data.get("analysis")

    if not isinstance(analysis, dict):
        return jsonify({
            "status": "error",
            "message": "Invalid scan analysis data."
        }), 400

    vulnerabilities = analysis.get("vulnerabilities", [])

    if not isinstance(vulnerabilities, list):
        return jsonify({
            "status": "error",
            "message": "Invalid vulnerability data."
        }), 400

    project_name = str(data.get("project_name", "project"))
    scan_date = str(data.get("scan_date", "Not available"))

    total = analysis.get("total_vulnerabilities", len(vulnerabilities))
    risk_level = str(analysis.get("risk_level", "UNKNOWN"))
    risk_score = analysis.get("risk_score", "N/A")

    severity = analysis.get("severity_summary", {})

    if not isinstance(severity, dict):
        severity = {}

    # Create PDF in memory
    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#163A63"),
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#163A63"),
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = styles["BodyText"]

    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    )

    story = []

    # Report title
    story.append(
        Paragraph(
            "DEPENDENCY SECURITY SCAN REPORT",
            title_style
        )
    )

    story.append(Spacer(1, 8))

    # Project information
    story.append(Paragraph(
        f"<b>Project:</b> {project_name}",
        normal_style
    ))

    story.append(Paragraph(
        f"<b>Scan Date:</b> {scan_date}",
        normal_style
    ))

    story.append(Paragraph(
        "<b>Scanner:</b> Automated Dependency Vulnerability Scanner",
        normal_style
    ))

    story.append(Spacer(1, 15))

    # Scan summary
    story.append(
        Paragraph("1. Scan Summary", heading_style)
    )

    summary_data = [
        ["Metric", "Result"],
        ["Total Vulnerabilities", str(total)],
        ["Critical", str(severity.get("CRITICAL", 0))],
        ["High", str(severity.get("HIGH", 0))],
        ["Medium", str(severity.get("MEDIUM", 0))],
        ["Low", str(severity.get("LOW", 0))],
        ["Risk Level", risk_level],
        ["Risk Score", str(risk_score)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[75 * mm, 75 * mm]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163A63")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F3F6FA"))
    ]))

    story.append(summary_table)

    story.append(Spacer(1, 15))

    # Vulnerability details
    story.append(
        Paragraph("2. Vulnerability Details", heading_style)
    )

    if vulnerabilities:

        table_data = [[
            "CVE ID",
            "Package",
            "Installed",
            "Fixed",
            "Severity"
        ]]

        for vulnerability in vulnerabilities:

            table_data.append([
                Paragraph(
                    str(vulnerability.get("id", "N/A")),
                    cell_style
                ),
                Paragraph(
                    str(vulnerability.get("package", "N/A")),
                    cell_style
                ),
                Paragraph(
                    str(vulnerability.get("installed_version", "N/A")),
                    cell_style
                ),
                Paragraph(
                    str(vulnerability.get("fixed_version", "N/A")),
                    cell_style
                ),
                Paragraph(
                    str(vulnerability.get("severity", "UNKNOWN")),
                    cell_style
                )
            ])

        vulnerability_table = Table(
            table_data,
            colWidths=[
                35 * mm,
                30 * mm,
                30 * mm,
                30 * mm,
                25 * mm
            ],
            repeatRows=1
        )

        vulnerability_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163A63")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))

        story.append(vulnerability_table)

        # Detailed descriptions
        story.append(
            Paragraph("3. Vulnerability Descriptions", heading_style)
        )

        for index, vulnerability in enumerate(vulnerabilities, start=1):

            cve_id = str(vulnerability.get("id", "N/A"))
            description = str(
                vulnerability.get("description", "No description available.")
            )
            package = str(vulnerability.get("package", "N/A"))
            fixed_version = str(
                vulnerability.get("fixed_version", "Not available")
            )
            url = str(vulnerability.get("url", ""))

            story.append(
                Paragraph(
                    f"<b>{index}. {cve_id}</b>",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Package:</b> {package}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Fixed Version:</b> {fixed_version}",
                    normal_style
                )
            )

            # Escape text before adding it to a ReportLab paragraph
            from xml.sax.saxutils import escape

            story.append(
                Paragraph(
                    escape(description),
                    normal_style
                )
            )

            if url:
                story.append(
                    Paragraph(
                        f"<b>Reference:</b> {escape(url)}",
                        cell_style
                    )
                )

            story.append(Spacer(1, 10))

    else:

        story.append(
            Paragraph(
                "No vulnerabilities were detected in this scan.",
                normal_style
            )
        )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "Generated by Automated Dependency Vulnerability Scanner",
            styles["Italic"]
        )
    )

    # Build PDF
    document.build(story)

    pdf_buffer.seek(0)

    safe_project_name = "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in project_name
    )[:80] or "project"

    from flask import send_file

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{safe_project_name}-security-report.pdf"
    )



# ==========================================
# POSTGRESQL SCAN HISTORY API
# ==========================================

@app.route("/api/history", methods=["GET"])
def get_scan_history():

    session = SessionLocal()

    try:
        records = (
            session.query(ScanHistory)
            .order_by(
                ScanHistory.scanned_at.desc(),
                ScanHistory.id.desc()
            )
            .limit(100)
            .all()
        )

        history = []

        for record in records:
            history.append({
                "id": record.id,
                "project_name": record.project_name,
                "scan_type": record.scan_type,
                "scanned_at": (
                    record.scanned_at.isoformat()
                    if record.scanned_at else None
                ),
                "total_vulnerabilities": record.total_vulnerabilities,
                "critical": record.critical,
                "high": record.high,
                "medium": record.medium,
                "low": record.low,
                "risk_score": record.risk_score,
                "risk_level": record.risk_level,
                "analysis": record.analysis
            })

        return jsonify({
            "status": "success",
            "total_records": len(history),
            "history": history
        })

    except Exception:
        app.logger.exception("Failed to retrieve PostgreSQL scan history")

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve scan history."
        }), 500

    finally:
        session.close()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
