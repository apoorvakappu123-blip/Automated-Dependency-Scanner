from flask import Flask, request, jsonify
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

from backend.scanner import scan_project
from backend.analyzer import analyze_report


app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent.parent

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


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )