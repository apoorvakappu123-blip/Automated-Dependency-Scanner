const API_URL = "http://127.0.0.1:5000/api/scan";
const UPLOAD_URL = "http://127.0.0.1:5000/api/upload";
const PDF_URL = "http://127.0.0.1:5000/api/download-pdf";

let latestAnalysis = null;
let latestProjectName = "project";
let latestScanDate = null;
let latestUploadedFile = null;
let latestScanType = null;


// ======================================
// 1. EXISTING PROJECT FOLDER SCANNING
// ======================================

async function scanProject() {

    const projectName = document.getElementById("projectName").value.trim();
    const scanButton = document.getElementById("scanButton");
    const scanStatus = document.getElementById("scanStatus");

    if (!projectName) {
        scanStatus.textContent = "Please enter a project folder name.";
        scanStatus.style.color = "red";
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    scanStatus.textContent = "Scanning project. Please wait...";
    scanStatus.style.color = "#2563eb";

    try {

        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                project: projectName
            })
        });

        const data = await response.json();

        if (!response.ok || data.status !== "success") {
            throw new Error(data.message || "Scanning failed.");
        }
        latestProjectName = projectName;
        latestScanType = "folder";
        latestUploadedFile = null;
        displayResults(data.analysis);

        scanStatus.textContent = "Scan completed successfully!";
        scanStatus.style.color = "green";

    } catch (error) {

        console.error("Scan error:", error);

        scanStatus.textContent = "Error: " + error.message;
        scanStatus.style.color = "red";

    } finally {

        scanButton.disabled = false;
        scanButton.textContent = "Scan Project";
    }
}


// ======================================
// 2. ZIP PROJECT UPLOAD
// ======================================

async function uploadProject() {

    const fileInput = document.getElementById("projectFile");
    const uploadButton = document.getElementById("uploadButton");
    const uploadStatus = document.getElementById("uploadStatus");

    const file = fileInput.files[0];

    if (!file) {

        uploadStatus.textContent = "Please select a ZIP file.";
        uploadStatus.style.color = "red";

        return;
    }

    if (!file.name.toLowerCase().endsWith(".zip")) {

        uploadStatus.textContent = "Only ZIP files are allowed.";
        uploadStatus.style.color = "red";

        return;
    }

    if (file.size > 50 * 1024 * 1024) {

        uploadStatus.textContent = "File size must be below 50 MB.";
        uploadStatus.style.color = "red";

        return;
    }

    uploadButton.disabled = true;
    uploadButton.textContent = "Uploading & Scanning...";

    uploadStatus.textContent =
        "Uploading project and scanning dependencies. Please wait...";

    uploadStatus.style.color = "#2563eb";

    try {

        const formData = new FormData();

        formData.append("file", file);

        const response = await fetch(UPLOAD_URL, {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok || data.status !== "success") {

            throw new Error(data.message || "Project upload failed.");

        }

        latestProjectName = file.name.replace(/\.zip$/i, "");
        latestScanType = "zip";
        latestUploadedFile = file;
        displayResults(data.analysis);

        uploadStatus.textContent =
            "Successfully scanned: " + file.name;

        uploadStatus.style.color = "green";

    } catch (error) {

        console.error("Upload error:", error);

        uploadStatus.textContent =
            "Error: " + error.message;

        uploadStatus.style.color = "red";

    } finally {

        uploadButton.disabled = false;
        uploadButton.textContent = "Upload & Scan";

    }
}
// ======================================
// 3. DISPLAY VULNERABILITY RESULTS
// ======================================

function displayResults(analysis) {

    latestAnalysis = analysis;
    latestScanDate = new Date();
    const rescanButton = document.getElementById("rescanButton");

if (rescanButton) {
    rescanButton.disabled = !latestScanType;
}

    // Save this successful scan to history
saveScanToHistory(analysis);

    const summary = analysis.severity_summary;

    document.getElementById("totalVulnerabilities").textContent =
        analysis.total_vulnerabilities;

    document.getElementById("criticalCount").textContent =
        summary.CRITICAL;

    document.getElementById("highCount").textContent =
        summary.HIGH;

    document.getElementById("mediumCount").textContent =
        summary.MEDIUM;

    document.getElementById("lowCount").textContent =
        summary.LOW;


    // Risk assessment

    const riskLevel = document.getElementById("riskLevel");

    riskLevel.textContent = analysis.risk_level;

    riskLevel.style.color =
        analysis.risk_level === "CRITICAL" ||
        analysis.risk_level === "HIGH"
            ? "#dc2626"
            : analysis.risk_level === "MEDIUM"
                ? "#d97706"
                : "#16a34a";

    document.getElementById("riskScore").textContent =
        analysis.risk_score;
        // ======================================
// UPDATE RISK SCORE VISUALIZATION
// ======================================

// Get risk score and risk level
const score = Number(analysis.risk_score) || 0;

const riskCircle = document.getElementById("riskCircle");

// Set circle color based on actual risk level
const riskColors = {
    CRITICAL: "#7f1d1d",
    HIGH: "#dc2626",
    MEDIUM: "#f59e0b",
    LOW: "#16a34a"
};

riskCircle.style.borderColor =
    riskColors[String(analysis.risk_level).toUpperCase()] || "#e5e7eb";


// Update severity distribution chart

const total = Number(analysis.total_vulnerabilities) || 0;

const severityData = [
    { name: "critical", count: Number(summary.CRITICAL) || 0 },
    { name: "high", count: Number(summary.HIGH) || 0 },
    { name: "medium", count: Number(summary.MEDIUM) || 0 },
    { name: "low", count: Number(summary.LOW) || 0 }
];

severityData.forEach(item => {

    const percentage = total > 0
        ? (item.count / total) * 100
        : 0;

    const bar = document.getElementById(item.name + "Bar");

    const count = document.getElementById(
        item.name + "ChartCount"
    );

    if (bar) {
        bar.style.width = percentage + "%";
    }

    if (count) {
        count.textContent = item.count;
    }

});



    // Vulnerability table

    const table = document.getElementById("vulnerabilityTable");

    table.replaceChildren();

    if (!analysis.vulnerabilities || !analysis.vulnerabilities.length) {

        const row = document.createElement("tr");

        const cell = document.createElement("td");

        cell.colSpan = 8;

        cell.textContent = "No vulnerabilities detected.";

        row.appendChild(cell);

        table.appendChild(row);

        return;
    }


    analysis.vulnerabilities.forEach(vulnerability => {

        const row = document.createElement("tr");


        // Basic vulnerability information

        const values = [

            vulnerability.id || "N/A",

            vulnerability.package || "N/A",

            vulnerability.installed_version || "N/A",

            vulnerability.fixed_version || "Not available"

        ];

        values.forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value;

            row.appendChild(cell);

        });


        // Severity

        const severityCell = document.createElement("td");

        severityCell.textContent =
            vulnerability.severity || "UNKNOWN";

        severityCell.className =
            "severity " + (vulnerability.severity || "UNKNOWN");

        row.appendChild(severityCell);


        // Fix Available

        const fixCell = document.createElement("td");

        fixCell.textContent =
            vulnerability.fix_available === true
                ? "Yes"
                : vulnerability.fix_available === false
                    ? "No"
                    : "Unknown";

        row.appendChild(fixCell);


// ======================================
// ADVANCED FIX RECOMMENDATION
// ======================================

const recommendationCell = document.createElement("td");

const recommendationBox = document.createElement("div");

// Recommended version
const versionText = document.createElement("p");

versionText.textContent =
    "Recommended Version: " +
    (vulnerability.recommended_version || "Not available");

recommendationBox.appendChild(versionText);


// Fix recommendation
const recommendationText = document.createElement("p");

recommendationText.textContent =
    vulnerability.recommendation ||
    "No fix available. Monitor for updates.";

recommendationBox.appendChild(recommendationText);


// Upgrade command
if (vulnerability.upgrade_command) {

    const commandLabel = document.createElement("p");

    commandLabel.textContent = "Upgrade Command:";

    recommendationBox.appendChild(commandLabel);

    const command = document.createElement("code");

    command.textContent = vulnerability.upgrade_command;

    recommendationBox.appendChild(command);
}


// Fix explanation
if (vulnerability.fix_explanation) {

    const explanation = document.createElement("p");

    explanation.textContent =
        vulnerability.fix_explanation;

    recommendationBox.appendChild(explanation);
}

recommendationCell.appendChild(recommendationBox);

row.appendChild(recommendationCell);


        


        // CVE Details

        const detailsCell = document.createElement("td");

        const link = document.createElement("a");

        link.href = vulnerability.url || "#";

        link.textContent = "View CVE";

        link.className = "details-link";

        link.target = "_blank";

        link.rel = "noopener noreferrer";

        detailsCell.appendChild(link);

        row.appendChild(detailsCell);


        table.appendChild(row);

    });

}




// ======================================
// 4. DOWNLOAD JSON REPORT
// ======================================

function downloadJSONReport() {

    if (!latestAnalysis) {

        alert("Please complete a vulnerability scan first.");

        return;
    }

    const report = {

        project_name: latestProjectName,

        scan_date: latestScanDate.toISOString(),

        scanner: "Automated Dependency Vulnerability Scanner",

        total_vulnerabilities:
            latestAnalysis.total_vulnerabilities,

        severity_summary:
            latestAnalysis.severity_summary,

        risk_level:
            latestAnalysis.risk_level,

        risk_score:
            latestAnalysis.risk_score,

        vulnerabilities:
            latestAnalysis.vulnerabilities

    };

    const jsonContent = JSON.stringify(report, null, 4);

    downloadFile(
        jsonContent,
        latestProjectName + "-security-report.json",
        "application/json"
    );

}


// ======================================
// 5. DOWNLOAD CSV REPORT
// ======================================

function downloadCSVReport() {

    if (!latestAnalysis) {

        alert("Please complete a vulnerability scan first.");

        return;
    }

    const headers = [

        "CVE ID",
        "Package",
        "Installed Version",
        "Fixed Version",
        "Severity",
        "URL"

    ];

    const rows = latestAnalysis.vulnerabilities.map(v => [

        v.id || "N/A",

        v.package || "N/A",

        v.installed_version || "N/A",

        v.fixed_version || "Not available",

        v.severity || "UNKNOWN",

        v.url || "N/A"

    ]);

    const csvContent = [

        headers,

        ...rows

    ].map(row =>

        row.map(value =>

            '"' + String(value).replace(/"/g, '""') + '"'

        ).join(",")

    ).join("\n");

    downloadFile(

        "\uFEFF" + csvContent,

        latestProjectName + "-security-report.csv",

        "text/csv;charset=utf-8;"

    );

}


// ======================================
// 6. COMMON FILE DOWNLOAD FUNCTION
// ======================================

function downloadFile(content, filename, contentType) {

    const blob = new Blob(

        [content],

        { type: contentType }

    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;

    link.download = filename;

    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);

    URL.revokeObjectURL(url);

}
async function downloadPDFReport() {

    if (!latestAnalysis) {
        alert("Please complete a vulnerability scan first.");
        return;
    }

    try {

        const response = await fetch(PDF_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                project_name: latestProjectName,
                scan_date: latestScanDate.toISOString(),
                analysis: latestAnalysis
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || "PDF generation failed.");
        }

        const blob = await response.blob();

        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");

        link.href = url;
        link.download = latestProjectName + "-security-report.pdf";

        document.body.appendChild(link);
        link.click();

        document.body.removeChild(link);
        URL.revokeObjectURL(url);

    } catch (error) {

        console.error("PDF Download Error:", error);
        alert("Unable to download PDF: " + error.message);

    }
}
// ======================================
// VULNERABILITY SEARCH AND FILTER
// ======================================


// ======================================
// VULNERABILITY SEARCH AND FILTER
// ======================================

function renderVulnerabilities(analysis) {

    const searchInput = document.getElementById("searchInput");
    const severityFilter = document.getElementById("severityFilter");
    const table = document.getElementById("vulnerabilityTable");

    if (!table || !analysis) return;

    const vulnerabilities = analysis.vulnerabilities || [];

    const searchText = searchInput
        ? searchInput.value.toLowerCase().trim()
        : "";

    const selectedSeverity = severityFilter
        ? severityFilter.value
        : "ALL";

    // Filter vulnerabilities

    const filtered = vulnerabilities.filter(v => {

        const cve = (v.id || "").toLowerCase();
        const packageName = (v.package || "").toLowerCase();
        const severity = (v.severity || "UNKNOWN").toUpperCase();

        const matchesSearch =
            cve.includes(searchText) ||
            packageName.includes(searchText);

        const matchesSeverity =
            selectedSeverity === "ALL" ||
            severity === selectedSeverity;

        return matchesSearch && matchesSeverity;

    });

    // Clear previous rows

    table.replaceChildren();

    // No results message

    if (filtered.length === 0) {

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 8;
        cell.textContent = vulnerabilities.length === 0
            ? "No vulnerabilities detected."
            : "No vulnerabilities found.";

        row.appendChild(cell);
        table.appendChild(row);

        return;
    }

    // Display filtered results

    filtered.forEach(v => {

        const row = document.createElement("tr");

        const values = [

            v.id || "N/A",
            v.package || "N/A",
            v.installed_version || "N/A",
            v.fixed_version || "Not available"

        ];

        values.forEach(value => {

            const cell = document.createElement("td");
            cell.textContent = value;

            row.appendChild(cell);

        });

        // Severity

        const severityCell = document.createElement("td");

        severityCell.textContent = v.severity || "UNKNOWN";

        severityCell.className =
            "severity " + (v.severity || "UNKNOWN");

        row.appendChild(severityCell);

        // Fix Available

        const fixCell = document.createElement("td");

        fixCell.textContent =
            v.fix_available === true ? "Yes" :
            v.fix_available === false ? "No" : "Unknown";

        row.appendChild(fixCell);

        // Recommendation

        const recommendationCell = document.createElement("td");

        recommendationCell.textContent =
            v.recommendation || "No recommendation";

        row.appendChild(recommendationCell);

        // CVE Details

        const detailsCell = document.createElement("td");

        if (v.url) {

            const link = document.createElement("a");

            link.href = v.url;
            link.textContent = "View CVE";
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.className = "details-link";

            detailsCell.appendChild(link);

        } else {

            detailsCell.textContent = "N/A";

        }

        row.appendChild(detailsCell);

        table.appendChild(row);

    });

}


// ======================================
// SEARCH AND FILTER EVENT LISTENERS
// ======================================

document.getElementById("searchInput")
    .addEventListener("input", function () {

        if (latestAnalysis) {
            renderVulnerabilities(latestAnalysis);
        }

    });


document.getElementById("severityFilter")
    .addEventListener("change", function () {

        if (latestAnalysis) {
            renderVulnerabilities(latestAnalysis);
        }

    });
    // ======================================
// 7. SCAN HISTORY
// ======================================

const HISTORY_KEY = "dependencyScannerHistory";


// Save successful scan

function saveScanToHistory(analysis) {

    try {

        let history = JSON.parse(
            localStorage.getItem(HISTORY_KEY) || "[]"
        );

        const scanRecord = {

            project_name: latestProjectName,

            scan_date: latestScanDate.toISOString(),

            total_vulnerabilities:
                analysis.total_vulnerabilities || 0,

            severity_summary:
                analysis.severity_summary || {},

            risk_score:
                analysis.risk_score || 0,

            risk_level:
                analysis.risk_level || "UNKNOWN",

            vulnerabilities:
                analysis.vulnerabilities || []

        };

        history.push(scanRecord);

        // Keep the latest 30 scans
        history = history.slice(-30);

        localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify(history)
        );

        renderScanHistory();

    } catch (error) {

        console.error("Unable to save scan history:", error);

    }

}


// Display scan history

function renderScanHistory() {

    const table = document.getElementById("scanHistoryTable");

    const compareButton =
        document.getElementById("compareScansButton");

    if (!table) return;

    const history = JSON.parse(
        localStorage.getItem(HISTORY_KEY) || "[]"
    );

    table.replaceChildren();

    if (history.length === 0) {

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;
        cell.textContent = "No scan history available yet.";

        row.appendChild(cell);
        table.appendChild(row);

        if (compareButton) {
            compareButton.disabled = true;
        }

        return;
    }

    if (compareButton) {
        compareButton.disabled = history.length < 2;
    }

    // Show newest scans first

    history.slice().reverse().forEach(scan => {

        const row = document.createElement("tr");

        const summary = scan.severity_summary || {};

        const values = [

            scan.project_name,

            new Date(scan.scan_date).toLocaleString(),

            scan.total_vulnerabilities,

            summary.CRITICAL || 0,

            summary.HIGH || 0,

            summary.MEDIUM || 0,

            summary.LOW || 0,

            scan.risk_score,

            scan.risk_level

        ];

        values.forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value;

            row.appendChild(cell);

        });

        table.appendChild(row);

    });

}


// ======================================
// 8. COMPARE LATEST TWO SCANS
// ======================================

function compareLatestScans() {

    const history = JSON.parse(
        localStorage.getItem(HISTORY_KEY) || "[]"
    );

    const results =
        document.getElementById("comparisonResults");

    if (!results) return;

    results.replaceChildren();

    if (history.length < 2) {

        results.textContent =
            "You need at least two successful scans to compare.";

        return;
    }

    const previous = history[history.length - 2];
    const latest = history[history.length - 1];

    const previousVulnerabilities =
        previous.vulnerabilities || [];

    const latestVulnerabilities =
        latest.vulnerabilities || [];

    // Identify vulnerabilities using CVE ID and package

    const getKey = v =>
        `${v.id || "UNKNOWN"}::${v.package || "UNKNOWN"}`;

    const previousSet = new Set(
        previousVulnerabilities.map(getKey)
    );

    const latestSet = new Set(
        latestVulnerabilities.map(getKey)
    );

    const fixed = previousVulnerabilities.filter(
        v => !latestSet.has(getKey(v))
    );

    const newlyDiscovered = latestVulnerabilities.filter(
        v => !previousSet.has(getKey(v))
    );

    const remaining = latestVulnerabilities.filter(
        v => previousSet.has(getKey(v))
    );

    // Display comparison

    const heading = document.createElement("h3");

    heading.textContent =
        "Scan Comparison: " +
        previous.project_name + " vs " + latest.project_name;

    results.appendChild(heading);

    const summaryTable = document.createElement("table");

    const metrics = [

        ["Total Vulnerabilities",
            previous.total_vulnerabilities,
            latest.total_vulnerabilities],

        ["Risk Score",
            previous.risk_score,
            latest.risk_score]

    ];

    metrics.forEach(metric => {

        const row = document.createElement("tr");

        metric.forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value;

            row.appendChild(cell);

        });

        summaryTable.appendChild(row);

    });

    results.appendChild(summaryTable);

    const comparisonDetails = document.createElement("div");

    comparisonDetails.innerHTML = `
        <h3>Comparison Results</h3>
        <p>Fixed Vulnerabilities: <strong>${fixed.length}</strong></p>
        <p>New Vulnerabilities: <strong>${newlyDiscovered.length}</strong></p>
        <p>Remaining Vulnerabilities: <strong>${remaining.length}</strong>
        </p>
    `;

    results.appendChild(comparisonDetails);

    // List fixed vulnerabilities

    const fixedHeading = document.createElement("h4");
    fixedHeading.textContent = "Fixed Vulnerabilities";
    results.appendChild(fixedHeading);

    const fixedList = document.createElement("ul");

    fixed.forEach(v => {

        const item = document.createElement("li");

        item.textContent =
            `${v.id} - ${v.package}`;

        fixedList.appendChild(item);

    });

    if (fixed.length === 0) {
        fixedList.textContent = "No vulnerabilities fixed yet.";
    }

    results.appendChild(fixedList);

    // List newly discovered vulnerabilities

    const newHeading = document.createElement("h4");
    newHeading.textContent = "Newly Discovered Vulnerabilities";
    results.appendChild(newHeading);

    const newList = document.createElement("ul");

    newlyDiscovered.forEach(v => {

        const item = document.createElement("li");

        item.textContent =
            `${v.id} - ${v.package}`;

        newList.appendChild(item);

    });

    if (newlyDiscovered.length === 0) {
        newList.textContent = "No new vulnerabilities detected.";
    }

    results.appendChild(newList);

}


// Load saved history when dashboard opens

renderScanHistory();
// ======================================
//  RESCAN PROJECT
// ======================================

async function rescanProject() {

    const rescanButton = document.getElementById("rescanButton");
    const scanStatus = document.getElementById("scanStatus");
    const uploadStatus = document.getElementById("uploadStatus");

    if (!latestScanType) {
        alert("Please scan a project before using Rescan.");
        return;
    }

    rescanButton.disabled = true;
    rescanButton.textContent = "Rescanning...";

    try {

        let response;

        // RESCAN PROJECT FOLDER
        if (latestScanType === "folder") {

            scanStatus.textContent = "Rescanning project. Please wait...";
            scanStatus.style.color = "#2563eb";

            response = await fetch(API_URL, {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    project: latestProjectName
                })

            });

        }

        // RESCAN ZIP FILE
        else if (latestScanType === "zip") {

            if (!latestUploadedFile) {
                throw new Error(
                    "Original ZIP file is unavailable. Please upload it again."
                );
            }

            uploadStatus.textContent =
                "Uploading ZIP file and rescanning. Please wait...";

            uploadStatus.style.color = "#2563eb";

            const formData = new FormData();

            formData.append("file", latestUploadedFile);

            response = await fetch(UPLOAD_URL, {

                method: "POST",

                body: formData

            });

        }

        const data = await response.json();

        if (!response.ok || data.status !== "success") {
            throw new Error(data.message || "Rescan failed.");
        }

        // Update dashboard and scan history
        displayResults(data.analysis);

        if (latestScanType === "folder") {

            scanStatus.textContent =
                "Project rescanned successfully!";

            scanStatus.style.color = "green";

        } else {

            uploadStatus.textContent =
                "Successfully rescanned: " + latestUploadedFile.name;

            uploadStatus.style.color = "green";

        }

    } catch (error) {

        console.error("Rescan error:", error);

        const statusElement =
            latestScanType === "folder"
                ? scanStatus
                : uploadStatus;

        statusElement.textContent = "Rescan error: " + error.message;
        statusElement.style.color = "red";

    } finally {

        rescanButton.disabled = false;
        rescanButton.textContent = "🔄 Rescan Project";

    }

}