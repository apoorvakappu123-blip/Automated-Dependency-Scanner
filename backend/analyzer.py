import re


def extract_version(version_string):
    if not version_string:
        return None

    match = re.search(r"\d+(?:\.\d+)*", str(version_string))

    if not match:
        return None

    return tuple(
        int(part) for part in match.group().split(".")
    )


def get_upgrade_command(package, version, ecosystem):

    ecosystem = str(ecosystem).lower()

    if ecosystem in ["pip", "python"]:
        return f"python -m pip install {package}=={version}"

    elif ecosystem in ["npm", "node-pkg"]:
        return f"npm install {package}@{version}"

    elif ecosystem == "gomod":
        return f"go get {package}@v{version}"

    elif ecosystem == "cargo":
        return f"cargo update -p {package}"

    elif ecosystem == "gem":
        return f"gem install {package} -v {version}"

    elif ecosystem == "composer":
        return f"composer require {package}:{version}"

    elif ecosystem == "nuget":
        return f"dotnet add package {package} --version {version}"

    return f"Update {package} to version {version} in your project configuration."


def analyze_report(report):

    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    vulnerabilities = []
    package_fixes = {}

    results = report.get("Results", [])

    # STEP 1: Collect vulnerabilities and fixed versions

    for result in results:

        ecosystem = result.get("Type", "unknown")

        issues = result.get("Vulnerabilities") or []

        for issue in issues:

            severity = str(
                issue.get("Severity", "UNKNOWN")
            ).upper()

            if severity in summary:
                summary[severity] += 1

            package = issue.get("PkgName", "Unknown")

            installed_version = issue.get(
                "InstalledVersion", "N/A"
            )

            fixed_version = issue.get(
                "FixedVersion", ""
            )

            fix_available = bool(
                fixed_version and fixed_version.strip()
            )

            vulnerability = {

                "id": issue.get("VulnerabilityID"),

                "package": package,

                "installed_version": installed_version,

                "fixed_version": fixed_version or "Not available",

                "severity": severity,

                "title": issue.get("Title"),

                "description": issue.get("Description"),

                "url": issue.get("PrimaryURL"),

                "fix_available": fix_available,

                "ecosystem": ecosystem,

                "recommended_version": "",

                "upgrade_command": "",

                "recommendation": "",

                "fix_explanation": ""

            }

            vulnerabilities.append(vulnerability)

            # Find the highest fixed version for this package

            if fix_available:

                version_candidates = []

                for version in fixed_version.split(","):

                    version = version.strip()

                    parsed = extract_version(version)

                    if parsed:
                        version_candidates.append(
                            (parsed, version)
                        )

                if version_candidates:

                    best_version = max(
                        version_candidates,
                        key=lambda item: item[0]
                    )

                    package_key = (ecosystem, package)

                    if package_key not in package_fixes:

                        package_fixes[package_key] = best_version

                    elif best_version[0] > package_fixes[package_key][0]:

                        package_fixes[package_key] = best_version

    # STEP 2: Generate advanced recommendations

    for vulnerability in vulnerabilities:

        package = vulnerability["package"]

        ecosystem = vulnerability["ecosystem"]

        package_key = (ecosystem, package)

        if package_key in package_fixes:

            recommended_version = package_fixes[package_key][1]

            command = get_upgrade_command(
                package,
                recommended_version,
                ecosystem
            )

            vulnerability["recommended_version"] = recommended_version

            vulnerability["upgrade_command"] = command

            vulnerability["recommendation"] = (
                f"Upgrade {package} to version "
                f"{recommended_version} to address the detected "
                f"fixed-version requirements."
            )

            vulnerability["fix_explanation"] = (
                f"The installed version "
                f"{vulnerability['installed_version']} has a known "
                f"security vulnerability. Version "
                f"{recommended_version} meets the highest "
                f"fixed-version requirement found for this package "
                f"in the scan."
            )

        else:

            vulnerability["recommendation"] = (
                "No fixed version currently available. "
                "Monitor security updates."
            )

            vulnerability["fix_explanation"] = (
                "A fixed version was not provided by the scanner "
                "for this vulnerability."
            )

    # STEP 3: Calculate risk score

    risk_score = sum(
        severity_weights.get(v["severity"], 0)
        for v in vulnerabilities
    )

    risk_score = min(risk_score, 100)

    # STEP 4: Determine risk level

    if summary["CRITICAL"] > 0:
        risk_level = "CRITICAL"

    elif summary["HIGH"] > 0:
        risk_level = "HIGH"

    elif summary["MEDIUM"] > 0:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # STEP 5: Return analysis

    return {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "total_vulnerabilities": len(vulnerabilities),

        "severity_summary": summary,

        "vulnerabilities": vulnerabilities

    }