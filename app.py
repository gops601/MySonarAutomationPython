from flask import Flask, render_template, request, redirect, url_for, jsonify
import requests
import mysql.connector

app = Flask(__name__)

SONAR_URL = "http://187.127.142.34:9000"
TOKEN = "squ_ff066785e24fbe24733df69242c14a50f7c4ae59"

DB = {
    "host": "localhost",
    "user": "root",
    "password": "Admin123",
    "database": "sonar_dashboard"
}

METRIC_KEYS = ",".join([
    "bugs",
    "vulnerabilities",
    "code_smells",
    "coverage",
    "duplicated_lines_density",
    "ncloc",
    "complexity",
    "duplicated_blocks",
    "new_bugs",
    "new_vulnerabilities",
    "new_code_smells",
    "reliability_remediation_effort",
    "security_remediation_effort",
    "sqale_debt_ratio"
])

RATING_MAP = {
    "1.0": "A",
    "2.0": "B",
    "3.0": "C",
    "4.0": "D",
    "5.0": "E"
}

def db_conn():
    return mysql.connector.connect(**DB)


def convert_rating(value):
    return RATING_MAP.get(str(value), str(value))


def issue_category(issue_type):
    if not issue_type:
        return 'UNKNOWN'
    type_upper = str(issue_type).upper()
    if type_upper == 'VULNERABILITY':
        return 'SECURITY'
    if type_upper == 'BUG':
        return 'RELIABILITY'
    if type_upper == 'CODE_SMELL':
        return 'MAINTAINABILITY'
    return 'OTHER'


def ensure_db_schema():
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics (
        project_key VARCHAR(255) PRIMARY KEY,
        bugs INT DEFAULT 0,
        vulnerabilities INT DEFAULT 0,
        code_smells INT DEFAULT 0,
        coverage FLOAT DEFAULT 0,
        duplicated_lines FLOAT DEFAULT 0,
        ncloc INT DEFAULT 0,
        complexity INT DEFAULT 0,
        duplicated_blocks INT DEFAULT 0,
        new_bugs INT DEFAULT 0,
        new_vulnerabilities INT DEFAULT 0,
        new_code_smells INT DEFAULT 0,
        reliability_remediation_effort VARCHAR(100),
        security_remediation_effort VARCHAR(100),
        sqale_debt_ratio FLOAT DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS quality_gate (
        project_key VARCHAR(255) PRIMARY KEY,
        status VARCHAR(50),
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ratings (
        project_key VARCHAR(255) PRIMARY KEY,
        reliability VARCHAR(5),
        security VARCHAR(5),
        maintainability VARCHAR(5),
        reliability_score FLOAT DEFAULT 0,
        security_score FLOAT DEFAULT 0,
        maintainability_score FLOAT DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS issues (
        id INT AUTO_INCREMENT PRIMARY KEY,
        project_key VARCHAR(255),
        issue_key VARCHAR(255),
        severity VARCHAR(50),
        message TEXT,
        `file` VARCHAR(1024),
        `line` INT,
        `type` VARCHAR(50),
        category VARCHAR(50),
        `status` VARCHAR(50),
        `rule` VARCHAR(255),
        effort VARCHAR(100),
        component VARCHAR(1024),
        creation_date VARCHAR(100),
        update_date VARCHAR(100),
        UNIQUE KEY unique_issue (project_key, issue_key)
    )""")

    cur.execute(
        "SELECT COUNT(*) FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = 'issues' AND column_name = 'category'",
        (DB['database'],)
    )
    if cur.fetchone()[0] == 0:
        cur.execute("ALTER TABLE issues ADD COLUMN category VARCHAR(50)")

    conn.commit()
    cur.close()
    conn.close()


# -------- FETCH PROJECTS -------- #
def fetch_projects():
    try:
        r = requests.get(f"{SONAR_URL}/api/projects/search", auth=(TOKEN, ""))
        return r.json().get("components", [])
    except:
        return []


# -------- FETCH USER EMAIL -------- #
def fetch_user_email(login):
    try:
        r = requests.get(
            f"{SONAR_URL}/api/users/search",
            params={"q": login, "ps": 1},
            auth=(TOKEN, "")
        )
        users = r.json().get("users", [])
        if users:
            return users[0].get("email", login) or login
        return login
    except:
        return login


# -------- FETCH METRICS -------- #
def fetch_metrics(project_key):
    try:
        params = {
            "component": project_key,
            "metricKeys": METRIC_KEYS
        }
        r = requests.get(f"{SONAR_URL}/api/measures/component", params=params, auth=(TOKEN, ""))

        data = r.json()
        metrics = {}

        for m in data.get("component", {}).get("measures", []):
            key = m["metric"]
            value = m.get("value", 0)
            try:
                metrics[key] = float(value)
            except (TypeError, ValueError):
                metrics[key] = value

        return metrics
    except:
        return {}


# -------- FETCH QUALITY -------- #
def fetch_quality(project_key):
    try:
        r = requests.get(
            f"{SONAR_URL}/api/qualitygates/project_status",
            params={"projectKey": project_key},
            auth=(TOKEN, "")
        )
        return r.json().get("projectStatus", {}).get("status", "UNKNOWN")
    except:
        return "UNKNOWN"


# -------- FETCH RATINGS -------- #
def fetch_ratings(project_key):
    try:
        params = {
            "component": project_key,
            "metricKeys": "reliability_rating,security_rating,sqale_rating"
        }
        r = requests.get(f"{SONAR_URL}/api/measures/component", params=params, auth=(TOKEN, ""))

        data = r.json()
        ratings = {}

        for m in data.get("component", {}).get("measures", []):
            key = m["metric"]
            value = m.get("value", "")
            base = key.replace("_rating", "") if key.endswith("_rating") else key
            ratings[base] = convert_rating(value)
            try:
                ratings[f"{base}_score"] = float(value)
            except (TypeError, ValueError):
                ratings[f"{base}_score"] = None

        return ratings
    except:
        return {}


# -------- FETCH ISSUES -------- #
def fetch_issues(project_key):
    all_issues = []
    page = 1
    page_size = 500
    
    while True:
        try:
            r = requests.get(
                f"{SONAR_URL}/api/issues/search",
                params={"componentKeys": project_key, "ps": page_size, "p": page},
                auth=(TOKEN, "")
            )
            data = r.json()
            issues = data.get("issues", [])
            all_issues.extend(issues)
            
            total = data.get("total", 0)
            if len(all_issues) >= total or len(issues) < page_size:
                break
            
            page += 1
        except:
            break
    
    return all_issues


# -------- FETCH ISSUES FROM DB -------- #
def fetch_issues_from_db(project_key, issue_type=None, severity=None):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    query = "SELECT * FROM issues WHERE project_key = %s"
    params = [project_key]

    if issue_type and issue_type.upper() != 'ALL':
        query += " AND UPPER(`type`) = %s"
        params.append(issue_type.upper())

    if severity:
        query += " AND UPPER(severity) = %s"
        params.append(severity.upper())

    query += " ORDER BY severity DESC"
    cur.execute(query, tuple(params))
    issues = cur.fetchall()
    cur.close()
    conn.close()
    return issues


# -------- SAVE DATA -------- #
def save_data(project_key, metrics, quality, ratings, issues):
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO metrics(
        project_key, bugs, vulnerabilities, code_smells, coverage,
        duplicated_lines, ncloc, complexity, duplicated_blocks,
        new_bugs, new_vulnerabilities, new_code_smells,
        reliability_remediation_effort, security_remediation_effort,
        sqale_debt_ratio
    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON DUPLICATE KEY UPDATE
        bugs = VALUES(bugs),
        vulnerabilities = VALUES(vulnerabilities),
        code_smells = VALUES(code_smells),
        coverage = VALUES(coverage),
        duplicated_lines = VALUES(duplicated_lines),
        ncloc = VALUES(ncloc),
        complexity = VALUES(complexity),
        duplicated_blocks = VALUES(duplicated_blocks),
        new_bugs = VALUES(new_bugs),
        new_vulnerabilities = VALUES(new_vulnerabilities),
        new_code_smells = VALUES(new_code_smells),
        reliability_remediation_effort = VALUES(reliability_remediation_effort),
        security_remediation_effort = VALUES(security_remediation_effort),
        sqale_debt_ratio = VALUES(sqale_debt_ratio)
    """, (
        project_key,
        metrics.get("bugs", 0),
        metrics.get("vulnerabilities", 0),
        metrics.get("code_smells", 0),
        metrics.get("coverage", 0),
        metrics.get("duplicated_lines_density", 0),
        metrics.get("ncloc", 0),
        metrics.get("complexity", 0),
        metrics.get("duplicated_blocks", 0),
        metrics.get("new_bugs", 0),
        metrics.get("new_vulnerabilities", 0),
        metrics.get("new_code_smells", 0),
        metrics.get("reliability_remediation_effort"),
        metrics.get("security_remediation_effort"),
        metrics.get("sqale_debt_ratio", 0)
    ))

    cur.execute(
        "INSERT INTO quality_gate(project_key, status) VALUES (%s,%s) ON DUPLICATE KEY UPDATE status = VALUES(status)",
        (project_key, quality)
    )

    cur.execute("""
    INSERT INTO ratings(
        project_key, reliability, security, maintainability,
        reliability_score, security_score, maintainability_score
    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
    ON DUPLICATE KEY UPDATE
        reliability = VALUES(reliability),
        security = VALUES(security),
        maintainability = VALUES(maintainability),
        reliability_score = VALUES(reliability_score),
        security_score = VALUES(security_score),
        maintainability_score = VALUES(maintainability_score)
    """, (
        project_key,
        ratings.get("reliability", "N/A"),
        ratings.get("security", "N/A"),
        ratings.get("maintainability", "N/A"),
        ratings.get("reliability_score", 0),
        ratings.get("security_score", 0),
        ratings.get("maintainability_score", 0)
    ))

    cur.execute("DELETE FROM issues WHERE project_key = %s", (project_key,))

    for issue in issues:
        issue_type_value = str(issue.get("type", "UNKNOWN")).upper()
        cur.execute("""
        INSERT INTO issues(
            project_key, issue_key, severity, message, `file`, `line`, `type`, category, `status`,
            `rule`, effort, component, creation_date, update_date
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            project_key,
            issue.get("key"),
            issue.get("severity"),
            issue.get("message"),
            issue.get("component"),
            issue.get("line", 0),
            issue_type_value,
            issue_category(issue_type_value),
            issue.get("status"),
            issue.get("rule"),
            issue.get("effort"),
            issue.get("component"),
            issue.get("creationDate"),
            issue.get("updateDate")
        ))

    conn.commit()
    cur.close()
    conn.close()


# -------- ROUTES -------- #

@app.route("/", methods=["GET"])
def dashboard():
    projects_raw = fetch_projects()
    
    grouped_projects = {}
    for p in projects_raw:
        original_name = p.get('name', 'Unknown')
        parts = original_name.split('-')
        
        if len(parts) >= 2:
            userid = parts[-1].strip()
            proj_name = "-".join(parts[:-1]).strip()
            user_email = fetch_user_email(userid)
        else:
            userid = "Other"
            user_email = "Other"
            proj_name = original_name.strip()
            
        if user_email not in grouped_projects:
            grouped_projects[user_email] = []
            
        grouped_projects[user_email].append({
            'key': p.get('key', ''),
            'name': proj_name,
            'original_name': original_name,
            'original_key': p.get('key', '')
        })

    return render_template("dashboard.html", grouped_projects=grouped_projects)

@app.route("/api/report/<project_key>", methods=["GET"])
def api_report(project_key):
    # Fetch latest data from SonarQube directly
    metrics = fetch_metrics(project_key)
    quality = fetch_quality(project_key)
    ratings = fetch_ratings(project_key)
    issues = fetch_issues(project_key)

    # Save to database in the background (or rather, synchronously before returning)
    try:
        save_data(project_key, metrics, quality, ratings, issues)
    except Exception as e:
        print(f"Failed to save data to DB: {e}")

    return jsonify({
        "metrics": metrics,
        "quality": {"status": quality},
        "ratings": ratings,
        "issues": issues,
        "project_key": project_key
    })

@app.route("/fetch/<project_key>", methods=["GET"])
def fetch_project(project_key):
    metrics = fetch_metrics(project_key)
    quality = fetch_quality(project_key)
    ratings = fetch_ratings(project_key)
    issues = fetch_issues(project_key)

    try:
        save_data(project_key, metrics, quality, ratings, issues)
    except Exception as e:
        print(f"Failed to save data to DB: {e}")

    return redirect(url_for('dashboard'))


@app.route("/api/issues/<project_key>", methods=["GET"])
def api_issues(project_key):
    issue_type = request.args.get('type')
    severity = request.args.get('severity')
    try:
        issues = fetch_issues_from_db(project_key, issue_type, severity)
        return jsonify({"issues": issues})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    ensure_db_schema()
    app.run(debug=True)