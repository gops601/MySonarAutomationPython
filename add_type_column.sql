-- Create / update Sonar data tables for the dashboard
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
);

CREATE TABLE IF NOT EXISTS quality_gate (
    project_key VARCHAR(255) PRIMARY KEY,
    status VARCHAR(50),
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ratings (
    project_key VARCHAR(255) PRIMARY KEY,
    reliability VARCHAR(5),
    security VARCHAR(5),
    maintainability VARCHAR(5),
    reliability_score FLOAT DEFAULT 0,
    security_score FLOAT DEFAULT 0,
    maintainability_score FLOAT DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

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
);

-- Optional: add type/category columns if the table already exists without them
ALTER TABLE issues ADD COLUMN IF NOT EXISTS `type` VARCHAR(50);
ALTER TABLE issues ADD COLUMN IF NOT EXISTS category VARCHAR(50);
