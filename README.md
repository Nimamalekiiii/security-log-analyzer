# Security Log Analyzer 🛡️

A Python-based cybersecurity tool for analyzing login logs and detecting suspicious authentication activity.

## 📌 About

Security Log Analyzer is a command-line security analysis tool developed to analyze authentication logs and identify potentially suspicious login behavior.

The tool processes login events, detects common attack patterns and assigns a risk score to each IP address.

The project uses synthetic log data for testing and demonstration purposes.

##  Security Detection

The analyzer currently detects:

- Brute-force login attempts
- Suspicious login patterns
- Multiple user accounts targeted from the same IP
- Possible account enumeration
- High numbers of failed login attempts

##  Risk Assessment

Each IP address receives a risk score from `0–100`.

The score is based on detected login activity and security findings.

| Score | Risk Level |
|---:|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

##  Features

- Login success and failure analysis
- IP-based analysis
- User-based analysis
- Brute-force detection
- Account enumeration detection
- Suspicious login pattern detection
- Automated risk scoring
- TXT report generation
- JSON report generation
- Custom output filenames
- Command-line interface
- Error handling
- Automated unit tests

##  Technologies

- Python
- `argparse`
- `json`
- `datetime`
- `unittest`

No external Python packages are required.

##  Project Structure

```text
security-log-analyzer/
├── analyzer.py
├── test_analyzer.py
├── security.log
├── README.md
└── .gitignore