# 🛡️ CloudGuardAI

### AI-Powered AWS Cloud Security Monitoring & Risk Assessment Platform

CloudGuardAI is an AI-powered cloud security platform designed to scan AWS environments, identify security misconfigurations, analyze cloud security risks, calculate an overall security posture score, and provide AI-generated security recommendations.

The platform combines AWS security scanning, risk analysis, compliance checks, security scoring, and AI-powered remediation guidance into a centralized security dashboard.

---

## 🚀 Project Status

**Current Version:** V2.0.0  
**Status:** MVP Complete  
**Development Branch:** `v2-development`

CloudGuardAI V2 provides an end-to-end cloud security monitoring workflow:

```text
AWS Account
    ↓
Security Scanners
    ↓
Finding Collection
    ↓
Duplicate Detection
    ↓
Risk Classification
    ↓
Security Score
    ↓
AI Security Advisor
    ↓
FastAPI Backend
    ↓
Security Dashboard

✨ Key Features
🔍 AWS Security Scanning

CloudGuardAI scans multiple AWS services to identify potential security risks and misconfigurations.

Supported Scanners
🪣 Amazon S3
🔐 AWS IAM
💻 Amazon EC2
📜 AWS CloudTrail
📋 Compliance Checks
🔐 IAM Security Analysis

The IAM scanner analyzes AWS identity and access configurations.

It can identify issues such as:

Disabled MFA
Excessive administrative permissions
AdministratorAccess policies
Potential violations of least-privilege principles
🪣 S3 Security Monitoring

The S3 scanner analyzes bucket security configurations and checks for potential security issues related to AWS S3 resources.

💻 EC2 Security Monitoring

The EC2 scanner evaluates EC2-related security configurations and identifies potential risks in compute infrastructure.

📜 CloudTrail Activity Analysis

CloudGuardAI analyzes CloudTrail events to provide visibility into AWS account activity.

The system identifies relevant API activity and classifies findings based on risk level.

📋 Compliance Monitoring

CloudGuardAI includes compliance-oriented checks to identify security configurations that may violate recommended AWS security practices.

🤖 AI Security Advisor

CloudGuardAI includes an AI-powered security advisor that analyzes individual security findings.

For each finding, the system provides:

Risk level
Priority
Security analysis
Recommended action
Remediation guidance

Example workflow:

Security Finding
       ↓
Risk Analysis
       ↓
AI Security Advisor
       ↓
Security Explanation
       ↓
Recommended Action

The goal is to help users understand security findings instead of simply displaying raw scanner output.

📊 Security Risk Scoring

CloudGuardAI calculates an overall security posture score based on identified findings.

The system classifies findings into:

🔴 CRITICAL
🟠 HIGH
🟡 MEDIUM
🟢 LOW

Example:

Security Score: 32 / 100
Security Grade: F

Critical: 2
High:     3
Medium:   0
Low:      7

The scoring engine helps users quickly understand the overall security posture of their AWS environment.

🧹 Finding Deduplication

CloudGuardAI automatically removes duplicate security findings before calculating the final security posture.

This prevents the same underlying security issue from being counted multiple times.

Multiple Scanner Findings
        ↓
Finding Normalization
        ↓
Duplicate Detection
        ↓
Unique Security Findings
        ↓
Final Risk Assessment
🖥️ Security Command Center Dashboard

CloudGuardAI includes a Streamlit-based security dashboard designed to provide centralized visibility into AWS security posture.

The dashboard provides:

Security Score
Security Grade
Total Findings
Critical Issues
Risk Distribution
Security Findings
AI Security Advice
AWS Security Coverage
Scan Status
Security Reports

The dashboard acts as the central security command center for CloudGuardAI.

⚡ FastAPI Backend

CloudGuardAI provides a FastAPI backend for interacting with the security scanning engine.

Available Endpoints
Health Check
GET /health

Returns:

{
  "status": "healthy"
}
Root Endpoint
GET /

Returns basic application information.

Full Security Scan
POST /scan

Runs the complete AWS security scanning pipeline.

The response includes:

Project information
Scan status
Security summary
Security score
Security grade
Risk distribution
Security findings
AI security advice

Example:

{
  "project": "CloudGuardAI",
  "version": "2.0.0",
  "scan_status": "completed",
  "summary": {
    "total_findings": 10,
    "security_score": 34,
    "security_grade": "F"
  }
}
🏗️ Architecture
                         ┌─────────────────────┐
                         │     AWS Account     │
                         └──────────┬──────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 │                  │                  │
                 ▼                  ▼                  ▼
              S3 Scanner        IAM Scanner       EC2 Scanner
                 │                  │                  │
                 └──────────────────┼──────────────────┘
                                    │
                         ┌──────────▼──────────┐
                         │   CloudTrail Scanner │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │ Compliance Scanner  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Finding Collection  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Deduplication Engine│
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Security Risk Engine│
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │ Security Score/Grade│
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ AI Security Advisor │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    FastAPI Backend  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Security Dashboard  │
                         └─────────────────────┘
🧰 Tech Stack
Programming
Python 3.12
Backend
FastAPI
Uvicorn
AWS
AWS IAM
Amazon S3
Amazon EC2
AWS CloudTrail
Boto3
AI
AI Security Advisor
Automated Security Analysis
Remediation Recommendations
Frontend / Dashboard
Streamlit
Python Requests
Testing
Pytest
Development
Git
GitHub
Python Virtual Environment
📁 Project Structure
CloudGuardAI/
│
├── backend/
│   │
│   ├── api/
│   │   └── main.py
│   │
│   ├── dashboard/
│   │   ├── __init__.py
│   │   └── dashboard.py
│   │
│   ├── models/
│   │   └── finding.py
│   │
│   ├── scanners/
│   │   ├── s3_scanner.py
│   │   ├── iam_scanner.py
│   │   ├── ec2_scanner.py
│   │   ├── cloudtrail_scanner.py
│   │   ├── compliance_scanner.py
│   │   │
│   │   ├── test_s3_scanner.py
│   │   ├── test_iam_scanner.py
│   │   ├── test_ec2_scanner.py
│   │   ├── test_cloudtrail_scanner.py
│   │   └── test_compliance_scanner.py
│   │
│   └── services/
│       ├── scan_service.py
│       ├── security_engine.py
│       ├── ai_advisor.py
│       │
│       ├── test_scan_service.py
│       ├── test_security_engine.py
│       └── test_ai_advisor.py
│
├── requirements.txt
├── README.md
└── .gitignore
🚀 Installation
1. Clone the Repository
git clone https://github.com/NithishRaman/CloudGuardAI.git

Navigate into the project:

cd CloudGuardAI
2. Create a Virtual Environment
python3 -m venv .venv

Activate it:

macOS / Linux
source .venv/bin/activate
Windows
.venv\Scripts\activate
3. Install Dependencies
pip install -r requirements.txt
☁️ AWS Configuration

CloudGuardAI uses Boto3 to communicate with AWS services.

Configure your AWS credentials using the AWS CLI:

aws configure

Provide:

AWS Access Key ID
AWS Secret Access Key
Default Region
Output Format

Example region:

ap-south-1
Security Recommendation

For production environments, use an IAM role with the minimum permissions required for security scanning.

Avoid storing AWS credentials directly in source code.

▶️ Running CloudGuardAI
Start the FastAPI Backend

From the project root:

uvicorn backend.api.main:app --reload

The API will be available at:

http://127.0.0.1:8000

Health check:

curl http://127.0.0.1:8000/health

Run a full scan:

curl -X POST http://127.0.0.1:8000/scan
Start the Dashboard

Open another terminal.

Navigate to the project:

cd ~/CloudGuardAI

Activate the virtual environment:

source .venv/bin/activate

Run:

streamlit run backend/dashboard/dashboard.py

The dashboard will open in your browser.

🧪 Testing

Run the test suite using:

pytest

Run scanner tests:

pytest backend/scanners/

Run service tests:

pytest backend/services/
🔐 Security Considerations

CloudGuardAI is designed as a security monitoring and assessment platform.

When deploying or extending the platform:

Use least-privilege IAM permissions
Never commit AWS credentials
Never commit .env files
Use IAM roles where possible
Secure API endpoints before production deployment
Add authentication and authorization for production use
Validate all AWS API inputs
Protect security reports containing sensitive information
🗺️ Roadmap
V2 — MVP
 AWS S3 scanning
 IAM scanning
 EC2 scanning
 CloudTrail analysis
 Compliance scanning
 Finding deduplication
 Risk classification
 Security scoring
 Security grading
 AI Security Advisor
 FastAPI backend
 Security dashboard
 Automated tests
V3 — Advanced Cloud Security Platform

Planned features:

 Advanced risk scoring engine
 CVSS-inspired security scoring
 Attack path analysis
 Cross-service security correlation
 AWS GuardDuty integration
 AWS Security Hub integration
 EventBridge integration
 Real-time security monitoring
 AI Security Copilot
 Natural language security queries
 AI-generated remediation plans
 Automated remediation workflows
 Multi-account AWS support
 Cloud security posture management
 Professional React + TypeScript frontend
 Production deployment
 Docker support
 CI/CD pipeline
🎯 Vision

The long-term goal of CloudGuardAI is to evolve into an intelligent Cloud Security Posture Management platform that continuously monitors AWS environments, identifies security risks, explains vulnerabilities using AI, and helps cloud teams prioritize and remediate security issues.

Detect
   ↓
Analyze
   ↓
Prioritize
   ↓
Explain
   ↓
Remediate
   ↓
Monitor
👨‍💻 Author

Nithish Raman

B.Tech — Artificial Intelligence & Data Science

Interested in:

Artificial Intelligence
Cloud Computing
AWS
Cloud Security
Cybersecurity
Machine Learning
AI Engineering
⭐ Contributing

Contributions, suggestions, and improvements are welcome.

If you would like to contribute:

Fork the repository
Create a feature branch
Make your changes
Add tests where applicable
Submit a pull request
📄 License

This project is licensed under the terms of the MIT License.
