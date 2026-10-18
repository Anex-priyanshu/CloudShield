# CloudShield – Cloud Security Posture Assessment Platform

> **Internship Project** | Priyanshu Patel | B.Tech Cyber Security, Indus University  
> Cloud Security Intern @ Techmicra IT Solutions (24 Sep – 24 Oct 2026)

---

## What is CloudShield?

CloudShield is a full-stack web platform for Cloud Security Posture Management (CSPM). It scans AWS accounts for misconfigurations, prioritises findings with a contextual risk score (Severity × Exposure × Data Sensitivity), monitors CloudTrail logs in near real-time, and scans Terraform/CloudFormation files before deployment.

**Vision:** *"Not just what is wrong in your cloud, but what to fix first."*

---

## Quick Start (Docker Compose)

```bash
git clone <repo-url>
cd cloudshield
cp .env.example .env
# Edit .env and set your SECRET_KEY and FERNET_KEY (or use the generated ones)
docker compose up --build
```

Then open **http://localhost:3000**

Default credentials:
- Email: `admin@cloudshield.local`
- Password: `Admin@12345!`

---

## Manual Run (without Docker)

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:3000  
Backend API docs: http://localhost:8000/docs

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14 (App Router) + TypeScript + Tailwind CSS + shadcn/ui |
| Charts | Recharts |
| Real-time | WebSocket (FastAPI native) |
| Backend | Python 3.11 + FastAPI + Pydantic v2 |
| Cloud SDK | boto3 (AWS) |
| Database | SQLAlchemy 2 + SQLite (dev) / Postgres (prod) |
| IaC Scan | Checkov |
| Auth | JWT + bcrypt |
| Secrets | Fernet (cryptography) |
| PDF | WeasyPrint |

---

## Project Structure

```
cloudshield/
├── docker-compose.yml
├── .env.example
├── README.md
├── backend/
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── db.py, models.py, schemas.py
│       ├── auth/
│       ├── routers/
│       ├── services/
│       ├── collectors/
│       ├── checks/
│       ├── detections/
│       ├── demo/
│       └── tests/
└── frontend/
    ├── package.json
    └── src/
        ├── app/
        ├── components/
        ├── lib/
        └── styles/
```

---

## Demo Mode

No AWS account? No problem!

1. Login → Click **"Add Demo Account"**
2. Click **"Start Scan"**
3. Watch live findings stream in (25+ findings, 3+ Critical)

The demo uses a built-in seeded dataset of a deliberately insecure AWS account (public S3 buckets, IAM users without MFA, open security groups, etc.). All findings go through the same check engine and risk engine as real data.

---

## Security Checks (25 implemented)

| Category | Checks |
|---|---|
| IAM | Root MFA, Root access keys, User MFA, Old keys, Unused credentials, Admin policies, Direct policies, Password policy |
| Storage (S3) | Public bucket, Account-level public access, Encryption, Versioning, Access logging, HTTPS enforcement |
| Network | SSH open, RDP open, All-ports open, Default SG |
| Logging | CloudTrail enabled, Log validation |
| Encryption | EBS, RDS, KMS rotation |
| Backup | RDS backups, EBS snapshots |

## Detection Rules (10 implemented)

Root usage, Console login without MFA, New access key, CloudTrail stopped, SG opened to internet, S3 made public, Admin privileges granted, Multiple failed logins, MFA deactivated, Login from new IP.

---

## Risk Scoring

```
Risk Score = Severity × Exposure × Data Sensitivity   (each 1–5, result 1–125)
```

| Band | Score | Colour |
|---|---|---|
| Critical | 91–125 | Red |
| High | 51–90 | Orange |
| Medium | 21–50 | Yellow |
| Low | 1–20 | Blue |

---

## AWS Read-Only Policy

Attach these AWS managed policies to a dedicated IAM user/role named `cloudshield-readonly`:
- `SecurityAudit`
- `ViewOnlyAccess`

**⚠️ Scan only accounts you own or are authorised to assess.**

---

## Environment Variables

See `.env.example` for all required variables.

---

## Running Tests

```bash
cd backend
pytest app/tests/ -v
```

---

## Architecture Diagram

```
Browser (Next.js)
    │
    ├── REST API ──────► FastAPI Backend
    │                         │
    └── WebSocket ────────────┤
                              ├── SQLite/Postgres
                              ├── AWS (boto3, read-only)
                              ├── Checkov (IaC scan)
                              └── Demo Data (seeded JSON)
```

---

## Legal / Ethical Notice

This tool is for **educational and authorised security assessment purposes only**.  
- Use only on accounts you own or have written authorisation to assess.  
- All AWS API calls are **read-only** — no write, delete, or modify operations.  
- CloudTrail `LookupEvents` and Describe/List calls are **free** within AWS free tier limits.

---

*Built with ❤️ by Priyanshu Patel for Techmicra IT Solutions internship.*
