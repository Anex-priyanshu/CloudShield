"""End-to-end integration verification for CloudShield."""
import httpx
import time

def run():
    client = httpx.Client(base_url="http://127.0.0.1:8000/api/v1")

    # 1. Login
    r = client.post("/auth/login", json={"email": "admin@cloudshield.local", "password": "Admin@12345!"})
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[1/7] Login successful, JWT obtained")

    # 2. Create Demo Account
    r = client.post("/accounts/demo", headers=headers)
    assert r.status_code == 200, f"Create demo failed: {r.text}"
    account = r.json()
    account_id = account["id"]
    print(f"[2/7] Demo Account created: ID {account_id}, Name: {account['name']}")

    # 3. Start Scan
    r = client.post("/scans", json={"account_id": account_id}, headers=headers)
    assert r.status_code == 200, f"Start scan failed: {r.text}"
    scan_id = r.json()["id"]
    print(f"[3/7] Scan #{scan_id} triggered")

    # 4. Wait for scan completion (demo scan completes in ~1-3s)
    scan = {}
    for _ in range(15):
        time.sleep(1)
        r = client.get(f"/scans/{scan_id}", headers=headers)
        scan = r.json()
        if scan.get("status") == "completed":
            break
    assert scan.get("status") == "completed", f"Scan did not complete: {scan}"
    print(f"[4/7] Scan #{scan_id} completed: {scan['total_findings']} findings, Risk Score: {scan['account_risk_score']}/100")

    # 5. Check Findings
    r = client.get(f"/findings?scan_id={scan_id}", headers=headers)
    findings = r.json()
    items = findings.get("items", findings)
    assert len(items) >= 15, f"Expected >=15 findings, got {len(items)}"
    crit = [f for f in items if f.get("band") == "critical"]
    print(f"[5/7] Findings verified: Total {len(items)}, Critical findings: {len(crit)}")

    # 6. Test IaC Scanner Gate
    r = client.post("/iac/sample", data={"sample_type": "insecure"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["verdict"] == "FAIL", "Insecure sample must FAIL gate"
    print("[6/7] IaC Insecure sample deployment gate correctly returned FAIL")

    r = client.post("/iac/sample", data={"sample_type": "secure"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["verdict"] == "PASS", "Secure sample must PASS gate"
    print("      IaC Secure sample deployment gate correctly returned PASS")

    # 7. Test PDF Generation
    r = client.get(f"/reports/{scan_id}/pdf", headers=headers)
    assert r.status_code == 200
    assert r.headers.get("content-type") == "application/pdf"
    assert len(r.content) > 1000
    print(f"[7/7] PDF report generated successfully ({len(r.content)} bytes)")

    print("\n=======================================================")
    print(" ALL 7 END-TO-END VALIDATION PHASES PASSED 100%!")
    print("=======================================================")

if __name__ == "__main__":
    run()
