"""
Midnight-Core Go service client.

Drop this into your Midnight-Core Python backend to call the Go compliance
analysis service instead of (or alongside) the Groq/LLaMA integration.

Install deps:
    pip install requests sseclient-py
"""

import json
import requests
import sseclient

GO_SERVICE_URL = "http://localhost:8080"

SUPPORTED_FRAMEWORKS = ["HIPAA", "SOC2", "PCI_DSS", "ISO_27001", "NIST_CSF", "HITRUST"]


def analyze(document: str, frameworks: list[str], title: str = "") -> dict:
    """
    Synchronous compliance analysis.
    Blocks until Claude finishes assessing all controls, then returns the full result.

    Returns a dict matching AnalysisResult:
        {
            "title": str,
            "frameworks": [
                {
                    "framework": str,
                    "assessments": [...],
                    "covered_count": int,
                    "partial_count": int,
                    "gap_count": int,
                    "coverage_percent": float
                }
            ]
        }
    """
    resp = requests.post(
        f"{GO_SERVICE_URL}/analyze",
        json={"title": title, "document": document, "frameworks": frameworks},
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()


def analyze_stream(document: str, frameworks: list[str], title: str = ""):
    """
    Streaming compliance analysis via SSE.
    Yields progress events in real time as Claude assesses each control,
    then yields the final result dict.

    Yields dicts of two shapes:
        {"type": "framework_start", "framework": str, "message": str}
        {"type": "control_assessed", "framework": str, "control_id": str,
         "control_name": str, "status": "covered"|"partial"|"gap"}
        {"type": "result", ...AnalysisResult fields...}

    Raises RuntimeError on server-side errors.

    Example:
        for event in analyze_stream(doc, ["HIPAA", "SOC2"], title="My Policy"):
            if event["type"] == "control_assessed":
                icon = {"covered": "✓", "partial": "~", "gap": "✗"}.get(event["status"], "?")
                print(f"  {icon} [{event['framework']}] {event['control_id']} — {event['status']}")
            elif event["type"] == "result":
                print(f"Done — {event['frameworks'][0]['coverage_percent']:.1f}% coverage")
    """
    with requests.post(
        f"{GO_SERVICE_URL}/analyze/stream",
        json={"title": title, "document": document, "frameworks": frameworks},
        stream=True,
        timeout=180,
    ) as resp:
        resp.raise_for_status()
        client = sseclient.SSEClient(resp)
        for event in client.events():
            data = json.loads(event.data)
            if event.event == "progress":
                yield data
            elif event.event == "result":
                yield {"type": "result", **data}
                return
            elif event.event == "error":
                raise RuntimeError(data.get("error", "unknown error from Go service"))


def health() -> dict:
    """Check that the Go service is up."""
    resp = requests.get(f"{GO_SERVICE_URL}/health", timeout=5)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Quick demo — run with: python examples/python_client.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Checking service health...")
    print(health())

    document = """
    Information Security Policy

    1. Access Control
    All systems require multi-factor authentication. Access rights are reviewed
    quarterly and revoked immediately upon employee termination. Role-based access
    control is enforced across all production environments.

    2. Incident Response
    Security incidents must be reported to the security team within 1 hour of
    discovery. We maintain a documented incident response plan reviewed annually.
    Post-incident reviews are conducted for all severity-1 events.

    3. Encryption
    All data at rest is encrypted using AES-256. Data in transit uses TLS 1.3.
    Encryption keys are rotated annually and managed via our key management system.

    4. Vendor Management
    Third-party vendors with access to sensitive data must sign a BAA and complete
    an annual security questionnaire.
    """

    print("\n=== Streaming analysis (HIPAA + SOC2) ===\n")
    for event in analyze_stream(document, ["HIPAA", "SOC2"], title="InfoSec Policy v1"):
        t = event.get("type", "")
        if t == "framework_start":
            print(f"\n[{event['framework']}] {event['message']}")
        elif t == "control_assessed":
            icon = {"covered": "✓", "partial": "~", "gap": "✗"}.get(event["status"], "?")
            print(f"  {icon}  {event['control_id']:25s}  {event['status']}")
        elif t == "result":
            print("\n=== Summary ===")
            for fw in event.get("frameworks", []):
                pct = fw["coverage_percent"]
                bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
                print(
                    f"  {fw['framework']:10s}  [{bar}] {pct:5.1f}%  "
                    f"✓{fw['covered_count']} ~{fw['partial_count']} ✗{fw['gap_count']}"
                )
