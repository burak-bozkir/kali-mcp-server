"""
API route tests through Flask's test client.

No Kali tool runs: the `fake_exec` fixture (conftest.py) stands in for the
process, so each tool endpoint still builds its real command, goes through
run_tool() / run_executor(), and is recorded in the SQLite history.
"""
import shlex
import uuid

import pytest

from .test_findings import NMAP_OUTPUT


# --------------------------------------------------------------------------- basics
def test_dashboard_is_served(client):
    for path in ("/", "/dashboard"):
        r = client.get(path)
        assert r.status_code == 200
        assert "<html" in r.get_data(as_text=True).lower()


def test_socketio_client_is_vendored(client):
    r = client.get("/static/socket.io.min.js")
    assert r.status_code == 200
    r.close()


def test_health(client):
    data = client.get("/health").get_json()
    assert data["status"] == "healthy"
    assert data["available_tools_count"] == data["total_tools_count"] == 5
    assert data["command_endpoint_enabled"] is False


def test_command_endpoint_off_by_default(client):
    r = client.post("/api/command", json={"command": "id"})
    assert r.status_code == 403


# --------------------------------------------------------------------------- tool endpoints
@pytest.mark.parametrize("tool,body", [
    ("nmap", {}),
    ("nmap", {"target": ""}),
    ("gobuster", {}),
    ("nikto", {}),
    ("sqlmap", {}),
])
def test_tool_requires_target(client, fake_exec, tool, body):
    r = client.post(f"/api/tools/{tool}", json=body)
    assert r.status_code == 400
    assert fake_exec.commands == []


@pytest.mark.parametrize("target", ["10.0.0.5; rm -rf /", "$(id)", "a b", "x" * 300])
def test_nmap_rejects_bad_target(client, fake_exec, target):
    r = client.post("/api/tools/nmap", json={"target": target})
    assert r.status_code == 400
    assert fake_exec.commands == []


def test_bad_timeout_is_400(client, fake_exec):
    r = client.post("/api/tools/nmap", json={"target": "10.0.0.5", "timeout": "soon"})
    assert r.status_code == 400
    assert "timeout" in r.get_json()["error"]


def test_nmap_command_is_built_from_params(client, fake_exec):
    r = client.post("/api/tools/nmap", json={
        "target": "10.0.0.5", "scan_type": "-sV", "ports": "22,80",
        "additional_args": "-T4"})
    assert r.status_code == 200
    assert fake_exec.commands == ["nmap -sV -p 22,80 -T4 10.0.0.5"]


def test_url_with_ampersand_stays_one_argument(client, fake_exec):
    url = "http://10.0.0.5/item.php?id=1&cat=2"
    r = client.post("/api/tools/sqlmap", json={"url": url})
    assert r.status_code == 200
    assert url in shlex.split(fake_exec.commands[0])


def test_sync_scan_result(client, fake_exec):
    fake_exec.stdout = NMAP_OUTPUT
    data = client.post("/api/tools/nmap", json={"target": "10.0.0.5"}).get_json()
    assert data["success"] is True
    assert data["status"] == "completed"
    assert data["stdout"] == NMAP_OUTPUT
    assert data["history_id"]
    assert data["timeout"] > 0


# --------------------------------------------------------------------------- history + findings
@pytest.fixture()
def nmap_scan(client, fake_exec):
    """Run one fake nmap scan and return its history id."""
    fake_exec.stdout = NMAP_OUTPUT
    data = client.post("/api/tools/nmap", json={"target": "10.0.0.5"}).get_json()
    return data["history_id"]


def test_scan_is_in_history(client, nmap_scan):
    data = client.get("/api/history?tool=nmap&limit=500").get_json()
    assert data["success"] is True
    assert data["filtered_by_tool"] == "nmap"
    assert nmap_scan in [h["id"] for h in data["history"]]


def test_history_detail(client, nmap_scan):
    r = client.get(f"/api/history/detail/{nmap_scan}")
    assert r.status_code == 200
    cmd = r.get_json()["command"]
    assert cmd["target"] == "10.0.0.5"
    assert cmd["stdout"] == NMAP_OUTPUT


def test_history_detail_unknown_id(client):
    assert client.get(f"/api/history/detail/{uuid.uuid4()}").status_code == 404


def test_history_stats(client, nmap_scan):
    data = client.get("/api/history/stats").get_json()
    assert data["success"] is True


def test_findings_endpoint_parses_the_scan(client, nmap_scan):
    r = client.get(f"/api/history/{nmap_scan}/findings")
    assert r.status_code == 200
    data = r.get_json()
    assert data["tool"] == "nmap" and data["scan_id"] == nmap_scan
    assert {p["port"] for p in data["ports"]} == {"21", "22", "80", "3306"}
    assert data["summary"]["high"] >= 2


def test_findings_endpoint_unknown_id(client):
    assert client.get(f"/api/history/{uuid.uuid4()}/findings").status_code == 404


# --------------------------------------------------------------------------- async scans
def test_async_scan_and_polling(client, fake_exec):
    fake_exec.stdout = "line one\nline two\nline three\n"
    scan_id = str(uuid.uuid4())
    r = client.post("/api/tools/nmap", json={"target": "10.0.0.5", "async": True,
                                             "scan_id": scan_id})
    assert r.status_code == 202
    body = r.get_json()
    assert body["scan_id"] == scan_id
    assert body["status_url"] == f"/api/scans/{scan_id}"

    # The fake process finishes instantly; wait for the thread to record it.
    import time
    for _ in range(100):
        snap = client.get(f"/api/scans/{scan_id}").get_json()
        if snap["status"] == "completed":
            break
        time.sleep(0.02)
    assert snap["status"] == "completed"
    assert [line["line"] for line in snap["lines"]] == ["line one", "line two", "line three"]
    assert snap["history_id"]

    # Pull from an offset, like the dashboard does
    snap = client.get(f"/api/scans/{scan_id}?since=2").get_json()
    assert [line["line"] for line in snap["lines"]] == ["line three"]
    assert snap["next"] == 3


def test_unknown_scan_is_404(client):
    assert client.get(f"/api/scans/{uuid.uuid4()}").status_code == 404
    assert client.post(f"/api/scans/cancel/{uuid.uuid4()}").status_code == 404


def test_active_scans_list(client):
    data = client.get("/api/scans/active").get_json()
    assert data["success"] is True and isinstance(data["scans"], list)


# --------------------------------------------------------------------------- templates
def test_builtin_templates_are_seeded(client):
    data = client.get("/api/templates").get_json()
    builtin = [t for t in data["templates"] if t["builtin"]]
    assert len(builtin) == 8


def test_builtin_template_is_protected(client):
    tpl = next(t for t in client.get("/api/templates").get_json()["templates"] if t["builtin"])
    assert client.put(f"/api/templates/{tpl['id']}", json={"name": "x"}).status_code == 403
    assert client.delete(f"/api/templates/{tpl['id']}").status_code == 403


def test_template_crud(client):
    r = client.post("/api/templates", json={"name": "Hızlı tarama", "tool": "nmap",
                                            "params": "-F", "target": "10.0.0.5"})
    assert r.status_code == 201
    tpl = r.get_json()["template"]
    assert tpl["builtin"] is False and tpl["name"] == "Hızlı tarama"

    r = client.put(f"/api/templates/{tpl['id']}", json={"params": "-sV"})
    assert r.status_code == 200 and r.get_json()["template"]["params"] == "-sV"
    assert client.get(f"/api/templates/{tpl['id']}").get_json()["template"]["params"] == "-sV"

    assert client.delete(f"/api/templates/{tpl['id']}").status_code == 200
    assert client.get(f"/api/templates/{tpl['id']}").status_code == 404


@pytest.mark.parametrize("body", [{"tool": "nmap"}, {"name": "x", "tool": "rm"}, {}])
def test_template_validation(client, body):
    assert client.post("/api/templates", json=body).status_code == 400


# --------------------------------------------------------------------------- recon workflows
@pytest.mark.parametrize("body", [
    {},
    {"target": "10.0.0.0/24"},
    {"target": "http://10.0.0.5"},
    {"target": "10.0.0.5; id"},
])
def test_recon_rejects_bad_target(client, fake_exec, body):
    assert client.post("/api/workflows/recon", json=body).status_code == 400
    assert fake_exec.commands == []


def test_recon_rejects_bad_workflow_id(client, fake_exec):
    r = client.post("/api/workflows/recon", json={"target": "10.0.0.5",
                                                  "workflow_id": "not-a-uuid"})
    assert r.status_code == 400


def test_unknown_workflow(client):
    wid = str(uuid.uuid4())
    assert client.get(f"/api/workflows/{wid}").status_code == 404
    assert client.post(f"/api/workflows/{wid}/cancel").status_code == 404


def test_workflow_list(client):
    data = client.get("/api/workflows").get_json()
    assert data["success"] is True and isinstance(data["workflows"], list)
