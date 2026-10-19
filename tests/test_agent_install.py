import hashlib
import subprocess

import pytest
from fastapi.testclient import TestClient

from app import agent_install
from app.config import settings
from app.main import app

CMD = "/api/v1/agent-install/command"


@pytest.fixture(autouse=True)
def defaults(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_manager_address", "10.64.0.82")
    monkeypatch.setattr(settings, "wazuh_agent_version", "4.14.5")
    monkeypatch.setattr(settings, "siemantics_public_url", "http://10.64.0.127:8000")


def test_linux_command(logged_in):
    res = logged_in.post(CMD, json={"os": "linux", "name": "web01", "group": "linux,web"})
    assert res.status_code == 200, res.text
    assert res.json()["command"] == ("curl -fsSL 'http://10.64.0.127:8000/agent-install/linux.sh?manager=10.64.0.82"
                                     "&version=4.14.5' | sudo bash -s -- --name 'web01' --group 'linux,web'")


def test_windows_command(logged_in):
    command = logged_in.post(CMD, json={"os": "windows", "name": "HL-AD-CORE01"}).json()["command"]
    assert command.startswith("powershell -NoProfile -ExecutionPolicy Bypass -Command")
    assert "agent-install/windows.ps1?manager=10.64.0.82&version=4.14.5" in command
    assert command.endswith(" -Name 'HL-AD-CORE01'\"") and "-Group" not in command


@pytest.mark.parametrize("body", [
    {"os": "linux", "name": "web01'; rm -rf / #"},
    {"os": "linux", "name": "web01", "group": "a b"},
    {"os": "windows", "name": "pc", "manager": "10.64.0.82; calc"},
    {"os": "linux", "name": "pc", "version": "latest"},
])
def test_unsafe_values_are_rejected(logged_in, body):
    assert logged_in.post(CMD, json=body).status_code == 422


def test_only_admins_generate_commands(logged_in):
    logged_in.post("/api/v1/users", json={"username": "bob", "password": "analyst-pass", "role": "l2"})
    bob = TestClient(app)
    bob.post("/api/v1/auth/login", json={"username": "bob", "password": "analyst-pass"})
    assert bob.post(CMD, json={"os": "linux"}).status_code == 403
    assert bob.get("/api/v1/agent-install/defaults").status_code == 403


def test_linux_installer_is_valid_bash_with_the_checksum(client, tmp_path):
    res = client.get("/agent-install/linux.sh?manager=10.64.0.82&version=4.14.5")
    assert res.status_code == 200 and res.headers["cache-control"] == "no-store"
    script = res.text
    expected = hashlib.sha256(agent_install.ar_file("siemantics-isolate")).hexdigest()
    assert 'MANAGER="10.64.0.82"' in script and 'VERSION="4.14.5"' in script and expected in script
    assert 'BASE="http://10.64.0.127:8000"' in script
    path = tmp_path / "linux.sh"
    path.write_text(script)
    assert subprocess.run(["bash", "-n", str(path)], capture_output=True).returncode == 0


def test_windows_installer_carries_both_checksums(client):
    script = client.get("/agent-install/windows.ps1").text
    for name in ("siemantics-isolate.cmd", "siemantics-isolate.ps1"):
        assert hashlib.sha256(agent_install.ar_file(name)).hexdigest() in script
    assert '$Manager = "10.64.0.82"' in script


def test_files_are_served_byte_exact(client):
    res = client.get("/agent-install/files/siemantics-isolate.ps1")
    assert res.status_code == 200 and res.content.startswith(b"\xef\xbb\xbf")
    assert res.content == agent_install.ar_file("siemantics-isolate.ps1")
    assert client.get("/agent-install/files/..%2F..%2Fapp%2Fconfig.py").status_code == 404
    assert client.get("/agent-install/files/config.py").status_code == 404


def test_invalid_query_values_are_rejected(client):
    assert client.get("/agent-install/linux.sh?manager=$(id)").status_code == 422
