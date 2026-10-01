from fastapi.testclient import TestClient

from app.main import app

from conftest import WEBHOOK_HEADERS, wazuh_alert


def _create_user(admin_client, username, role="analyst"):
    res = admin_client.post(
        "/api/v1/users",
        json={"username": username, "password": "analyst-pass", "role": role},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _login(username, password="analyst-pass") -> TestClient:
    # separate client = separate cookie jar; shares the app (and its event loop setup)
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 200
    return c


def _escalated_case(client) -> int:
    body = client.post("/api/v1/alerts", json=wazuh_alert(level=13), headers=WEBHOOK_HEADERS).json()
    return body["case"]["case_id"]


def test_wrong_password_is_rejected(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    assert res.status_code == 401


def test_analyst_cannot_use_admin_endpoints(logged_in):
    _create_user(logged_in, "alice")
    alice = _login("alice")
    assert alice.get("/api/v1/users").status_code == 403


def test_analyst_case_assignment_rules(logged_in):
    alice_id = _create_user(logged_in, "alice")
    bob_id = _create_user(logged_in, "bob")
    case_id = _escalated_case(logged_in)
    alice, bob = _login("alice"), _login("bob")

    # an analyst can take an unowned case for themselves...
    assert alice.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": alice_id}).status_code == 200
    # ...but cannot take someone else's, or assign it to another user
    assert bob.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": bob_id}).status_code == 403
    assert bob.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": None}).status_code == 403
    # the owner can release it; the admin can assign it to anyone
    assert alice.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": None}).status_code == 200
    assert logged_in.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": bob_id}).status_code == 200

    alert = logged_in.get("/api/v1/alerts").json()[0]
    assert alert["assignee"]["username"] == "bob"


def test_unknown_case_cannot_be_assigned(logged_in):
    assert logged_in.put("/api/v1/cases/424242/assignee", json={"user_id": 1}).status_code == 404
