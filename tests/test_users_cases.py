from fastapi.testclient import TestClient

from app.main import app

from conftest import process_alert, wazuh_alert


def _create_user(admin_client, username, role="analyst"):
    res = admin_client.post(
        "/api/v1/users",
        json={"username": username, "password": "analyst-pass", "role": role},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _login(username, password="analyst-pass") -> TestClient:
    # Kulon kliens = kulon cookie; ugyanaz az app.
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 200
    return c


def _escalated_case(client) -> int:
    return process_alert(client, wazuh_alert(level=13))["iris_case_id"]


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

    # Analyst magahoz veheti a gazdatlan esetet...
    assert alice.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": alice_id}).status_code == 200
    # ...de maset nem veheti el, es masnak sem adhatja.
    assert bob.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": bob_id}).status_code == 403
    assert bob.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": None}).status_code == 403
    # A gazda leadhatja; az admin barkihez rendelheti.
    assert alice.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": None}).status_code == 200
    assert logged_in.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": bob_id}).status_code == 200

    alert = logged_in.get("/api/v1/alerts").json()[0]
    assert alert["assignee"]["username"] == "bob"


def test_unknown_case_cannot_be_assigned(logged_in):
    assert logged_in.put("/api/v1/cases/424242/assignee", json={"user_id": 1}).status_code == 404


def test_admin_deletes_a_user_and_their_cases_become_unassigned(logged_in):
    alice_id = _create_user(logged_in, "alice")
    alice = _login("alice")
    case_id = _escalated_case(logged_in)
    assert alice.put(f"/api/v1/cases/{case_id}/assignee", json={"user_id": alice_id}).status_code == 200
    # Naplo-hivatkozas: alice hoz letre egy elnyomo szabalyt (L2 jog kell hozza).
    logged_in.patch(f"/api/v1/users/{alice_id}", json={"role": "l2"})
    alert_ref = logged_in.get("/api/v1/alerts").json()[0]["display_id"]
    rule = alice.post("/api/v1/suppressions", json={"alert_refs": [alert_ref], "apply_existing": False}).json()["rules"][0]

    res = logged_in.delete(f"/api/v1/users/{alice_id}")
    assert res.status_code == 200 and res.json() == {"deleted": "alice", "released_cases": [case_id]}
    assert all(u["username"] != "alice" for u in logged_in.get("/api/v1/users").json())
    # A munkamenete azonnal megszunik, az esete felelos nelkuli, a szabaly megmarad szerzo nelkul.
    assert alice.get("/api/v1/auth/me").status_code == 401
    assert logged_in.get(f"/api/v1/alerts/{alert_ref}").json()["assignee"] is None
    kept = next(r for r in logged_in.get("/api/v1/suppressions").json() if r["id"] == rule["id"])
    assert kept["created_by"] is None


def test_admin_cannot_delete_themselves_and_analysts_cannot_delete(logged_in):
    me = logged_in.get("/api/v1/auth/me").json()
    assert logged_in.delete(f"/api/v1/users/{me['id']}").status_code == 400
    bob_id = _create_user(logged_in, "bob")
    _create_user(logged_in, "carol")
    assert _login("carol").delete(f"/api/v1/users/{bob_id}").status_code == 403
    assert logged_in.delete("/api/v1/users/999999").status_code == 404
