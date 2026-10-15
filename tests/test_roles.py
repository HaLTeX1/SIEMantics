import pytest
from fastapi.testclient import TestClient

from app.main import app

from conftest import process_alert, wazuh_alert
from test_response import wazuh  # noqa: F401


def user_client(admin_client, username, role="analyst", response_allowed=False) -> TestClient:
    res = admin_client.post("/api/v1/users", json={"username": username, "password": "analyst-pass",
                                                   "role": role, "response_allowed": response_allowed})
    assert res.status_code == 201, res.text
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": username, "password": "analyst-pass"}).status_code == 200
    return c


def suppress(client, display_id):
    return client.post("/api/v1/suppressions", json={"alert_refs": [display_id]})


def block(client, display_id):
    return client.post(f"/api/v1/alerts/{display_id}/block-ip", json={"ip": "45.155.205.10", "duration_hours": 1})


def test_me_reports_permissions(logged_in):
    analyst = user_client(logged_in, "alice")
    l2 = user_client(logged_in, "bob", role="l2")
    responder = user_client(logged_in, "carol", response_allowed=True)
    me = {c: c.get("/api/v1/auth/me").json() for c in (analyst, l2, responder, logged_in)}
    assert (me[analyst]["can_suppress"], me[analyst]["can_block_ip"]) == (False, False)
    assert (me[l2]["role"], me[l2]["can_suppress"], me[l2]["can_block_ip"]) == ("l2", True, True)
    assert (me[responder]["can_suppress"], me[responder]["can_block_ip"]) == (False, True)
    assert (me[logged_in]["can_suppress"], me[logged_in]["can_block_ip"]) == (True, True)


@pytest.mark.parametrize("role,allowed", [("analyst", False), ("l2", True)])
def test_suppression_needs_l2(logged_in, role, allowed):
    alert = process_alert(logged_in, wazuh_alert(alert_id="s1"))
    client = user_client(logged_in, "user1", role=role)
    res = suppress(client, alert["display_id"])
    assert res.status_code == (200 if allowed else 403)
    if allowed:
        rule_id = res.json()["rules"][0]["id"]
        assert client.delete(f"/api/v1/suppressions/{rule_id}").status_code == 200
    # A szabalyok listaja mindenkinek lathato.
    assert client.get("/api/v1/suppressions").status_code == 200


def test_analyst_cannot_deactivate_rules(logged_in):
    alert = process_alert(logged_in, wazuh_alert(alert_id="s2"))
    rule_id = suppress(logged_in, alert["display_id"]).json()["rules"][0]["id"]
    analyst = user_client(logged_in, "user2")
    assert analyst.delete(f"/api/v1/suppressions/{rule_id}").status_code == 403


@pytest.mark.parametrize("role,response_allowed,allowed", [
    ("analyst", False, False),
    ("analyst", True, True),
    ("l2", False, True),
])
def test_block_ip_needs_l2_or_permission(logged_in, iris, wazuh, role, response_allowed, allowed):  # noqa: F811
    alert = process_alert(logged_in, wazuh_alert(alert_id="b1", level=13, agent={"id": "001", "name": "web01"}))
    client = user_client(logged_in, "user3", role=role, response_allowed=response_allowed)
    assert block(client, alert["display_id"]).status_code == (200 if allowed else 403)


def test_admin_grants_and_revokes_response_permission(logged_in, iris, wazuh):  # noqa: F811
    alert = process_alert(logged_in, wazuh_alert(alert_id="b2", level=13, agent={"id": "001", "name": "web01"}))
    analyst = user_client(logged_in, "user4")
    user_id = analyst.get("/api/v1/auth/me").json()["id"]
    assert block(analyst, alert["display_id"]).status_code == 403
    assert logged_in.patch(f"/api/v1/users/{user_id}", json={"response_allowed": True}).json()["can_block_ip"] is True
    assert block(analyst, alert["display_id"]).status_code == 200
    logged_in.patch(f"/api/v1/users/{user_id}", json={"response_allowed": False})
    assert block(analyst, alert["display_id"]).status_code == 403
