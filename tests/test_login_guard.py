from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.config import settings
from app.db import async_session
from app.login_guard import client_ip, record_failure
from app.main import app
from app.models import IpBan

LOGIN = "/api/v1/auth/login"


def bad(client, user="admin"):
    return client.post(LOGIN, json={"username": user, "password": "wrong-password"})


def good(client):
    return client.post(LOGIN, json={"username": "admin", "password": "admin-password"})


def _request(peer, headers=None):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "client": (peer, 1234), "headers": raw})


def test_too_many_failures_ban_the_ip_even_for_the_right_password(client):
    for _ in range(settings.login_max_failures - 1):
        assert bad(client).status_code == 401
    res = bad(client, user="root")
    assert res.status_code == 429 and int(res.headers["retry-after"]) > 25 * 60
    assert good(client).status_code == 429


def test_successful_login_resets_the_counter(client):
    for _ in range(settings.login_max_failures - 1):
        bad(client)
    assert good(client).status_code == 200
    for _ in range(settings.login_max_failures - 1):
        assert bad(client).status_code == 401


def test_repeat_offender_gets_a_longer_ban(client):
    async def two_bans():
        async with async_session() as session:
            for _ in range(settings.login_max_failures):
                first = await record_failure(session, "45.155.205.233", "admin")
            first.until = datetime.utcnow() - timedelta(seconds=1)
            await session.commit()
            for _ in range(settings.login_max_failures):
                second = await record_failure(session, "45.155.205.233", "admin")
            return first.created_at, (second.until - second.created_at)

    _, second_length = client.portal.call(two_bans)
    assert second_length == timedelta(minutes=2 * settings.login_ban_minutes)


def test_exempt_and_trusted_proxy_addresses_are_never_banned(client, monkeypatch):
    monkeypatch.setattr(settings, "login_ban_exempt", "10.64.0.12")
    monkeypatch.setattr(settings, "trusted_proxy_ips", "172.18.0.0/16")

    async def failures(ip):
        async with async_session() as session:
            return [await record_failure(session, ip, "admin") for _ in range(settings.login_max_failures + 2)]

    assert all(b is None for b in client.portal.call(failures, "10.64.0.12"))
    assert all(b is None for b in client.portal.call(failures, "172.18.0.3"))
    assert client.portal.call(failures, "198.51.100.9")[-3] is not None


def test_real_ip_only_from_trusted_proxy_headers(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_ips", "172.18.0.0/16")
    # cloudflared (megbizhato) -> a CF-Connecting-IP a latogato.
    assert client_ip(_request("172.18.0.3", {"CF-Connecting-IP": "45.155.205.233"})) == "45.155.205.233"
    assert client_ip(_request("172.18.0.3", {"X-Forwarded-For": "45.155.205.233, 172.18.0.1"})) == "45.155.205.233"
    # Mas forrastol a fejlec hamisithato: a kapcsolat IP-je szamit.
    assert client_ip(_request("203.0.113.7", {"CF-Connecting-IP": "10.64.0.12"})) == "203.0.113.7"
    assert client_ip(_request("172.18.0.3", {"CF-Connecting-IP": "not-an-ip"})) == "172.18.0.3"
    assert client_ip(_request("10.64.0.20")) == "10.64.0.20"


def test_admin_lists_and_lifts_bans(logged_in):
    async def ban():
        async with async_session() as session:
            for _ in range(settings.login_max_failures):
                result = await record_failure(session, "198.51.100.9", "admin")
            return result.id

    ban_id = logged_in.portal.call(ban)
    bans = logged_in.get("/api/v1/security/bans").json()
    assert [b["ip"] for b in bans] == ["198.51.100.9"] and bans[0]["usernames"] == ["admin"]
    lifted = logged_in.delete(f"/api/v1/security/bans/{ban_id}").json()
    assert lifted["active"] is False and lifted["lifted_by"] == "admin"
    assert logged_in.get("/api/v1/security/bans").json() == []
    assert len(logged_in.get("/api/v1/security/bans?active_only=false").json()) == 1
    status = logged_in.get("/api/v1/system/status").json()["login_protection"]
    assert status["active_bans"] == 0 and status["bans_24h"] == 1

    logged_in.post("/api/v1/users", json={"username": "alice", "password": "analyst-pass", "role": "l2"})
    alice = TestClient(app)
    alice.post(LOGIN, json={"username": "alice", "password": "analyst-pass"})
    assert alice.get("/api/v1/security/bans").status_code == 403
