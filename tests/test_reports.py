# Bejelentkezeshez kotott riportok.


def test_report_requires_login(client):
    res = client.get("/reports/4-tablazat", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/ui/login.html?next=/reports/4-tablazat"


def test_report_is_served_after_login(logged_in):
    res = logged_in.get("/reports/4-tablazat")
    assert res.status_code == 200 and res.headers["content-type"].startswith("text/html")
    assert "4. táblázat Az összesített hatékonyságmérés mutatói" in res.text
    assert res.headers["cache-control"] == "no-store"


def test_unknown_or_unsafe_report_name(logged_in):
    assert logged_in.get("/reports/nincs-ilyen").status_code == 404
    assert logged_in.get("/reports/..%2Fmain").status_code == 404
    assert logged_in.get("/reports/4-TABLAZAT").status_code == 404
