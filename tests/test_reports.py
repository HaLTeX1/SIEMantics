# Bejelentkezeshez kotott riportok.

from conftest import process_alert, wazuh_alert


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


def _row(html: str, label: str) -> str:
    start = html.index(f"<td>{label}</td><td>") + len(f"<td>{label}</td><td>")
    return html[start:html.index("</td>", start)]


def test_table4_is_built_from_the_decision_log(logged_in, iris):
    # Ket valodi (Wazuh formatumu azonositoju) riasztas cimkevel, egy webhookos teszt kimarad.
    tp = process_alert(logged_in, wazuh_alert(alert_id="1700000000.1", level=13, data={"srcip": "198.51.100.1"}))
    tn = process_alert(logged_in, wazuh_alert(alert_id="1700000000.2", level=2, data={"srcip": "198.51.100.2"}))
    process_alert(logged_in, wazuh_alert(alert_id="t5-teszt", level=13, data={"srcip": "198.51.100.3"}))
    logged_in.patch(f"/api/v1/alerts/{tp['display_id']}/label", json={"ground_truth": "true_positive"})
    logged_in.patch(f"/api/v1/alerts/{tn['display_id']}/label", json={"ground_truth": "false_positive"})

    html = logged_in.get("/reports/4-tablazat").text
    assert "$" not in html.split("</style>")[1]
    assert _row(html, "Feldolgozott riasztások száma") == "2 db"
    assert _row(html, "Ellenőrzött és címkézett riasztások száma") == "2 db"
    assert (_row(html, "True Positive (TP)"), _row(html, "True Negative (TN)")) == ("1", "1")
    assert _row(html, "Accuracy / Precision / Recall / F1") == "100,0 % / 100,0 % / 100,0 % / 100,0 %"
    assert _row(html, "Téves pozitív arány (FPR)") == "0,0 %"
    assert "frissítve:" in html
