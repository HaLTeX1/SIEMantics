from app import pipeline

from conftest import WEBHOOK_HEADERS, process_alert, wazuh_alert

MERGE = "/api/v1/cases/merge"


def alert(alert_id, level=13, host="h1", srcip="198.51.100.1", rule_id="100"):
    # Mas host / IP / szabaly, hogy a korrelacio ne vonja ossze oket magatol.
    payload = wazuh_alert(alert_id=alert_id, level=level, agent={"id": "001", "name": host, "ip": "10.0.0.5"},
                          data={"srcip": srcip})
    payload["rule"]["id"] = rule_id
    return payload


def get(client, display_id):
    return client.get(f"/api/v1/alerts/{display_id}").json()


# --- merge

def test_merge_two_cases_into_the_earliest(logged_in, iris):
    first = process_alert(logged_in, alert("a1", host="h1", srcip="198.51.100.1", rule_id="101"))
    second = process_alert(logged_in, alert("a2", host="h2", srcip="198.51.100.2", rule_id="102"))
    assert first["iris_case_id"] != second["iris_case_id"]

    res = logged_in.post(MERGE, json={"alert_refs": [second["display_id"], first["display_id"]]})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["iris_case_id"] == first["iris_case_id"]
    assert body["target"] == first["display_id"] and body["merged"] == [second["display_id"]]
    assert body["closed_cases"] == [second["iris_case_id"]]

    moved = get(logged_in, second["display_id"])
    assert moved["iris_case_id"] == first["iris_case_id"]
    assert moved["correlated_with"] == first["display_id"]
    # Osszevonasi note a celesetben, a regi eset lezarva egy mutato note-tal.
    target_notes = [n for n in iris.notes if n[0] == first["iris_case_id"]]
    assert "Merged alerts" in target_notes[0][2][0][0] and second["display_id"] in target_notes[0][2][0][1]
    assert second["iris_case_id"] in iris.closed
    assert "merged" in iris.tags[first["iris_case_id"]]


def test_merge_flood_alerts_without_case(logged_in, iris):
    case_alert = process_alert(logged_in, alert("f0"))
    # needs_review riasztasok (6-os szint, minta nelkul), nincs esetuk.
    flood = [process_alert(logged_in, alert(f"f{i}", level=6, host=f"x{i}", srcip=f"203.0.113.{i}")) for i in (1, 2, 3)]
    assert all(f["status"] == "needs_review" and f["iris_case_id"] is None for f in flood)

    refs = [case_alert["display_id"]] + [f["display_id"] for f in flood]
    body = logged_in.post(MERGE, json={"alert_refs": refs}).json()
    assert body["iris_case_id"] == case_alert["iris_case_id"]
    assert sorted(body["merged"]) == sorted(f["display_id"] for f in flood)
    assert body["closed_cases"] == []

    record = get(logged_in, flood[0]["display_id"])
    assert record["status"] == "escalated" and record["auto_status"] == "needs_review"
    assert record["escalated_by"]["username"] == "admin"
    # Az osszevonas nem itelet: nincs cimke.
    assert record["ground_truth"] is None


def test_merge_without_open_case_only_groups(logged_in, iris):
    # Pl. tobb FP: nincs nyitott IRIS eset, igy csak SIEMantics csoport lesz.
    a = process_alert(logged_in, alert("n1", level=6, host="x1", srcip="203.0.113.1"))
    b = process_alert(logged_in, alert("n2", level=2, host="x2", srcip="203.0.113.2"))
    body = logged_in.post(MERGE, json={"alert_refs": [a["display_id"], b["display_id"]]}).json()

    assert body["iris_case_id"] is None and body["case_url"] is None
    assert body["group"] == a["display_id"] and body["merged"] == [b["display_id"]]
    assert iris.calls == [] and iris.notes == []
    record = get(logged_in, b["display_id"])
    # Nem eszkalalodik, a statusz es a cimke valtozatlan.
    assert record["status"] == "suppressed" and record["iris_case_id"] is None and record["ground_truth"] is None
    assert record["group"] == a["display_id"] and record["group_size"] == 2


def test_merge_moves_every_alert_of_a_selected_case(logged_in, iris):
    first = process_alert(logged_in, alert("c1", host="h1", srcip="198.51.100.1", rule_id="101"))
    # Ugyanaz az IP es szabaly: a korrelacio a masodikat az elso esetebe teszi.
    first_b = process_alert(logged_in, alert("c1b", host="h1", srcip="198.51.100.1", rule_id="101"))
    assert first_b["iris_case_id"] == first["iris_case_id"]
    other = process_alert(logged_in, alert("c2", host="h2", srcip="198.51.100.2", rule_id="102"))

    # Csak a masik eset egy riasztasa es az elso eset egyik riasztasa van kijelolve.
    body = logged_in.post(MERGE, json={"alert_refs": [other["display_id"], first_b["display_id"]]}).json()
    assert body["iris_case_id"] == first["iris_case_id"] and body["group"] == first["display_id"]
    # Az elso eset fo riasztasa is a csoportba kerul.
    assert sorted(body["merged"]) == sorted([first_b["display_id"], other["display_id"]])
    assert get(logged_in, first["display_id"])["group_size"] == 3


def test_merge_skips_a_closed_earliest_case(logged_in, iris):
    first = process_alert(logged_in, alert("z1", host="h1", srcip="198.51.100.1", rule_id="101"))
    second = process_alert(logged_in, alert("z2", host="h2", srcip="198.51.100.2", rule_id="102"))
    iris.closed.add(first["iris_case_id"])

    body = logged_in.post(MERGE, json={"alert_refs": [first["display_id"], second["display_id"]]}).json()
    assert body["iris_case_id"] == second["iris_case_id"]
    assert body["merged"] == [first["display_id"]]
    # A mar lezart esetet nem kell ujra lezarni, csak atkerul.
    assert body["closed_cases"] == [first["iris_case_id"]]


def test_merge_rejects_bad_selections(logged_in, iris, monkeypatch):
    a = process_alert(logged_in, alert("r1", host="h1", srcip="198.51.100.1", rule_id="101"))
    assert logged_in.post(MERGE, json={"alert_refs": [a["display_id"]]}).status_code == 422
    assert logged_in.post(MERGE, json={"alert_refs": [a["display_id"], a["display_id"]]}).status_code == 422
    assert logged_in.post(MERGE, json={"alert_refs": [a["display_id"], "ID-99999"]}).status_code == 404

    b = process_alert(logged_in, alert("r2", host="h1", srcip="198.51.100.1", rule_id="101"))
    assert b["iris_case_id"] == a["iris_case_id"]
    # Egy esetben, de meg nem csoportban: osszevonhato; masodszorra mar nem.
    assert logged_in.post(MERGE, json={"alert_refs": [a["display_id"], b["display_id"]]}).status_code == 200
    assert logged_in.post(MERGE, json={"alert_refs": [a["display_id"], b["display_id"]]}).status_code == 409

    monkeypatch.setattr(pipeline.alert_queue, "enqueue", lambda record_id: None)
    queued = logged_in.post("/api/v1/alerts", json=alert("r3"), headers=WEBHOOK_HEADERS).json()
    assert logged_in.post(MERGE, json={"alert_refs": [a["display_id"], queued["id"]]}).status_code == 409


def test_failed_merge_leaves_records_unchanged(logged_in, iris):
    first = process_alert(logged_in, alert("e1", host="h1", srcip="198.51.100.1", rule_id="101"))
    second = process_alert(logged_in, alert("e2", host="h2", srcip="198.51.100.2", rule_id="102"))
    iris.fail_notes = True
    assert logged_in.post(MERGE, json={"alert_refs": [first["display_id"], second["display_id"]]}).status_code == 502
    assert get(logged_in, second["display_id"])["iris_case_id"] == second["iris_case_id"]
    assert second["iris_case_id"] not in iris.closed


# --- false positive

def test_close_case_as_false_positive(logged_in, iris):
    a = process_alert(logged_in, alert("p1", host="h1", srcip="198.51.100.1", rule_id="101"))
    b = process_alert(logged_in, alert("p2", host="h1", srcip="198.51.100.1", rule_id="101"))
    case_id = a["iris_case_id"]
    assert b["iris_case_id"] == case_id

    res = logged_in.post(f"/api/v1/cases/{case_id}/false-positive", json={"reason": "admin maintenance"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["iris_closed"] is True and sorted(body["labeled"]) == sorted([a["display_id"], b["display_id"]])

    assert get(logged_in, a["display_id"])["ground_truth"] == "false_positive"
    assert case_id in iris.closed and "false-positive" in iris.tags[case_id]
    note = iris.notes[-1][2][0][1]
    assert "FALSE POSITIVE" in note and "admin maintenance" in note
    # A rendszer eszkalalta, de FP volt: a metrikaban hamis pozitiv.
    assert logged_in.get("/api/v1/metrics").json()["false_positive"] == 2


def test_false_positive_on_already_closed_case_only_labels(logged_in, iris):
    a = process_alert(logged_in, alert("q1"))
    iris.closed.add(a["iris_case_id"])
    body = logged_in.post(f"/api/v1/cases/{a['iris_case_id']}/false-positive").json()
    assert body["iris_closed"] is False
    assert iris.notes == []
    assert get(logged_in, a["display_id"])["ground_truth"] == "false_positive"


def test_false_positive_errors(logged_in, iris):
    assert logged_in.post("/api/v1/cases/424242/false-positive").status_code == 404
    a = process_alert(logged_in, alert("w1"))
    iris.fail = True
    assert logged_in.post(f"/api/v1/cases/{a['iris_case_id']}/false-positive").status_code == 502
    assert get(logged_in, a["display_id"])["ground_truth"] is None


def test_case_actions_require_login(client):
    assert client.post(MERGE, json={"alert_refs": ["ID-1", "ID-2"]}).status_code == 401
    assert client.post("/api/v1/cases/1/false-positive").status_code == 401
    assert client.post("/api/v1/cases/groups/ID-1/false-positive").status_code == 401


# --- SIEMantics csoportok

def test_merging_groups_unites_them(logged_in, iris):
    a, b, c, d = (process_alert(logged_in, alert(f"g{i}", level=2, host=f"x{i}", srcip=f"203.0.113.{i}"))
                  for i in range(1, 5))
    logged_in.post(MERGE, json={"alert_refs": [a["display_id"], b["display_id"]]})
    logged_in.post(MERGE, json={"alert_refs": [c["display_id"], d["display_id"]]})
    # Egy-egy tag kijelolese a ket csoportbol: a teljes csoportok egyesulnek.
    body = logged_in.post(MERGE, json={"alert_refs": [b["display_id"], d["display_id"]]}).json()
    assert body["group"] == a["display_id"]
    # A b mar az a csoportjaban volt, csak a masik csoport kerul at.
    assert sorted(body["merged"]) == sorted([c["display_id"], d["display_id"]])
    assert {get(logged_in, x["display_id"])["group"] for x in (a, b, c, d)} == {a["display_id"]}


def test_group_with_open_case_also_merges_in_iris(logged_in, iris):
    fp = process_alert(logged_in, alert("m1", level=2, host="x1", srcip="203.0.113.1"))
    case_alert = process_alert(logged_in, alert("m2", host="h1", srcip="198.51.100.1"))
    body = logged_in.post(MERGE, json={"alert_refs": [fp["display_id"], case_alert["display_id"]]}).json()
    # A cel a nyitott eset riasztasa, a korabbi FP is bekerul az esetbe.
    assert body["iris_case_id"] == case_alert["iris_case_id"] and body["group"] == case_alert["display_id"]
    assert get(logged_in, fp["display_id"])["iris_case_id"] == case_alert["iris_case_id"]


def test_group_false_positive_labels_all_and_closes_open_cases(logged_in, iris):
    fp1 = process_alert(logged_in, alert("v1", level=2, host="x1", srcip="203.0.113.1"))
    fp2 = process_alert(logged_in, alert("v2", level=6, host="x2", srcip="203.0.113.2"))
    logged_in.post(MERGE, json={"alert_refs": [fp1["display_id"], fp2["display_id"]]})

    res = logged_in.post(f"/api/v1/cases/groups/{fp2['display_id']}/false-positive", json={"reason": "zaj"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["group"] == fp1["display_id"] and body["closed_cases"] == []
    assert sorted(body["labeled"]) == sorted([fp1["display_id"], fp2["display_id"]])
    assert get(logged_in, fp2["display_id"])["ground_truth"] == "false_positive"
    assert iris.notes == []


def test_group_false_positive_closes_the_groups_iris_case(logged_in, iris):
    a = process_alert(logged_in, alert("k1", host="h1", srcip="198.51.100.1"))
    b = process_alert(logged_in, alert("k2", level=2, host="x2", srcip="203.0.113.2"))
    logged_in.post(MERGE, json={"alert_refs": [a["display_id"], b["display_id"]]})
    body = logged_in.post(f"/api/v1/cases/groups/{a['display_id']}/false-positive").json()
    assert body["closed_cases"] == [a["iris_case_id"]] and a["iris_case_id"] in iris.closed
    assert "false-positive" in iris.tags[a["iris_case_id"]]


def test_group_false_positive_for_alert_without_group(logged_in, iris):
    a = process_alert(logged_in, alert("s1", level=2))
    body = logged_in.post(f"/api/v1/cases/groups/{a['display_id']}/false-positive").json()
    assert body["labeled"] == [a["display_id"]]
    assert logged_in.post("/api/v1/cases/groups/ID-99999/false-positive").status_code == 404
