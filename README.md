# SIEMantics

Saját fejlesztésű SOAR keretrendszer: Wazuh riasztásokat fogad webhookon, normalizálja, LLM-alapú triázzsal (OpenAI) szűri a hamis pozitívokat, majd valós incidens esetén esetet nyit a DFIR-IRIS-ben. Minden döntés perzisztálva van egy döntésnaplóba, amiből utólagos címkézéssel (ground truth) pontosság/precision/recall/hamis pozitív arány és feldolgozási idő számolható.

## Adatfolyam

```
Wazuh --webhook--> POST /api/v1/alerts --normalize--> LLM triázs --true positive--> DFIR-IRIS eset
                                                             |                              |
                                                        false positive              LLM elemzés + IoC-k
                                                             |                        note-ként az esetben
                                                             v
                                                     döntésnapló (SQLite)  <---- minden ág ide ír
```

## Projektstruktúra

```
app/
├── main.py           # FastAPI app, lifespan (DB init), router regisztráció
├── config.py         # pydantic-settings (.env betöltés)
├── enums.py           # AlertStatus, GroundTruth
├── schemas.py         # Pydantic API sémák (bemenet/kimenet)
├── normalize.py        # Wazuh payload -> NormalizedAlert
├── llm_engine.py        # OpenAI triázs (structured output)
├── iris_client.py       # DFIR-IRIS eset/note/IoC API kliens
├── db.py              # SQLAlchemy async engine/session
├── models.py           # AlertRecord ORM tábla (döntésnapló)
├── metrics.py           # konfúziós mátrix + feldolgozási idő statisztikák
└── routers/
    ├── alerts.py        # POST/GET /alerts, PATCH /alerts/{id}/label
    └── metrics.py         # GET /metrics
```

## Előfeltételek

- Python 3.12 (a Dockerfile és a CI is ezt használja)
- Docker + `docker-compose` (V1, önálló bináris) (konténeres futtatáshoz/deployhoz)
- OpenAI API kulcs
- Elérhető DFIR-IRIS instancia + API kulcs

## Helyi futtatás (venv)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env kitöltése: OPENAI_API_KEY, IRIS_BASE_URL, IRIS_API_KEY, ...

uvicorn app.main:app --reload
```

Az app induláskor (`lifespan`) automatikusan létrehozza az SQLite adatbázist (`siemantics.db`), migráció nem szükséges.

## Konfiguráció (.env)

| Változó | Leírás |
|---|---|
| `OPENAI_API_KEY` | OpenAI API kulcs a triázshoz |
| `OPENAI_MODEL` | alapértelmezett: `gpt-4o-mini` |
| `IRIS_BASE_URL` | DFIR-IRIS instancia URL-je |
| `IRIS_API_KEY` | DFIR-IRIS API kulcs |
| `IRIS_CUSTOMER_ID` | eset létrehozáshoz tartozó ügyfél ID |
| `WAZUH_WEBHOOK_TOKEN` | megosztott titok a webhook hívások hitelesítéséhez (`X-Webhook-Token` header) |
| `DATABASE_URL` | döntésnapló DB elérési útja, alapértelmezett: `sqlite+aiosqlite:///./siemantics.db` |

## API végpontok

| Metódus | Útvonal | Leírás |
|---|---|---|
| `POST` | `/api/v1/alerts` | Wazuh riasztás fogadása, triázs, esetleges IRIS eset nyitás |
| `GET` | `/api/v1/alerts` | eltárolt riasztás-rekordok listázása (`limit`, `offset`) |
| `PATCH` | `/api/v1/alerts/{alert_id}/label` | ground truth címkézés (`true_positive` / `false_positive`) |
| `GET` | `/api/v1/metrics` | konfúziós mátrix + feldolgozási idő statisztikák a címkézett rekordokból |
| `GET` | `/healthz` | health check |

### Teszt riasztás küldése

```bash
curl -X POST http://localhost:8000/api/v1/alerts \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: <WAZUH_WEBHOOK_TOKEN>" \
  -d '{
    "id": "alert-001",
    "rule": { "id": "100", "level": 12, "description": "Possible SQL injection attempt" },
    "agent": { "id": "001", "name": "web01", "ip": "10.0.0.5" },
    "data": { "srcip": "203.0.113.7" },
    "full_log": "GET /login?user=admin'\'' OR 1=1--"
  }'
```

### Címkézés és metrika lekérdezés (kiértékeléshez)

```bash
curl -X PATCH http://localhost:8000/api/v1/alerts/alert-001/label \
  -H "Content-Type: application/json" \
  -d '{"ground_truth": "true_positive"}'

curl http://localhost:8000/api/v1/metrics
```

## Futtatás Dockerrel

```bash
docker-compose up -d --build
docker-compose logs -f siemantics
```

A döntésnapló a `siemantics_data` named volume-ban perzisztál, túléli a konténer újraindítását.

## Kiértékelési munkafolyamat (szakdolgozat 6. fejezet)

1. Teszt/labor riasztásokat küldesz a webhookra (valós vagy szimulált támadási forgatókönyvekből).
2. Minden riasztásnál eltárolódik: az LLM döntése, indoklása, kinyert IoC-k, feldolgozási idő (`processing_time_ms`).
3. Utólag, a labor eredmények ismeretében, `PATCH /alerts/{id}/label`-lel felcímkézed, hogy az adott riasztás valóban true positive vagy false positive volt.
4. `GET /api/v1/metrics` visszaadja a konfúziós mátrixot (TP/FP/TN/FN), accuracy/precision/recall/F1-et, hamis pozitív arányt, valamint az átlag/medián/p95 feldolgozási időt — ezek kerülnek a 6.3 fejezet táblázataiba/ábráiba.

## Deployment (Forgejo CI/CD)

A `.forgejo/workflows/deploy.yml` három jobot futtat `main`-re pusholáskor:

1. **ci-prereqs** — függőségek telepítése, `py_compile`, import smoke test.
2. **remote-prereqs** — SSH-val bejelentkezik a célszerverre, ellenőrzi hogy van-e `docker`/`docker-compose`, írható-e a deploy path.
3. **deploy** — `rsync`-eli a kódot a szerverre, `docker-compose build && up -d`, majd `/healthz` health check.

### Szükséges Forgejo repo secretek

| Secret | Érték |
|---|---|
| `DEPLOY_HOST` | szerver hostname/IP |
| `DEPLOY_USER` | pl. `deploy` |
| `DEPLOY_PORT` | SSH port, ha nem 22 |
| `DEPLOY_SSH_KEY` | dedikált privát SSH kulcs teljes tartalma |
| `DEPLOY_PATH` | pl. `/opt/siemantics` |

A célszerveren a valódi `.env` fájlt (OpenAI/IRIS kulcsokkal) kézzel kell létrehozni a `DEPLOY_PATH` alatt, első deploy előtt — a CI ezt sosem írja felül, sosem tölti fel.

### Szerver előkészítése (dedikált deploy user)

```bash
sudo useradd -m -s /bin/bash deploy
sudo usermod -aG docker deploy
sudo mkdir -p /opt/siemantics
sudo chown deploy:deploy /opt/siemantics
```

### SSH deploy kulcs generálása

```bash
ssh-keygen -t ed25519 -C "siemantics-forgejo-deploy" -f ~/.ssh/siemantics_deploy -N ""
```

Publikus kulcs felhelyezése a szerverre:

```bash
ssh-copy-id -i ~/.ssh/siemantics_deploy.pub -p <PORT> deploy@<SERVER_HOST>
```

Ha nincs meglévő hozzáférés a userhez, sudo-s userrel manuálisan:

```bash
sudo mkdir -p /home/deploy/.ssh
echo "<PUBLIC_KEY_TARTALMA>" | sudo tee -a /home/deploy/.ssh/authorized_keys
sudo chown -R deploy:deploy /home/deploy/.ssh
sudo chmod 700 /home/deploy/.ssh
sudo chmod 600 /home/deploy/.ssh/authorized_keys
```

Kapcsolat tesztelése, mielőtt a CI-ba kerülne a kulcs:

```bash
ssh -i ~/.ssh/siemantics_deploy -p <PORT> deploy@<SERVER_HOST> 'docker --version && docker-compose --version'
```

A privát kulcs tartalma (`DEPLOY_SSH_KEY` secret értéke):

```bash
cat ~/.ssh/siemantics_deploy
```

## Ismert korlátok / nyitott pontok

- Nincs még labor/teszt log-generátor a 6.1 fejezethez (támadási szenáriók automatikus generálása).
- A bemeneti séma jelenleg Wazuh-specifikus; több SIEM forrás támogatásához a normalizációs réteget bővíteni kell.
- Az 5.4 fejezetben tárgyalt biztonságos kódolási szempontok (rate limiting, retry/backoff LLM és IRIS hívásokhoz, bővebb audit log) még nincsenek teljeskörűen implementálva.
