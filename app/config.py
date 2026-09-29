from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    openrouter_api_key: str = ""
    # AI modell definiálása (Most épp csak ingyenes modelleket használ)
    openrouter_model: str = "openrouter/free"

    # Ez egy mock, azaz ha elérhetetlen az OR akkor erre fog visszaesni és csak a detection adatok alapján elemez.
    llm_mock_severity_threshold: int = 7

    # DFIR-IRIS
    iris_base_url: str
    iris_api_key: str
    iris_customer_id: int = 1
    iris_verify_ssl: bool = True

    wazuh_webhook_token: str = ""

    # IoC enrichment (optional; skipped per-provider if its key is unset).
    # Only runs for true-positive/escalated alerts, capped to a handful of
    # unique IPs per alert to stay within free-tier rate limits.
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    enrichment_max_iocs: int = 5

    # Decision log / evaluation dataset storage
    database_url: str = "sqlite+aiosqlite:///./siemantics.db"

    # Felhasználókezelés: ha még nincs egyetlen felhasználó sem, induláskor ezzel jön létre az első admin.
    admin_username: str = "admin"
    admin_password: str = ""
    session_ttl_hours: int = 12
    # HTTPS mögött (reverse proxy) true-ra állítandó, sima HTTP-s lab környezetben false.
    session_cookie_secure: bool = False


settings = Settings()
