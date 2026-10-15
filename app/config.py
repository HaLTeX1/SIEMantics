from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    openrouter_api_key: str = ""
    # LLM modell, csak ingyenes (openrouter/free vagy :free vegu).
    openrouter_model: str = "openrouter/free"

    # Mock motor kuszobe: OpenRouter nelkul ettol a Wazuh szinttol TP.
    llm_mock_severity_threshold: int = 7
    # Egy OpenRouter hivas max. ideje mp-ben, utana a mock motor dont.
    openrouter_timeout_seconds: float = Field(default=60.0, gt=0)

    # FP iteletnel ez alatti confidence-szel NEEDS_REVIEW lesz, nem SUPPRESSED.
    review_confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    # Prompt injection vedohalo: ettol a szinttol az LLM FP itelete NEEDS_REVIEW.
    review_severity_floor: int = 12

    # DFIR-IRIS
    iris_base_url: str
    iris_api_key: str
    iris_customer_id: int = 1
    iris_verify_ssl: bool = True
    # Ennyi masodpercenkent az IRIS-ben lezart esetek kimenetele bekerul a dispositionbe (0 = ki).
    iris_sync_interval_seconds: int = Field(default=120, ge=0)
    # Publikus URL, ha meg van adva, az IRIS eset visszalinkel a riasztasra.
    siemantics_public_url: str = ""
    # Korrelacios ablak oraban (0 = ki): IP alapu esetbe sorolas es LLM kontextus.
    correlation_window_hours: int = Field(default=24, ge=0)
    # Forras IP nelkuli riasztas ennyi percen belul a host nyitott esetebe kerul (0 = ki).
    correlation_host_window_minutes: int = Field(default=10, ge=0)
    # Ennyi oran belul az azonos ujjlenyomatu riasztas nem megy LLM-hez, a korabbi donteset kapja (0 = ki).
    dedup_window_hours: int = Field(default=24, ge=0)
    # Flood: ha egy szabaly+host ennyi riasztast ad az ablakban, a tobbi LLM nelkul a legutobbi dontest kapja (0 = ki).
    flood_threshold: int = Field(default=20, ge=0)
    flood_window_minutes: int = Field(default=10, ge=0)
    # Legfeljebb ennyi kapcsolodo riasztas kerul az LLM ele.
    correlation_max_alerts: int = Field(default=10, ge=0)

    wazuh_webhook_token: str = ""

    # Wazuh manager API a valaszlepesekhez (IP blokkolas); ures URL = kikapcsolva.
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_ssl: bool = True
    # Tovabbi vedett IP-k / halozatok vesszovel, a nem publikus cimeken felul (pl. sajat publikus IP-k).
    response_protected_networks: str = ""
    # Parhuzamos triazs workerek; 1 = sorban (free rate limit, korrelacio).
    triage_workers: int = Field(default=1, ge=1)

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    enrichment_max_iocs: int = 5

    database_url: str = "sqlite+aiosqlite:///./siemantics.db"

    # Elso admin, ha meg nincs egyetlen felhasznalo sem.
    admin_username: str = "admin"
    admin_password: str = ""
    session_ttl_hours: int = 12
    session_cookie_secure: bool = False


settings = Settings()
