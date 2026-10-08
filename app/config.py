from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    openrouter_api_key: str = ""
    # AI modell definiálása (Most épp csak ingyenes modelleket használ)
    openrouter_model: str = "openrouter/free"

    # Ez egy mock, azaz ha elérhetetlen az OR akkor erre fog visszaesni és csak a detection adatok alapján elemez.
    llm_mock_severity_threshold: int = 7
    # Egy OpenRouter hívás max. ideje (mp); lejárat után a mock motor dönt. Az OpenAI kliens
    # alapértéke 600 mp lenne, ami egy lassú ingyenes modellnél percekre feltartaná a sort.
    openrouter_timeout_seconds: float = Field(default=60.0, gt=0)

    # Ha a triázs false positive-ot mond, de a confidence ez alatt van, a riasztás nem
    # SUPPRESSED, hanem NEEDS_REVIEW lesz (analystnak kell ránéznie, IRIS eset nem nyílik).
    review_confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    # Prompt injection védőháló: ilyen Wazuh severity felett az LLM nem nyomhatja el a riasztást
    # (false positive ítélet esetén is NEEDS_REVIEW lesz belőle).
    review_severity_floor: int = 12

    # DFIR-IRIS
    iris_base_url: str
    iris_api_key: str
    iris_customer_id: int = 1
    iris_verify_ssl: bool = True
    # Publikus URL, ha meg van adva, az IRIS eset visszalinkel a riasztasra.
    siemantics_public_url: str = ""
    # Korrelacios ablak orakban, 0 = kikapcsolva. Ezen belul az azonos forras IP-rol jovo hasonlo riasztas a meglevo
    # IRIS esetbe kerul, es az azonos hostrol / forras IP-rol jott riasztasok az LLM ele kerulnek ("related alerts").
    correlation_window_hours: int = Field(default=24, ge=0)
    # Legfeljebb ennyi kapcsolodo riasztas kerul az LLM ele.
    correlation_max_alerts: int = Field(default=10, ge=0)

    wazuh_webhook_token: str = ""
    # Háttérben párhuzamosan feldolgozott riasztások száma (app/pipeline.py). 1 = sorban,
    # ami kíméli az OpenRouter free rate limitet és a korreláció is a korábbi döntéseket látja.
    triage_workers: int = Field(default=1, ge=1)

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    enrichment_max_iocs: int = 5

    database_url: str = "sqlite+aiosqlite:///./siemantics.db"

    # Felhasználókezelés: ha még nincs egyetlen felhasználó sem, induláskor ezzel jön létre az első admin.
    admin_username: str = "admin"
    admin_password: str = ""
    session_ttl_hours: int = 12
    session_cookie_secure: bool = False


settings = Settings()
