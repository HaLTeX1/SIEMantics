from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # OpenRouter - optional; if unset (or if a call fails), triage falls back to the mock engine.
    # Default is OpenRouter's "Free Models Router" (https://openrouter.ai/docs/cookbook/get-started/free-models-router-playground),
    # which always routes to a currently-available free model - unlike a hardcoded ":free" slug,
    # this doesn't break when OpenRouter deprecates/repriced a specific free model (has happened before).
    # Only "openrouter/free" or a ":free"-suffixed model are ever used (enforced in llm_engine.py)
    # so triage can never incur cost, even if this is misconfigured.
    openrouter_api_key: str = ""
    openrouter_model: str = "openrouter/free"

    # Mock triage engine (fallback when OpenRouter is unavailable)
    llm_mock_severity_threshold: int = 7

    # DFIR-IRIS
    iris_base_url: str
    iris_api_key: str
    iris_customer_id: int = 1
    iris_verify_ssl: bool = True

    # Inbound webhook auth (shared secret, checked via header)
    wazuh_webhook_token: str = ""

    # Decision log / evaluation dataset storage
    database_url: str = "sqlite+aiosqlite:///./siemantics.db"


settings = Settings()
