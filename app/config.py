from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # OpenAI - optional; if unset (or if a call fails), triage falls back to the mock engine
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # Mock triage engine (fallback when OpenAI is unavailable)
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
