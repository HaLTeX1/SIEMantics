from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # OpenAI
    openai_api_key: str
    openai_model: str = "gpt-4o-mini"

    # DFIR-IRIS
    iris_base_url: str
    iris_api_key: str
    iris_customer_id: int = 1

    # Inbound webhook auth (shared secret, checked via header)
    wazuh_webhook_token: str = ""

    # Decision log / evaluation dataset storage
    database_url: str = "sqlite+aiosqlite:///./siemantics.db"


settings = Settings()
