from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Trustiva AI"
    app_env: str = "development"
    debug: bool = True

    llm_provider: str = "openrouter"

    llm_api_key: str = ""
    llm_model: str = ""

    embedding_model: str = (
        "sentence-transformers/all-MiniLM-L6-v2"
    )

    vector_db_path: str = "data/vectorstore"

    max_upload_size_mb: int = 10

    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

@lru_cache
def get_settings() -> Settings:
    return Settings()