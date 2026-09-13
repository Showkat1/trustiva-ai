from functools import lru_cache
import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Trustiva AI"
    app_env: str = "development"
    debug: bool = True

    llm_provider: str = "openrouter"
    llm_api_key: str = ""
    llm_model: str = "openrouter/free"

    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    vector_db_path: str = "data/vectorstore"

    max_upload_size_mb: int = 10
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


def _load_streamlit_secrets():
    """
    Load configuration from Streamlit Secrets when running
    on Streamlit Community Cloud.

    Local development continues to use .env.
    """
    try:
        import streamlit as st

        if not hasattr(st, "secrets"):
            return {}

        secrets = st.secrets

        return {
            "llm_provider": secrets.get("LLM_PROVIDER", ""),
            "llm_api_key": secrets.get("LLM_API_KEY", ""),
            "llm_model": secrets.get("LLM_MODEL", ""),
            "embedding_model": secrets.get("EMBEDDING_MODEL", ""),
            "vector_db_path": secrets.get("VECTOR_DB_PATH", ""),
        }

    except Exception:
        # Streamlit secrets are unavailable during normal local
        # execution or before Streamlit initializes.
        return {}


@lru_cache
def get_settings() -> Settings:
    """
    Build application settings.

    Priority:
    1. Streamlit Cloud Secrets
    2. Environment variables / .env
    3. Default values
    """
    settings = Settings()

    streamlit_values = _load_streamlit_secrets()

    for key, value in streamlit_values.items():
        if value:
            setattr(settings, key, value)

    return settings