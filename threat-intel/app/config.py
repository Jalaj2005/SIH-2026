"""
Settings & environment variables for the Threat Intel module.

Loads config from a .env file (see .env.example) so secrets like
API keys never get hardcoded or committed to git.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Redis ---
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    # --- AlienVault OTX (TAXII 2.1) ---
    otx_api_key: str = ""
    otx_taxii_url: str = "https://otx.alienvault.com/taxii/discovery"
    otx_collection_id: str = ""  # set after discovering the collection

    # --- URLhaus (fallback static feed, no key needed) ---
    urlhaus_csv_url: str = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    # --- Sync scheduler ---
    sync_interval_minutes: int = 30

    # --- FastAPI server ---
    app_host: str = "0.0.0.0"
    app_port: int = 8003  # module 3 -> port 800X convention, adjust as your team agrees

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


# Single shared settings instance — import this everywhere else
settings = Settings()