import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "JCS Unified Pipeline"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql://jcs_user:jcs_password@postgres:5432/jcs_db"
    )
    
    # Celery Broker / Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # AI Engine
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    class Config:
        case_sensitive = True

settings = Settings()
