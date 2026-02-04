import os
from typing import List

class Settings:
    """Application settings"""
    
    # App Info
    APP_NAME: str = "ScamShield AI"
    VERSION: str = "3.0.0"
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # CORS
    ALLOWED_ORIGINS: List[str] = os.getenv(
        "ALLOWED_ORIGINS",
        "*"
    ).split(",")
    
    # Feature Flags
    ENABLE_ML: bool = os.getenv("ENABLE_ML", "true").lower() == "true"
    ENABLE_ANALYTICS: bool = os.getenv("ENABLE_ANALYTICS", "true").lower() == "true"
    ENABLE_SCREENSHOT_DETECTION: bool = os.getenv("ENABLE_SCREENSHOT_DETECTION", "true").lower() == "true"
    
    # ML Configuration
    ML_MODEL_TYPE: str = os.getenv("ML_MODEL_TYPE", "random_forest")  # random_forest, logistic_regression
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "models/scam_detector.pkl")
    ML_WEIGHT: float = float(os.getenv("ML_WEIGHT", "0.65"))
    RULE_WEIGHT: float = float(os.getenv("RULE_WEIGHT", "0.35"))
    
    # Detection Thresholds
    SCAM_THRESHOLD: float = float(os.getenv("SCAM_THRESHOLD", "0.75"))
    SUSPICIOUS_THRESHOLD: float = float(os.getenv("SUSPICIOUS_THRESHOLD", "0.45"))
    
    # Limits
    MAX_MESSAGE_LENGTH: int = int(os.getenv("MAX_MESSAGE_LENGTH", "5000"))
    
    # Paths
    RULES_PATH: str = os.getenv("RULES_PATH", "detection/rules.json")
    
    # Database (for future use)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scamshield.db")

settings = Settings()
