import os
from datetime import timedelta
from typing import Any, Dict
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # LLM API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

    # Model Settings
    GPT4_MODEL = "gpt-4.1"
    GEMINI_MODEL = "gemini-2.0-flash"
    GROQ_MODEL = "llama-3.3-70b-versatile"
    
    # Fallback Models
    FALLBACK_MODELS = {
        "gpt4": "gpt-4.1",
        "gemini": "gemini-2.0-flash",
        "groq": "llama-3.3-70b-versatile"
    }

    MODEL_PARAMS = {
        "gpt4": {
            "temperature": 0,
            "max_tokens": 4096,
            "timeout": 60,
            "retry_attempts": 3
        },
        "gemini": {
            "temperature": 0,
            "max_output_tokens": 2048,
            "timeout": 60,
            "retry_attempts": 3
        },
        "groq": {
            "temperature": 0,
            "max_tokens": 4096,
            "timeout": 60,
            "retry_attempts": 3
        }
    }

    # Image Settings
    MAX_IMAGE_SIZE = 20 * 1024 * 1024  # 20MB
    SUPPORTED_FORMATS = ["jpg", "jpeg", "png"]
    IMAGE_QUALITY = 85  # JPEG quality (0-100)

    @classmethod
    def get_model_config(cls) -> Dict[str, Any]:
        """Get model configuration settings."""
        return {
            "gpt4": {
                "model": cls.GPT4_MODEL,
                **cls.MODEL_PARAMS["gpt4"],
                "fallback_model": cls.FALLBACK_MODELS["gpt4"]
            },
            "gemini": {
                "model": cls.GEMINI_MODEL,
                **cls.MODEL_PARAMS["gemini"],
                "fallback_model": cls.FALLBACK_MODELS["gemini"]
            },
            "groq": {
                "model": cls.GROQ_MODEL,
                **cls.MODEL_PARAMS["groq"],
                "fallback_model": cls.FALLBACK_MODELS["groq"]
            }
        }

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///app.db')
    # SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://localhost/flask_auth_dev')

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # Use in-memory SQLite for testing
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    JWT_SECRET_KEY = 'test-jwt-secret'  # Use a fixed secret key for testing

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///app.db')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}