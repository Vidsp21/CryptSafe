import os

class Config:
    """Application configuration settings"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    
    # Database settings
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'secure_storage.db')
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Security settings
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'