import os
import json
import logging
from datetime import timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

class Config:
    # Base paths
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR / 'data'
    STATIC_DIR = BASE_DIR / 'static'
    TEMPLATES_DIR = BASE_DIR / 'templates'

    # Ensure required directories exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Security: Secret key from environment or cryptographically random fallback
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

    # Session security
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT_MINUTES', 60)))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    # Geolocation Settings - Every 5 seconds continuous check
    LOCATION_CHECK_INTERVAL_SECONDS = 5
    LOCATION_CHECK_INTERVAL_MS = 5000

    # Default Campus Coordinates - Sphoorthy Engineering College
    DEFAULT_CAMPUS_NAME = "Sphoorthy Engineering College"
    DEFAULT_LATITUDE = 17.282309
    DEFAULT_LONGITUDE = 78.553238
    DEFAULT_RADIUS_KM = 15.0

    # Fallback allowed locations list
    ALLOWED_LOCATIONS = [
        {
            'name': 'Sphoorthy Engineering College Campus',
            'latitude': 17.282309,
            'longitude': 78.553238,
            'radius_km': 15.0
        }
    ]

    # Google OAuth 2.0 Settings
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

    credentials_path = DATA_DIR / 'credentials.json'
    if credentials_path.exists() and not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        try:
            with open(credentials_path, 'r', encoding='utf-8') as f:
                creds_data = json.load(f)
                client_info = creds_data.get('installed', creds_data.get('web', {}))
                if not GOOGLE_CLIENT_ID:
                    GOOGLE_CLIENT_ID = client_info.get('client_id', '')
                if not GOOGLE_CLIENT_SECRET:
                    GOOGLE_CLIENT_SECRET = client_info.get('client_secret', '')
        except Exception as e:
            logger.warning(f"Could not load Google credentials: {e}")

    # Authorized Administrator Google Accounts
    default_admins = 'admin@aivontraa.com,support@aivontraa.com,admin@sphoorthyengg.ac.in'
    ADMIN_EMAILS = [
        email.strip().lower()
        for email in os.environ.get('ADMIN_EMAILS', default_admins).split(',')
        if email.strip()
    ]

    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'support@aivontraa.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'support@aivontraa.com')
    MAIL_DEBUG = False

    # Upload and Document Settings
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
    ALLOWED_DOCUMENT_EXTENSIONS = {'pdf'}
    ALLOWED_EXCEL_EXTENSIONS = {'xlsx', 'xls', 'csv'}

    # Company Branding - Aivontraa
    APP_NAME = "Vault E-Library"
    COLLEGE_NAME = "Sphoorthy Engineering College"
    COMPANY_NAME = "Aivontraa"
    COMPANY_URL = "https://aivontraa.com/"
    COMPANY_LOGO_URL = "https://aivontraa.com/assets/images/ai.png"
    DEVELOPER_CREDIT = "Developed by Aivontraa"
    SUPPORT_EMAIL = "support@aivontraa.com"

    # Pagination Defaults
    DEFAULT_PER_PAGE_PDFS = 12
    DEFAULT_PER_PAGE_USERS = 15

    # Document token signature secret
    DOCUMENT_TOKEN_SECRET = os.environ.get('DOCUMENT_TOKEN_SECRET') or os.urandom(24).hex()
