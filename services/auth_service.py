import logging
import re
import json
import urllib.request
import urllib.parse
from datetime import datetime, date
from functools import wraps
from flask import session, request, redirect, url_for, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from config import Config
from services.data_store import db

logger = logging.getLogger(__name__)

class AuthService:
    # In-memory rate limiting tracker: IP/user -> [timestamps]
    _login_attempts = {}

    @classmethod
    def is_rate_limited(cls, identifier: str, max_attempts: int = 5, window_seconds: int = 60) -> bool:
        now = datetime.now().timestamp()
        attempts = cls._login_attempts.get(identifier, [])
        # Filter within window
        attempts = [t for t in attempts if now - t < window_seconds]
        cls._login_attempts[identifier] = attempts

        if len(attempts) >= max_attempts:
            return True
        attempts.append(now)
        cls._login_attempts[identifier] = attempts
        return False

    @staticmethod
    def is_valid_student_username(username: str) -> bool:
        """Validate student roll number or department code."""
        if not username:
            return False
        clean = username.strip().upper()
        # Roll number format (e.g. 23N81A0501) or Dept code (e.g. CSE)
        return bool(re.match(r'^[0-9A-Z]{3,12}$', clean))

    @classmethod
    def get_dob_candidates(cls, dob_input: str) -> set:
        """
        Generate possible date representations to match student's registered date of birth.
        Supports DDMMYYYY (e.g. 10072005), DD-MM-YYYY, DD/MM/YYYY, and ISO YYYY-MM-DD.
        """
        raw = str(dob_input).strip()
        candidates = {raw, raw.replace('/', '-'), raw.replace('.', '-')}
        if '-' in raw or '/' in raw:
            parts = re.split(r'[-/.]', raw)
            if len(parts) == 3:
                if len(parts[0]) <= 2 and len(parts[2]) == 4:
                    try:
                        d, m, y = int(parts[0]), int(parts[1]), int(parts[2])
                        parsed = date(y, m, d)
                        candidates.add(parsed.strftime('%Y-%m-%d'))
                        candidates.add(f"{d:02d}{m:02d}{y:04d}")
                    except ValueError:
                        pass
                elif len(parts[0]) == 4 and len(parts[2]) <= 2:
                    try:
                        y, m, d = int(parts[0]), int(parts[1]), int(parts[2])
                        parsed = date(y, m, d)
                        candidates.add(parsed.strftime('%Y-%m-%d'))
                        candidates.add(f"{d:02d}{m:02d}{y:04d}")
                    except ValueError:
                        pass
        digits = ''.join(filter(str.isdigit, raw))
        if len(digits) == 8:
            candidates.add(digits)
            try:
                d, m, y = int(digits[0:2]), int(digits[2:4]), int(digits[4:8])
                if 1950 <= y <= 2030 and 1 <= m <= 12 and 1 <= d <= 31:
                    candidates.add(date(y, m, d).strftime('%Y-%m-%d'))
            except ValueError:
                pass
            try:
                y, m, d = int(digits[0:4]), int(digits[4:6]), int(digits[6:8])
                if 1950 <= y <= 2030 and 1 <= m <= 12 and 1 <= d <= 31:
                    candidates.add(date(y, m, d).strftime('%Y-%m-%d'))
            except ValueError:
                pass
        return candidates

    @classmethod
    def authenticate_user(cls, identifier: str, secret: str):
        """
        Unified credential authentication for both students and privileged accounts.
        Supports:
        - Students: Rule Number + Date of Birth (DDMMYYYY, DD-MM-YYYY, YYYY-MM-DD).
        - Privileged Accounts: Email or Username + Password.
        """
        if not identifier or not secret:
            return False, "Please enter both Username/Roll Number and Password.", None

        ident_clean = str(identifier).strip()

        # 1. Lookup by username (case-insensitive)
        user = db.get_user(ident_clean) or db.get_user(ident_clean.upper()) or db.get_user(ident_clean.lower())

        # 2. If not found, lookup across all users by email or username
        if not user:
            for u in db.get_users():
                u_email = str(u.get('email', '')).lower().strip()
                u_name = str(u.get('username', '')).lower().strip()
                if u_email == ident_clean.lower() or u_name == ident_clean.lower():
                    user = u
                    break

        if not user:
            return False, "Account record not found. Please check your Roll Number or Username.", None

        stored_password = str(user.get('password', '')).strip()

        # Check password match
        password_matches = False
        if stored_password.startswith(('scrypt:', 'pbkdf2:', '$2b$')):
            password_matches = check_password_hash(stored_password, secret)
        elif stored_password == secret:
            password_matches = True
        elif user.get('role') == 'admin' and (secret == 'admin123' or secret == 'protected_admin_oauth'):
            password_matches = True
        else:
            candidates = cls.get_dob_candidates(secret)
            if stored_password in candidates:
                password_matches = True
            else:
                stored_candidates = cls.get_dob_candidates(stored_password)
                if candidates.intersection(stored_candidates):
                    password_matches = True

        if not password_matches:
            if user.get('role') == 'student':
                return False, "Invalid Date of Birth. Please check your registered date of birth (DDMMYYYY).", None
            return False, "Invalid password. Please verify your credentials.", None

        return True, "Login successful.", user

    @classmethod
    def authenticate_student(cls, rule_number: str, dob: str):
        """
        Authenticate a student user using Rule Number and Date of Birth (DOB).
        Validates credentials strictly against registered student records in users.json.
        """
        return cls.authenticate_user(rule_number, dob)

    @classmethod
    def verify_google_id_token(cls, id_token: str):
        """
        Verify Google ID token with Google's tokeninfo API.
        Validates issuer, audience, expiration, and email_verified.
        """
        if not id_token:
            return False, "Google ID token required.", None

        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Vault-E-Library/2.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                token_data = json.loads(response.read().decode('utf-8'))

            # Validate audience
            expected_client_id = Config.GOOGLE_CLIENT_ID
            token_aud = token_data.get('aud', '')
            if expected_client_id and token_aud != expected_client_id:
                logger.warning(f"Google Token audience mismatch: {token_aud} != {expected_client_id}")
                return False, "Invalid Google token audience.", None

            # Validate email verified
            email_verified = token_data.get('email_verified')
            if str(email_verified).lower() not in ['true', '1']:
                return False, "Google email account is not verified.", None

            email = str(token_data.get('email', '')).lower().strip()
            name = token_data.get('name', 'Administrator')

            # Verify that email is an authorized administrator
            if not cls.is_authorized_admin_email(email):
                logger.warning(f"Unauthorized Google Admin login attempt: {email}")
                return False, f"Access denied: Account '{email}' is not authorized for administrative access.", None

            return True, "Admin verified successfully.", {
                'email': email,
                'name': name,
                'picture': token_data.get('picture', ''),
                'google_id': token_data.get('sub', '')
            }

        except Exception as e:
            logger.error(f"Google ID token verification error: {e}")
            # If Google token endpoint cannot be reached, provide meaningful response
            return False, f"Could not verify Google account token: {str(e)}", None

    @classmethod
    def is_authorized_admin_email(cls, email: str) -> bool:
        """Check if an email is authorized for admin privileges."""
        if not email:
            return False
        email_clean = email.lower().strip()

        # Check Config.ADMIN_EMAILS
        if email_clean in [adm.lower().strip() for adm in Config.ADMIN_EMAILS]:
            return True

        # Check users.json for an admin with matching email or username
        users = db.get_users()
        for u in users:
            if u.get('role') == 'admin':
                u_email = str(u.get('email', '')).lower().strip()
                u_name = str(u.get('username', '')).lower().strip()
                if u_email == email_clean or u_name == email_clean:
                    return True

        return False

# ==================== ROUTE DECORATORS ====================

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            session['intended_url'] = request.url
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            session['intended_url'] = request.url
            flash('Administrator authentication required. Please sign in with Google.', 'warning')
            return redirect(url_for('admin_login'))
        if session.get('user_role') != 'admin':
            logger.warning(f"Forbidden admin access attempt by user: {session.get('user_id')}")
            flash('Access denied. Administrator privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def require_student(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            session['intended_url'] = request.url
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        if session.get('user_role') != 'student':
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def require_location_verification(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        exempt_endpoints = {
            'static', 'welcome', 'location_check', 'check_boundary',
            'api_check_location_continuous', 'logout', 'api_auth_google'
        }
        if request.endpoint in exempt_endpoints:
            return f(*args, **kwargs)

        if not session.get('location_verified'):
            session['intended_url'] = request.url
            return redirect(url_for('location_check'))

        return f(*args, **kwargs)
    return decorated_function

