import hmac
import hashlib
import time
import base64
import json
import logging
from datetime import datetime
from config import Config
from services.data_store import db

logger = logging.getLogger(__name__)

class DocumentService:
    TOKEN_VALIDITY_SECONDS = 300  # 5 minutes validity for viewing tokens

    @classmethod
    def sanitize_pdf_for_student(cls, pdf: dict) -> dict:
        """
        Sanitize PDF document record for student clients.
        STRIPS ALL direct Google Drive URLs, internal system paths, and sensitive metadata.
        """
        if not pdf:
            return {}
        return {
            'id': pdf.get('id'),
            'title': pdf.get('title', 'Untitled Document'),
            'upload_date': pdf.get('upload_date', ''),
            'file_size': pdf.get('file_size', 'N/A')
        }

    @classmethod
    def generate_view_token(cls, pdf_id: int, user_id: str) -> str:
        """
        Generate a cryptographically signed, short-lived HMAC token for viewing a document.
        Protects against IDOR, URL tampering, and unauthorized links.
        """
        expires_at = int(time.time()) + cls.TOKEN_VALIDITY_SECONDS
        payload = f"{pdf_id}:{user_id}:{expires_at}"
        signature = hmac.new(
            Config.DOCUMENT_TOKEN_SECRET.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        token_raw = f"{payload}:{signature}"
        return base64.urlsafe_b64encode(token_raw.encode('utf-8')).decode('utf-8')

    @classmethod
    def verify_view_token(cls, token: str, pdf_id: int, user_id: str) -> bool:
        """Verify the integrity, matching parameters, and expiration of a viewing token."""
        if not token:
            return False

        try:
            token_raw = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
            parts = token_raw.split(':')
            if len(parts) != 4:
                return False

            t_pdf_id, t_user_id, t_exp, t_sig = parts
            if int(t_pdf_id) != int(pdf_id) or str(t_user_id).upper() != str(user_id).upper():
                return False

            # Check expiration
            if int(t_exp) < int(time.time()):
                logger.info(f"Viewing token expired for PDF {pdf_id}")
                return False

            # Verify signature
            expected_payload = f"{t_pdf_id}:{t_user_id}:{t_exp}"
            expected_sig = hmac.new(
                Config.DOCUMENT_TOKEN_SECRET.encode('utf-8'),
                expected_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(t_sig, expected_sig)

        except Exception as e:
            logger.warning(f"Token verification error: {e}")
            return False

    @staticmethod
    def extract_drive_file_id(drive_link: str) -> str:
        """Extract Google Drive file ID from standard drive URLs."""
        if not drive_link:
            return ''
        import re
        match = re.search(r'/file/d/([a-zA-Z0-9_-]+)', drive_link)
        if match:
            return match.group(1)
        match_id = re.search(r'id=([a-zA-Z0-9_-]+)', drive_link)
        if match_id:
            return match_id.group(1)
        return ''

    @classmethod
    def get_secure_embed_url(cls, drive_link: str) -> str:
        """
        Generate a restricted preview embed URL for the backend-rendered iframe.
        Removes toolbar and direct download interfaces.
        """
        file_id = cls.extract_drive_file_id(drive_link)
        if file_id:
            return f"https://drive.google.com/file/d/{file_id}/preview"
        return drive_link

