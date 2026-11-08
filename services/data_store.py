import json
import os
import shutil
import tempfile
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from config import Config

logger = logging.getLogger(__name__)

class DataStore:
    """Thread-safe, high-performance in-memory cached JSON data store."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(DataStore, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, data_dir=None):
        if self._initialized:
            return
        self.data_dir = Path(data_dir or Config.DATA_DIR)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._cache = {}
        self._cache_mtimes = {}
        self._rw_locks = {
            'users.json': threading.Lock(),
            'pdfs.json': threading.Lock(),
            'boundaries.json': threading.Lock(),
            'contacts.json': threading.Lock(),
            'access_logs.json': threading.Lock()
        }
        self._initialized = True
        logger.info(f"DataStore initialized with directory: {self.data_dir}")

    def _get_lock(self, filename: str) -> threading.Lock:
        if filename not in self._rw_locks:
            self._rw_locks[filename] = threading.Lock()
        return self._rw_locks[filename]

    def _load_raw(self, filename: str):
        filepath = self.data_dir / filename
        if not filepath.exists():
            return [] if not filename.endswith('credentials.json') else {}

        current_mtime = filepath.stat().st_mtime
        cached_mtime = self._cache_mtimes.get(filename)

        if filename in self._cache and cached_mtime == current_mtime:
            return self._cache[filename]

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    data = [] if not filename.endswith('credentials.json') else {}
                else:
                    data = json.loads(content)
            self._cache[filename] = data
            self._cache_mtimes[filename] = current_mtime
            return data
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
            return self._cache.get(filename, [] if not filename.endswith('credentials.json') else {})

    def _save_raw(self, filename: str, data) -> bool:
        filepath = self.data_dir / filename
        lock = self._get_lock(filename)

        with lock:
            temp_file = None
            try:
                # Write atomically via temp file
                with tempfile.NamedTemporaryFile('w', dir=str(self.data_dir), delete=False, encoding='utf-8') as tf:
                    json.dump(data, tf, indent=2, ensure_ascii=False)
                    temp_file = tf.name

                shutil.move(temp_file, str(filepath))
                self._cache[filename] = data
                self._cache_mtimes[filename] = filepath.stat().st_mtime
                return True
            except Exception as e:
                logger.error(f"Error saving {filename}: {e}")
                if temp_file and os.path.exists(temp_file):
                    os.unlink(temp_file)
                return False

    # ==================== USERS ====================
    def get_users(self):
        data = self._load_raw('users.json')
        return list(data) if isinstance(data, list) else []

    def get_user(self, username: str):
        if not username:
            return None
        target = str(username).strip().upper()
        for u in self.get_users():
            if str(u.get('username', '')).strip().upper() == target:
                return dict(u)
        return None

    def save_user(self, user_data: dict) -> bool:
        users = self.get_users()
        username = str(user_data.get('username', '')).strip()
        if not username:
            return False

        updated = False
        target = username.upper()
        for idx, u in enumerate(users):
            if str(u.get('username', '')).strip().upper() == target:
                users[idx] = {**u, **user_data}
                updated = True
                break

        if not updated:
            new_id = max([u.get('id', 0) for u in users], default=0) + 1
            user_data['id'] = new_id
            if 'created_at' not in user_data:
                user_data['created_at'] = datetime.now().isoformat()
            users.append(user_data)

        return self._save_raw('users.json', users)

    def delete_user(self, username: str) -> bool:
        users = self.get_users()
        target = str(username).strip().upper()
        filtered = [u for u in users if str(u.get('username', '')).strip().upper() != target]
        if len(filtered) < len(users):
            return self._save_raw('users.json', filtered)
        return False

    def add_users_bulk(self, new_users: list) -> int:
        users = self.get_users()
        existing_usernames = {str(u.get('username', '')).strip().upper() for u in users}
        next_id = max([u.get('id', 0) for u in users], default=0) + 1
        added_count = 0

        for nu in new_users:
            uname = str(nu.get('username', '')).strip()
            if not uname or uname.upper() in existing_usernames:
                continue
            nu['id'] = next_id
            next_id += 1
            if 'created_at' not in nu:
                nu['created_at'] = datetime.now().isoformat()
            users.append(nu)
            existing_usernames.add(uname.upper())
            added_count += 1

        if added_count > 0:
            self._save_raw('users.json', users)
        return added_count

    # ==================== PDFS ====================
    def get_pdfs(self):
        data = self._load_raw('pdfs.json')
        return list(data) if isinstance(data, list) else []

    def get_pdf(self, pdf_id: int):
        try:
            pid = int(pdf_id)
        except (ValueError, TypeError):
            return None
        for p in self.get_pdfs():
            if p.get('id') == pid:
                return dict(p)
        return None

    def save_pdf(self, pdf_data: dict) -> bool:
        pdfs = self.get_pdfs()
        pid = pdf_data.get('id')

        if pid is not None:
            pid = int(pid)
            for idx, p in enumerate(pdfs):
                if p.get('id') == pid:
                    pdfs[idx] = {**p, **pdf_data}
                    return self._save_raw('pdfs.json', pdfs)

        new_id = max([p.get('id', 0) for p in pdfs], default=0) + 1
        pdf_data['id'] = new_id
        if 'uploaded_at' not in pdf_data:
            pdf_data['uploaded_at'] = datetime.now().isoformat()
        if 'upload_date' not in pdf_data:
            pdf_data['upload_date'] = datetime.now().strftime('%Y-%m-%d')
        pdfs.append(pdf_data)
        return self._save_raw('pdfs.json', pdfs)

    def delete_pdf(self, pdf_id: int) -> bool:
        try:
            pid = int(pdf_id)
        except (ValueError, TypeError):
            return False
        pdfs = self.get_pdfs()
        filtered = [p for p in pdfs if p.get('id') != pid]
        if len(filtered) < len(pdfs):
            return self._save_raw('pdfs.json', filtered)
        return False

    def add_pdfs_bulk(self, new_pdfs: list) -> int:
        pdfs = self.get_pdfs()
        next_id = max([p.get('id', 0) for p in pdfs], default=0) + 1
        now_iso = datetime.now().isoformat()
        now_date = datetime.now().strftime('%Y-%m-%d')
        added = 0

        for np in new_pdfs:
            np['id'] = next_id
            next_id += 1
            np.setdefault('uploaded_at', now_iso)
            np.setdefault('upload_date', now_date)
            np.setdefault('file_size', 'N/A')
            pdfs.append(np)
            added += 1

        if added > 0:
            self._save_raw('pdfs.json', pdfs)
        return added

    # ==================== BOUNDARIES ====================
    def get_boundaries(self):
        data = self._load_raw('boundaries.json')
        return list(data) if isinstance(data, list) else []

    def save_boundary(self, boundary_data: dict) -> bool:
        boundaries = self.get_boundaries()
        bid = boundary_data.get('id')

        if bid is not None:
            bid = int(bid)
            for idx, b in enumerate(boundaries):
                if b.get('id') == bid:
                    boundaries[idx] = {**b, **boundary_data}
                    return self._save_raw('boundaries.json', boundaries)

        new_id = max([b.get('id', 0) for b in boundaries], default=0) + 1
        boundary_data['id'] = new_id
        if 'created_at' not in boundary_data:
            boundary_data['created_at'] = datetime.now().isoformat()
        boundaries.append(boundary_data)
        return self._save_raw('boundaries.json', boundaries)

    def delete_boundary(self, boundary_id: int) -> bool:
        try:
            bid = int(boundary_id)
        except (ValueError, TypeError):
            return False
        boundaries = self.get_boundaries()
        filtered = [b for b in boundaries if b.get('id') != bid]
        if len(filtered) < len(boundaries):
            return self._save_raw('boundaries.json', filtered)
        return False

    # ==================== CONTACTS ====================
    def get_contacts(self):
        data = self._load_raw('contacts.json')
        return list(data) if isinstance(data, list) else []

    def save_contact(self, contact_data: dict) -> bool:
        contacts = self.get_contacts()
        new_id = max([c.get('id', 0) for c in contacts], default=0) + 1
        contact_data['id'] = new_id
        contact_data.setdefault('submitted_at', datetime.now().isoformat())
        contact_data.setdefault('submitted_date', datetime.now().strftime('%Y-%m-%d'))
        contact_data.setdefault('status', 'pending')
        contacts.append(contact_data)
        return self._save_raw('contacts.json', contacts)

    def update_contact_status(self, contact_id: int, status: str) -> bool:
        try:
            cid = int(contact_id)
        except (ValueError, TypeError):
            return False
        contacts = self.get_contacts()
        for c in contacts:
            if c.get('id') == cid:
                c['status'] = status
                c['updated_at'] = datetime.now().isoformat()
                return self._save_raw('contacts.json', contacts)
        return False

    def delete_contact(self, contact_id: int) -> bool:
        try:
            cid = int(contact_id)
        except (ValueError, TypeError):
            return False
        contacts = self.get_contacts()
        filtered = [c for c in contacts if c.get('id') != cid]
        if len(filtered) < len(contacts):
            return self._save_raw('contacts.json', filtered)
        return False

    # ==================== ACCESS LOGS ====================
    def get_access_logs(self):
        data = self._load_raw('access_logs.json')
        return list(data) if isinstance(data, list) else []

    def log_access(self, username: str, action: str, location: str = None, pdf_id: int = None):
        try:
            logs = self.get_access_logs()
            now = datetime.now()
            entry = {
                'id': len(logs) + 1,
                'username': str(username or 'anonymous'),
                'action': str(action or 'general'),
                'location': location or 'Unknown',
                'pdf_id': pdf_id,
                'timestamp': now.isoformat(),
                'date': now.strftime('%Y-%m-%d'),
                'time': now.strftime('%H:%M:%S'),
                'hour': now.hour
            }
            logs.append(entry)

            # Keep 30 days of logs to maintain high performance
            cutoff = now - timedelta(days=30)
            logs = [
                l for l in logs
                if datetime.fromisoformat(l['timestamp']) > cutoff
            ]
            self._save_raw('access_logs.json', logs)
        except Exception as e:
            logger.error(f"Error logging access: {e}")

# Global instance
db = DataStore()

