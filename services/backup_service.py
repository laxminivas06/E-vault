"""
Storage Lifecycle, Automatic Partitioning & Backup Retention Service for Vault E-Library.
Developed by Aivontraa Automation Private Limited (https://aivontraa.com).

Requirements:
1. Dynamic file partitioning: As access logs and non-catalog data increase,
   automatically save records into separate partitioned files.
2. 15-Day Backup: Automatically snapshot dynamic data (access logs, contacts, archives)
   every 15 days into dedicated backup storage.
3. 45-Day Automatic Retention Purge: All dynamic data older than 45 days is automatically
   deleted from active storage and backup archives.
4. Permanent Exemption: Users (users.json) and Courseware PDFs (pdfs.json) are strictly
   exempt from retention purging and are permanently preserved.
"""

import os
import json
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List

from config import Config

logger = logging.getLogger(__name__)


class StorageLifecycleService:
    # Retention and Partitioning Rules
    RETENTION_DAYS = 45
    BACKUP_INTERVAL_DAYS = 15
    PARTITION_THRESHOLD_ENTRIES = 500  # Automatically partition when log exceeds 500 entries

    # Explicitly exempt files that must NEVER be deleted by retention policy
    PERMANENT_EXEMPT_FILES = {'users.json', 'pdfs.json', 'credentials.json', 'boundaries.json'}

    def __init__(self, data_dir: Path = None):
        self.data_dir = Path(data_dir or Config.DATA_DIR)
        self.logs_dir = self.data_dir / 'logs'
        self.backups_dir = self.data_dir / 'backups'
        self.meta_file = self.data_dir / 'storage_lifecycle_meta.json'

        # Ensure directory structures exist
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

    def get_lifecycle_metadata(self) -> Dict[str, Any]:
        """Load metadata tracking last backup date and retention cleanup cycles."""
        if not self.meta_file.exists():
            default_meta = {
                'last_backup_at': None,
                'last_cleanup_at': None,
                'total_purged_records': 0,
                'total_partitions_created': 0,
                'retention_policy_days': self.RETENTION_DAYS,
                'backup_interval_days': self.BACKUP_INTERVAL_DAYS
            }
            self._save_metadata(default_meta)
            return default_meta

        try:
            with open(self.meta_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading lifecycle metadata: {e}")
            return {
                'last_backup_at': None,
                'last_cleanup_at': None,
                'total_purged_records': 0,
                'total_partitions_created': 0,
                'retention_policy_days': self.RETENTION_DAYS,
                'backup_interval_days': self.BACKUP_INTERVAL_DAYS
            }

    def _save_metadata(self, meta: Dict[str, Any]):
        try:
            with open(self.meta_file, 'w', encoding='utf-8') as f:
                json.dump(meta, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving lifecycle metadata: {e}")

    # ==================== 1. AUTOMATIC DATA PARTITIONING ====================

    def check_and_partition_logs(self, active_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        When access logs increase beyond PARTITION_THRESHOLD_ENTRIES,
        automatically partition the older records into a separate timestamped file.
        Returns the remaining active logs to keep in access_logs.json.
        """
        if not active_logs or len(active_logs) < self.PARTITION_THRESHOLD_ENTRIES:
            return active_logs

        try:
            # Keep the newest 100 entries active; archive the older entries
            cutoff_idx = len(active_logs) - 100
            to_archive = active_logs[:cutoff_idx]
            remaining_active = active_logs[cutoff_idx:]

            now_str = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            partition_filename = f"access_logs_partition_{now_str}.json"
            partition_path = self.logs_dir / partition_filename

            with open(partition_path, 'w', encoding='utf-8') as f:
                json.dump(to_archive, f, indent=2, ensure_ascii=False)

            logger.info(f"Auto-partitioned {len(to_archive)} logs into {partition_filename}")

            meta = self.get_lifecycle_metadata()
            meta['total_partitions_created'] = meta.get('total_partitions_created', 0) + 1
            meta['last_partition_at'] = datetime.now().isoformat()
            self._save_metadata(meta)

            return remaining_active
        except Exception as e:
            logger.error(f"Error during automatic log partitioning: {e}")
            return active_logs

    def load_all_partitioned_logs(self) -> List[Dict[str, Any]]:
        """Load all valid logs from partitioned separate files."""
        all_partitioned = []
        try:
            for file_path in sorted(self.logs_dir.glob("access_logs_partition_*.json")):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            all_partitioned.extend(data)
                except Exception as fe:
                    logger.warning(f"Could not read partition {file_path.name}: {fe}")
        except Exception as e:
            logger.error(f"Error loading partitioned logs: {e}")
        return all_partitioned

    # ==================== 2. 15-DAY BACKUP GENERATION ====================

    def run_15_day_backup_if_due(self, force: bool = False) -> Dict[str, Any]:
        """
        Create a dedicated snapshot backup of dynamic data (access logs, contacts, partitions)
        every 15 days. Users and PDFs are permanently preserved separately.
        """
        meta = self.get_lifecycle_metadata()
        last_backup_str = meta.get('last_backup_at')
        now = datetime.now()

        should_run = force
        if not should_run:
            if not last_backup_str:
                should_run = True
            else:
                try:
                    last_backup = datetime.fromisoformat(last_backup_str)
                    if now - last_backup >= timedelta(days=self.BACKUP_INTERVAL_DAYS):
                        should_run = True
                except Exception:
                    should_run = True

        if not should_run:
            return {'status': 'skipped', 'message': 'Backup not due yet.', 'last_backup_at': last_backup_str}

        return self.create_backup_snapshot()

    def is_permanently_exempt(self, filename: str) -> bool:
        """Check whether a file is permanently exempt from pruning or deletion."""
        return Path(filename).name in self.PERMANENT_EXEMPT_FILES

    def create_backup_snapshot(self) -> Dict[str, Any]:
        """Creates an immediate 15-day backup snapshot in data/backups/."""
        now = datetime.now()
        timestamp = now.strftime('%Y%m%d_%H%M%S_%f')
        snapshot_dir = self.backups_dir / f"backup_15d_{timestamp}"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        copied_files = []

        # Target files for 15-day backup: dynamic data only (exempting users and pdfs from pruning)
        targets = ['access_logs.json', 'contacts.json']
        for target in targets:
            src = self.data_dir / target
            if src.exists():
                dst = snapshot_dir / target
                shutil.copy2(src, dst)
                copied_files.append(target)

        # Also copy active partitions
        partitions_copied = 0
        for part in self.logs_dir.glob("access_logs_partition_*.json"):
            dst_part = snapshot_dir / part.name
            shutil.copy2(part, dst_part)
            partitions_copied += 1

        # Write manifest
        manifest = {
            'backup_timestamp': now.isoformat(),
            'backup_cycle_days': self.BACKUP_INTERVAL_DAYS,
            'retention_policy_days': self.RETENTION_DAYS,
            'files_backed_up': copied_files,
            'partitions_backed_up': partitions_copied,
            'exempt_permanent_files': list(self.PERMANENT_EXEMPT_FILES)
        }
        with open(snapshot_dir / 'manifest.json', 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

        meta = self.get_lifecycle_metadata()
        meta['last_backup_at'] = now.isoformat()
        self._save_metadata(meta)

        logger.info(f"Created 15-day backup snapshot at {snapshot_dir.name}")
        return {
            'success': True,
            'status': 'success',
            'message': f"Backup snapshot '{snapshot_dir.name}' created successfully.",
            'snapshot': snapshot_dir.name,
            'copied_files': copied_files,
            'partitions_count': partitions_copied,
            'timestamp': now.isoformat()
        }

    # ==================== 3. 45-DAY AUTOMATIC RETENTION PURGE ====================

    def run_45_day_retention_purge(self, dt: datetime = None) -> Dict[str, Any]:
        """
        Automatically purges all dynamic data older than 45 days:
        - Prunes access_logs.json entries older than 45 days.
        - Prunes contacts.json entries older than 45 days.
        - Deletes partitioned log files in data/logs/ older than 45 days.
        - Deletes backup snapshots in data/backups/ older than 45 days.
        - Stays 100% EXEMPT for users.json and pdfs.json.
        """
        now = dt or datetime.now()
        cutoff_date = now - timedelta(days=self.RETENTION_DAYS)
        purged_stats = {
            'logs_purged': 0,
            'contacts_purged': 0,
            'partition_files_deleted': 0,
            'backup_snapshots_deleted': 0
        }

        # 1. Prune active access_logs.json
        logs_file = self.data_dir / 'access_logs.json'
        if logs_file.exists():
            try:
                with open(logs_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
                if isinstance(logs, list):
                    original_len = len(logs)
                    retained_logs = [
                        l for l in logs
                        if self._is_within_retention(l.get('timestamp') or l.get('date'), cutoff_date)
                    ]
                    purged_stats['logs_purged'] += (original_len - len(retained_logs))
                    if len(retained_logs) != original_len:
                        with open(logs_file, 'w', encoding='utf-8') as f:
                            json.dump(retained_logs, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Error purging active access logs: {e}")

        # 2. Prune active contacts.json
        contacts_file = self.data_dir / 'contacts.json'
        if contacts_file.exists():
            try:
                with open(contacts_file, 'r', encoding='utf-8') as f:
                    contacts = json.load(f)
                if isinstance(contacts, list):
                    original_len = len(contacts)
                    retained_contacts = [
                        c for c in contacts
                        if self._is_within_retention(c.get('submitted_at') or c.get('submitted_date'), cutoff_date)
                    ]
                    purged_stats['contacts_purged'] += (original_len - len(retained_contacts))
                    if len(retained_contacts) != original_len:
                        with open(contacts_file, 'w', encoding='utf-8') as f:
                            json.dump(retained_contacts, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Error purging contacts: {e}")

        # 3. Delete expired partition files in data/logs/
        for part_file in self.logs_dir.glob("access_logs_partition_*.json"):
            try:
                is_expired = False
                # Try parsing date from filename
                parts = part_file.stem.split('_')
                if len(parts) >= 4 and len(parts[3]) == 8 and parts[3].isdigit():
                    try:
                        file_date = datetime.strptime(parts[3], '%Y%m%d')
                        if file_date < cutoff_date:
                            is_expired = True
                    except Exception:
                        pass
                
                if not is_expired:
                    mtime = datetime.fromtimestamp(part_file.stat().st_mtime)
                    if mtime < cutoff_date:
                        is_expired = True

                if is_expired:
                    part_file.unlink()
                    purged_stats['partition_files_deleted'] += 1
                    logger.info(f"Purged expired log partition: {part_file.name}")
            except Exception as pe:
                logger.error(f"Error inspecting partition file {part_file}: {pe}")

        # 4. Delete expired backup snapshots in data/backups/
        for snap_dir in self.backups_dir.glob("backup_15d_*"):
            if snap_dir.is_dir():
                try:
                    is_expired = False
                    parts = snap_dir.name.split('_')
                    if len(parts) >= 3 and len(parts[2]) == 8 and parts[2].isdigit():
                        try:
                            snap_date = datetime.strptime(parts[2], '%Y%m%d')
                            if snap_date < cutoff_date:
                                is_expired = True
                        except Exception:
                            pass

                    if not is_expired:
                        mtime = datetime.fromtimestamp(snap_dir.stat().st_mtime)
                        if mtime < cutoff_date:
                            is_expired = True

                    if is_expired:
                        shutil.rmtree(snap_dir)
                        purged_stats['backup_snapshots_deleted'] += 1
                        logger.info(f"Purged expired backup snapshot: {snap_dir.name}")
                except Exception as se:
                    logger.error(f"Error deleting expired backup {snap_dir}: {se}")

        meta = self.get_lifecycle_metadata()
        meta['last_cleanup_at'] = now.isoformat()
        total_p = sum(purged_stats.values())
        meta['total_purged_records'] = meta.get('total_purged_records', 0) + total_p
        self._save_metadata(meta)

        logger.info(f"45-day retention purge completed: {purged_stats}")
        return {
            'success': True,
            'status': 'success',
            'purged_stats': purged_stats,
            'cutoff_date': cutoff_date.isoformat(),
            'exempt_files': list(self.PERMANENT_EXEMPT_FILES)
        }

    # ==================== 4. STATUS & AUDITING ====================

    def get_storage_status(self) -> Dict[str, Any]:
        """Provides real-time storage, partition, and backup statistics for administrative UI."""
        meta = self.get_lifecycle_metadata()
        partitions = list(self.logs_dir.glob("access_logs_partition_*.json"))
        backups = [d for d in self.backups_dir.glob("backup_15d_*") if d.is_dir()]

        # File sizes
        def get_size_kb(p: Path) -> float:
            return round(p.stat().st_size / 1024, 2) if p.exists() else 0.0

        return {
            'retention_policy_days': self.RETENTION_DAYS,
            'backup_interval_days': self.BACKUP_INTERVAL_DAYS,
            'last_backup_at': meta.get('last_backup_at'),
            'last_cleanup_at': meta.get('last_cleanup_at'),
            'total_partitions': len(partitions),
            'total_backups': len(backups),
            'permanent_exempt_files': [
                {'name': 'users.json', 'desc': 'Student & Admin Accounts (Permanent)', 'size_kb': get_size_kb(self.data_dir / 'users.json')},
                {'name': 'pdfs.json', 'desc': 'Curated Courseware Catalog (Permanent)', 'size_kb': get_size_kb(self.data_dir / 'pdfs.json')},
                {'name': 'boundaries.json', 'desc': 'Campus Geofences & Coordinates', 'size_kb': get_size_kb(self.data_dir / 'boundaries.json')},
            ],
            'dynamic_lifecycle_files': [
                {'name': 'access_logs.json', 'desc': 'Active Access & Security Logs', 'size_kb': get_size_kb(self.data_dir / 'access_logs.json')},
                {'name': 'contacts.json', 'desc': 'Inquiries & Technical Tickets', 'size_kb': get_size_kb(self.data_dir / 'contacts.json')}
            ]
        }

    @staticmethod
    def _is_within_retention(timestamp_str: str, cutoff: datetime) -> bool:
        if not timestamp_str:
            return True
        try:
            # Handle ISO timestamps, space-separated timestamps, or YYYY-MM-DD
            clean_ts = str(timestamp_str).strip()[:19].replace(' ', 'T')
            if 'T' in clean_ts:
                dt = datetime.fromisoformat(clean_ts)
            else:
                dt = datetime.strptime(clean_ts[:10], '%Y-%m-%d')
            return dt >= cutoff
        except Exception:
            # On parse ambiguity, keep record to be safe
            return True


# Global lifecycle service instance
lifecycle_service = StorageLifecycleService()
