"""
Academic Year Detection & Progression Service for Vault E-Library.
Developed by Aivontraa Automation Private Limited (https://aivontraa.com).

Calculates student admission year, expected graduation year, and current academic year
dynamically based on the first two digits of each student's roll number.
Distinguishes between regular 4-year engineering students and Lateral Entry (LE) students,
with support for administrative overrides and future admission batches.
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any, Union

logger = logging.getLogger(__name__)


class AcademicService:
    # In Indian engineering institutions, the academic year commences in June/July (Month >= 6)
    ACADEMIC_YEAR_START_MONTH = 6

    @classmethod
    def get_admission_year(cls, roll_number: Union[str, int]) -> Optional[int]:
        """
        Identify admission year from the first two digits of the student's roll number.
        Example: '23N81A0501' -> 2023.
        Supports any 2-digit prefix dynamically:
          '22' -> 2022
          '23' -> 2023
          '24' -> 2024
          '25' -> 2025
          '26' -> 2026
          '27' -> 2027
          Future batches ('28', '29', ...) automatically map to 2000 + prefix.
        """
        if not roll_number:
            return None
        roll_clean = str(roll_number).strip().upper()
        if len(roll_clean) >= 2 and roll_clean[:2].isdigit():
            prefix = int(roll_clean[:2])
            return 2000 + prefix
        return None

    @classmethod
    def get_current_academic_start_year(cls, dt: Optional[datetime] = None) -> int:
        """
        Determine the starting calendar year of the ongoing academic session.
        If current month >= 6 (June-December), current academic year starts in current year.
        If current month < 6 (January-May), current academic year started in previous year.
        Example: November 2026 -> 2026 (for academic session 2026–27).
        """
        current_dt = dt or datetime.now()
        if current_dt.month >= cls.ACADEMIC_YEAR_START_MONTH:
            return current_dt.year
        return current_dt.year - 1

    @classmethod
    def get_current_academic_session(cls, dt: Optional[datetime] = None) -> str:
        """
        Returns academic session formatted as '2026–27'.
        """
        start_year = cls.get_current_academic_start_year(dt)
        end_year = start_year + 1
        return f"{start_year}–{str(end_year)[-2:]}"

    @classmethod
    def is_lateral_entry_roll(cls, roll_number: Union[str, int]) -> bool:
        """
        Heuristic detection for JNTUH / State university lateral entry roll format (e.g. '5A' at indices 4:6).
        Regular 4-year entry typically uses '1A', while lateral entry uses '5A'.
        """
        if not roll_number:
            return False
        clean = str(roll_number).strip().upper()
        if len(clean) >= 6 and clean[4:6] == '5A':
            return True
        return False

    @classmethod
    def calculate_student_academic_info(
        cls,
        user_or_roll: Any,
        is_lateral_entry: Optional[bool] = None,
        manual_year: Optional[str] = None,
        dt: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Dynamically calculate student's academic year, batch, and status.

        Calculation Rules:
        1. Read first 2 digits of roll number for admission year.
        2. Regular students:
           - 4-year engineering curriculum.
           - Graduation Year = admission_year + 4.
           - Year 1 in (admission_year)–(admission_year + 1).
           - Academic year = (current_academic_start_year - admission_year) + 1.
        3. Lateral Entry (LE) students:
           - Admitted directly into 2nd year.
           - 3-year curriculum (2nd, 3rd, 4th year).
           - Graduation Year = admission_year + 3.
           - Year 2 in (admission_year)–(admission_year + 1).
           - Academic year = (current_academic_start_year - admission_year) + 2.
        4. Manual Override:
           - If an administrator specified a manual year, honor it without overriding historical record.
        """
        roll_number = ""
        role = "student"
        explicit_le = is_lateral_entry
        override_year = manual_year

        if isinstance(user_or_roll, dict):
            roll_number = str(user_or_roll.get('username', '')).strip().upper()
            role = str(user_or_roll.get('role', 'student')).strip().lower()

            if explicit_le is None:
                if 'is_lateral_entry' in user_or_roll:
                    val = user_or_roll.get('is_lateral_entry')
                    if isinstance(val, str):
                        explicit_le = val.strip().lower() in ('true', 'yes', '1', 'le', 'lateral')
                    else:
                        explicit_le = bool(val)
                elif user_or_roll.get('entry_type') == 'lateral':
                    explicit_le = True
                elif cls.is_lateral_entry_roll(roll_number):
                    explicit_le = True
                else:
                    explicit_le = False

            if override_year is None:
                override_year = user_or_roll.get('manual_year_override')
        else:
            roll_number = str(user_or_roll).strip().upper()
            if explicit_le is None:
                explicit_le = cls.is_lateral_entry_roll(roll_number)

        current_start_year = cls.get_current_academic_start_year(dt)
        session_str = cls.get_current_academic_session(dt)

        # For non-student or missing roll numbers
        if role != 'student' or not roll_number:
            return {
                'roll_number': roll_number,
                'role': role,
                'admission_year': None,
                'graduation_year': None,
                'academic_year': None,
                'year_label': None,
                'display_badge': None,
                'academic_session': session_str,
                'batch_label': None,
                'is_lateral_entry': False,
                'entry_label': 'Regular',
                'is_graduated': False,
                'is_manual_override': False
            }

        admission_year = cls.get_admission_year(roll_number)

        # If roll number does not start with digits
        if not admission_year:
            year_label = override_year if (override_year and override_year.lower() != 'auto') else "Student"
            return {
                'roll_number': roll_number,
                'role': role,
                'admission_year': None,
                'graduation_year': None,
                'academic_year': cls._parse_year_number(year_label),
                'year_label': year_label,
                'display_badge': year_label,
                'academic_session': session_str,
                'batch_label': None,
                'is_lateral_entry': bool(explicit_le),
                'entry_label': 'Lateral Entry' if explicit_le else 'Regular',
                'is_graduated': False,
                'is_manual_override': bool(override_year and override_year.lower() != 'auto')
            }

        # Expected Graduation Year
        if explicit_le:
            graduation_year = admission_year + 3
            entry_label = 'Lateral Entry'
        else:
            graduation_year = admission_year + 4
            entry_label = 'Regular'

        batch_label = f"{admission_year}–{graduation_year}"

        # If administrative manual override is active
        if override_year and str(override_year).strip() and str(override_year).strip().lower() != 'auto':
            clean_override = str(override_year).strip()
            num = cls._parse_year_number(clean_override)
            is_grad = 'graduat' in clean_override.lower()
            badge = clean_override
            if explicit_le and "(LE)" not in badge and not is_grad:
                badge = f"{badge} (LE)"

            return {
                'roll_number': roll_number,
                'role': role,
                'admission_year': admission_year,
                'graduation_year': graduation_year,
                'academic_year': num,
                'year_label': clean_override,
                'display_badge': badge,
                'academic_session': session_str,
                'batch_label': batch_label,
                'is_lateral_entry': bool(explicit_le),
                'entry_label': entry_label,
                'is_graduated': is_grad,
                'is_manual_override': True
            }

        # Automatic calculation
        years_elapsed = current_start_year - admission_year

        if explicit_le:
            calc_year = years_elapsed + 2
        else:
            calc_year = years_elapsed + 1

        year_ordinals = {
            1: "1st Year",
            2: "2nd Year",
            3: "3rd Year",
            4: "4th Year"
        }

        if calc_year < 1 or (explicit_le and calc_year < 2):
            year_label = "Pre-Admission"
            is_graduated = False
            academic_year_num = None
        elif calc_year > 4:
            year_label = "Graduated"
            is_graduated = True
            academic_year_num = 5
        else:
            year_label = year_ordinals.get(calc_year, f"{calc_year}th Year")
            is_graduated = False
            academic_year_num = calc_year

        display_badge = f"{year_label} (LE)" if explicit_le and not is_graduated and year_label != "Pre-Admission" else year_label

        return {
            'roll_number': roll_number,
            'role': role,
            'admission_year': admission_year,
            'graduation_year': graduation_year,
            'academic_year': academic_year_num,
            'year_label': year_label,
            'display_badge': display_badge,
            'academic_session': session_str,
            'batch_label': batch_label,
            'is_lateral_entry': bool(explicit_le),
            'entry_label': entry_label,
            'is_graduated': is_graduated,
            'is_manual_override': False
        }

    @classmethod
    def enrich_user_academic_info(cls, user_dict: dict, dt: Optional[datetime] = None) -> dict:
        """
        Enrich a user record with calculated academic progression fields.
        Does not mutate the original dictionary.
        """
        if not user_dict:
            return {}
        res = dict(user_dict)
        info = cls.calculate_student_academic_info(user_dict, dt=dt)
        res['admission_year'] = info.get('admission_year')
        res['graduation_year'] = info.get('graduation_year')
        res['academic_year'] = info.get('academic_year')
        res['year_label'] = info.get('year_label')
        res['display_badge'] = info.get('display_badge')
        res['academic_session'] = info.get('academic_session')
        res['batch_label'] = info.get('batch_label')
        res['is_lateral_entry'] = info.get('is_lateral_entry', False)
        res['entry_label'] = info.get('entry_label', 'Regular')
        res['is_graduated'] = info.get('is_graduated', False)
        res['is_manual_override'] = info.get('is_manual_override', False)
        return res

    @staticmethod
    def _parse_year_number(label: str) -> Optional[int]:
        if not label:
            return None
        l = label.lower()
        if '1st' in l or '1' in l:
            return 1
        if '2nd' in l or '2' in l:
            return 2
        if '3rd' in l or '3' in l:
            return 3
        if '4th' in l or '4' in l:
            return 4
        if 'graduat' in l:
            return 5
        return None
