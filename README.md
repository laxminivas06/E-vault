# Vault E-Library – Secure Institutional Digital Repository

[![Platform](https://img.shields.io/badge/Platform-Python%20%7C%20Flask-4f46e5.svg)](#)
[![Security](https://img.shields.io/badge/Security-Geofenced%20%7C%20Protected-10b981.svg)](#)
[![Theme](https://img.shields.io/badge/UI%20Theme-Clean%20Modern%20Blue-1a73e8.svg)](#)
[![Developer](https://img.shields.io/badge/Developed%20By-Aivontraa%20Automation-0ea5e9.svg)](https://aivontraa.com)

A modern, professional, highly secure, responsive, and reliable digital library platform engineered for **Sphoorthy Engineering College**.

Developed by **[Aivontraa Automation Private Limited](https://aivontraa.com)**.

---

## 🏛️ System Architecture & Workflow

### 1. Unified Directory Structure
Consolidated into a clean, maintainable architecture:

```text
e-vault/
├── run.py                       # Root launcher (python run.py)
├── test_verification.py         # Automated test suite (28 comprehensive tests)
└── E-vault/
    ├── app.py                   # Central Flask application & route controllers
    ├── config.py                # Environment-driven, secure configuration
    ├── requirements.txt         # Dependency specifications
    ├── .env                     # Production environment configuration
    ├── .env.example             # Safe template
    ├── .gitignore               # Ignored runtime caches and secrets
    ├── README.md                # System documentation
    ├── data/                    # JSON data stores
    │   ├── access_logs.json     # Access audit trails (auto-rotated)
    │   ├── boundaries.json      # Campus geofence zones
    │   ├── contacts.json        # Support messages & requests
    │   ├── credentials.json     # Google OAuth 2.0 Client credentials
    │   ├── pdfs.json            # Academic documents catalog (2,600+ volumes)
    │   └── users.json           # Student & Admin user credentials
    │   ├── admin_dashboard.html # Admin PDF management console
    │   ├── admin_users.html     # Admin student & role management
    │   ├── admin_location.html  # Admin interactive Leaflet geofencing
    │   ├── admin_statistics.html# Analytics charts, logs & CSV export
    │   ├── admin_contacts.html  # Support ticket management
    │   ├── _pdf_table.html      # Partial template for PDF catalog
    │   └── error.html           # Defensive HTTP error displays (400/401/403/404/500)
    ├── services/                # Decoupled backend service modules
    │   ├── auth_service.py      # Google OAuth & Student authentication
    │   ├── data_store.py        # Thread-safe, in-memory cached JSON store
    │   ├── document_service.py  # Zero-leakage PDF security & token signing
    │   └── location_service.py  # 5-second Haversine & polygon geofencing
    ├── static/
    │   ├── css/style.css        # Clean Modern Blue design system (#1a73e8, Inter font)
    │   ├── js/script.js         # Unified client-side scripts, GIS auth & location trackers
    │   └── images/              # College & developer branding assets
    └── templates/               # Responsive HTML templates with base.html
        ├── base.html            # Master layout with navbar, alerts & minimal Aivontraa footer
        ├── welcome.html         # Landing page with TV/laptop and book animations
        ├── login.html           # Student Login portal (Rule Number + DOB)
        ├── admin_login.html     # Dedicated Administrator Google Sign-In portal
        ├── dashboard.html       # Student document catalog & viewer modal
        ├── viewer.html          # Protected viewer with dynamic watermark
        ├── location_check.html  # Geolocation verification interface (Pre-login)
        └── contact.html         # Support inquiries with 5 categories & Aivontraa info
```

---

## 🔒 Authentication & Access Flow

The application enforces a streamlined, privacy-conscious 4-step workflow:

```
WELCOME PAGE
    │
    ▼ [ACCESS LIBRARY]
LOCATION VERIFICATION (/location-check)
    │  • Browser GPS requested & validated against geofence
    │  • Strict campus perimeter enforcement; no public admin indicators
    │
    ▼ [Successful Campus Verification]
UNIFIED AUTHENTICATION PORTAL (/login)
    │
    ├─► Regular Users: Roll Number + Date of Birth (DDMMYYYY)
    └─► Privileged Accounts: Identified automatically via Google GIS or Username & Password
    │
    ▼
AUTHORIZED DASHBOARD
    • Regular Users ──► Student Dashboard (/dashboard)
    • Privileged Users ──► Administrative Console (/admin/dashboard)
```

### 1. Mandatory Location Verification Before Login
* **Route**: `/location-check`
* Initiated immediately when a user clicks **ACCESS LIBRARY**.
* Device GPS coordinates are captured and checked against active campus boundaries.
* If outside campus or permission is denied, clear instructions and retry options are presented.
* No bypass is permitted; authentication is accessible only after verified presence.

### 2. Unified Authentication Portal (No Separate Admin Page)
* **Route**: `/login` (Unified portal for all users; `/admin/login` redirects here)
* **Regular Users (Students)**:
  * **Roll Number**: e.g., `23N81A0501`
  * **Date of Birth**: Registered birth date in `DDMMYYYY` format.
* **Privileged Accounts (Administrators)**:
  * Automatically recognized via Google Identity Services (GIS) or email/password.
  * Zero public display of the words *Admin*, *Administrator Login*, *Google Admin*, or *Admin Portal*.
  * Privileged whitelist: `admin@aivontraa.com`, `support@aivontraa.com`, `admin@sphoorthyengg.ac.in`, `laxminivasmorishetty143@gmail.com`.

### 3. Dedicated Logout & Session Termination
* Prominent, visible **Logout** button placed directly in the header of all dashboards and the navigation bar.
* Clears the user session completely and redirects to the welcome page.
* Expired or terminated sessions are immediately blocked from protected routes.

### 4. Automatic Student Academic-Year Detection System
* **Prefix-Based Batch Identification**:
  * Extracts the admission year directly from the **first two digits of each student's roll number** (e.g. `23N81A0501` -> 2023, `24N81A0501` -> 2024).
  * Dynamic mathematical calculation (`2000 + prefix`) that automatically supports previous, current, and future admission batches without requiring hardcoded lists.
* **Continuous Academic Progression**:
  * Automatically calculates ongoing academic year and expected graduation year:
    * `22` -> Admission: 2022 -> Graduation: 2026 (Graduated)
    * `23` -> Admission: 2023 -> Graduation: 2027 (4th Year in 2026–27)
    * `24` -> Admission: 2024 -> Graduation: 2028 (3rd Year in 2026–27)
    * `25` -> Admission: 2025 -> Graduation: 2029 (2nd Year in 2026–27)
    * `26` -> Admission: 2026 -> Graduation: 2030 (1st Year in 2026–27)
    * `27` -> Admission: 2027 -> Graduation: 2031 (Pre-Admission)
* **Lateral Entry (LE) Students**:
  * Separate classification for students admitted through lateral entry.
  * Direct entry into 2nd year (3-year curriculum); does not use standard 4-year calculation.
  * Expected Graduation Year = Admission Year + 3.
  * Dedicated manual toggle in Admin User Directory and enrollment modal to mark students as **Lateral Entry (LE)**.
* **Administrative Override**:
  * Administrators can manually correct academic years or set custom overrides whenever needed.
* **System-Wide Integration**:
  * Real-time presentation across student dashboard user-info pill, PDF dynamic watermarking, administrative user directory, and AJAX search endpoints.

---

## 🎨 Design System & Visuals

* **Theme Tokens**:
  * Google Font `'Inter', sans-serif` (weights 400, 500, 600, 700, 800).
  * Color combination: `--primary: #1a73e8` (Google Blue), `--primary-dark: #1557b0`, `--secondary: #e8f0fe`, `--bg-color: #f4f7fe` (clean light tech background), `--card-bg: #ffffff`, `--text-main: #1e293b`.
  * Frosted glass navigation bar (`rgba(255, 255, 255, 0.95)`, `backdrop-filter: blur(10px)`).
  * White cards (`border-radius: 20px`) with primary blue header bars.
  * Pill buttons (`border-radius: 50px`) for actions.
* **Header Redesign**:
  * For unauthenticated visitors: displays exclusively the brand on the left and a clean **Contact Icon** (`<i class="fas fa-headset"></i>`) on the right.
  * All clutter (Home, Access Library, Admin buttons) removed from guest navbar.
* **Hero Section**:
  * Clean primary blue (`#1a73e8`) hero with interactive TV screen and floating books animation.
  * Single, unmistakable primary call-to-action button: **ACCESS LIBRARY**.
* **Interactive Map & Geofencing**:
  * High-resolution **Satellite Aerial Imagery** (Esri World Imagery) and **Hybrid View** (Google Satellite with labels).
  * Interactive drawing toolbar (Circle, Rectangle, Polygon) with full dual-endpoint backend support.
* **Company Branding Footer**:
  * Clean, minimal footer featuring exclusively:
    1. Company Logo: `https://aivontraa.com/assets/images/ai.png`
    2. Company Website Link: `https://aivontraa.com/`
    3. Text: **Developed by Aivontraa Automation Private Limited**
  * Zero personal names, founder details, or personal social profile credits.
* **Contact & Support Page**:
  * Minimal, focused support inquiry form with essential institutional contact info (`hello.aivontraa@gmail.com`, `https://aivontraa.com/`).
  * Dynamic inquiry categories with custom topic support when "Other" is chosen.
  * 100% responsive layout across mobile, tablet, laptop, and desktop.

---

## 🛡️ Security Audit & Protection Measures

| Protection | Implementation | Status |
| :--- | :--- | :---: |
| **Document Content Protection** | Restricts right-click context menu and inspection shortcuts inside document viewer modal. | ✅ **Enforced** |
| **Zero Drive URL Leaks** | Raw Google Drive URLs are stripped from student responses; document access is governed by 5-minute single-use HMAC-SHA256 viewing tokens (`/api/document/token/<id>`). | ✅ **Enforced** |
| **Print & Copy Suppression** | `@media print { body { display: none !important; } }`, right-click disabling on viewer, and blocking Ctrl+P, Ctrl+S, Ctrl+U, F12. | ✅ **Enforced** |
| **Dynamic Watermarking** | Full-screen repeating diagonal watermark with student ID, timestamp, and copyright notice. | ✅ **Enforced** |
| **Continuous Geofencing** | Background GPS verification every 5 seconds; auto-pauses when tab is hidden; immediate redirection if user leaves campus boundary. | ✅ **Enforced** |
| **Pre-Login Location Gate** | Mandatory verification before accessing student login; unverified attempts auto-routed to `/location-check`. | ✅ **Enforced** |
| **Null Display Bug Fix** | Sanitized all hover events, tooltips, and data bindings via `safeText()` and `safe_text` Jinja filters so `null`, `undefined`, or `None` are never displayed. | ✅ **Fixed** |
| **Caching & Performance** | Thread-safe in-memory caching of JSON repositories for sub-50ms response times. | ✅ **Optimized** |

---

## 🚀 Running the Platform

### 1. Installation
```powershell
# Navigate to the project root
cd c:\Users\laxmi\OneDrive\Desktop\e-vault
pip install -r E-vault/requirements.txt
```

### 2. Start the Application
```powershell
python run.py
```
The server will be available at `http://localhost:5000`.

* **Student E-Library & Welcome**: `http://localhost:5000/` or `http://localhost:5000/welcome`
* **Campus Location Verification**: `http://localhost:5000/location-check`
* **Student Login**: `http://localhost:5000/login`
* **Dedicated Administrator Portal**: `http://localhost:5000/admin/login`
* **Contact & Support Desk**: `http://localhost:5000/contact`

### 3. Run Automated Tests
```powershell
python test_verification.py
```
Executes all 30 automated unit and integration tests covering authentication, geofencing, branding, security tokens, Inter typography, mobile responsiveness, and zero-error stability.

---

## 👨‍💻 Platform Engineering

* **Developed By**: **Aivontraa Automation Private Limited**
* **Website**: [https://aivontraa.com](https://aivontraa.com)
* **Support Email**: `hello.aivontraa@gmail.com`
* **Application**: Vault E-Library (Institutional Edition)
* **Client**: Sphoorthy Engineering College
