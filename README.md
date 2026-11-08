# Vault E-Library – Secure Institutional Digital Repository

[![Platform](https://img.shields.io/badge/Platform-Python%20%7C%20Flask-4f46e5.svg)](#)
[![Security](https://img.shields.io/badge/Security-Geofenced%20%7C%20Protected-10b981.svg)](#)
[![Developer](https://img.shields.io/badge/Developed%20By-Aivontraa-0ea5e9.svg)](https://aivontraa.com)

A modern, professional, highly secure, responsive, and reliable digital library platform engineered for **Sphoorthy Engineering College**.

Developed by **[Aivontraa](https://aivontraa.com)**.

---

## 🏛️ System Architecture & Workflow

### 1. Unified Directory Structure
Consolidated into a clean, maintainable architecture:

```text
e-vault/
├── run.py                       # Root launcher (python run.py)
├── test_verification.py         # Automated test suite (26 comprehensive tests)
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
    ├── services/                # Decoupled backend service modules
    │   ├── auth_service.py      # Google OAuth & Student authentication
    │   ├── data_store.py        # Thread-safe, in-memory cached JSON store
    │   ├── document_service.py  # Zero-leakage PDF security & token signing
    │   └── location_service.py  # 5-second Haversine & polygon geofencing
    ├── static/
    │   ├── css/style.css        # Unified design system (Contact page visual standard)
    │   ├── js/script.js         # Unified client-side scripts & trackers
    │   └── images/              # College & developer branding assets
    └── templates/               # Responsive HTML templates with base.html
        ├── base.html            # Master layout with navbar, alerts & Aivontraa footer
        ├── welcome.html         # Landing page with TV/laptop and book animations
        ├── login.html           # Student Login portal (Rule Number + DOB)
        ├── admin_login.html     # Dedicated Administrator Google Sign-In portal
        ├── dashboard.html       # Student document catalog & viewer modal
        ├── viewer.html          # Protected viewer with dynamic watermark
        ├── location_check.html  # Geolocation verification interface (Pre-login)
        ├── contact.html         # Support inquiries with 5 categories & Aivontraa info
        ├── admin_dashboard.html # Admin PDF management console
        ├── admin_users.html     # Admin student & role management
        ├── admin_location.html  # Admin interactive Leaflet geofencing
        ├── admin_statistics.html# Analytics charts, logs & CSV export
        ├── admin_contacts.html  # Support ticket management
        ├── _pdf_table.html      # Partial template for PDF catalog
        └── error.html           # Defensive HTTP error displays (400/401/403/404/500)
```

---

## 🔒 Authentication & Access Flow

### 1. Mandatory Location Verification Before Student Login
Students must physically be within the college campus boundary before accessing the student login portal:
1. **Access Library**: When a student clicks "Access Library" (or visits `/login` directly without verification), they are routed to `/location-check`.
2. **Campus Geofencing**: Device GPS coordinates are captured and verified against campus boundaries (Sphoorthy Engineering College).
3. **Verification**: If within campus, the session is verified and the student is forwarded to `/login`, where a green **Campus Verified** badge is displayed.
4. **Boundary Restriction**: If outside campus, access is denied (`403 Forbidden`) with a clear explanation and retry options.

### 2. Student Authentication (Rule Number + Date of Birth)
* **Route**: `/login` (Accessible after campus location verification)
* **Fields**:
  * **Rule Number**: College-assigned roll number (e.g. `23N81A0501`).
  * **Date of Birth**: Registered birth date in `DDMMYYYY` format (also supports `DD-MM-YYYY` and `YYYY-MM-DD`).
* **Validation**: Validates credentials strictly against student records in `users.json`. Admin accounts are prevented from logging in through this interface.

### 3. Dedicated Administrator Authentication (Google Sign-In)
* **Route**: `/admin/login` (Dedicated, separate portal)
* **Mechanism**: Official Google Identity Services (GIS) button with backend token verification (`/api/auth/google`).
* **Whitelisting**: Authenticated email is verified against the `ADMIN_EMAILS` whitelist (`admin@aivontraa.com`, `support@aivontraa.com`, `admin@sphoorthyengg.ac.in`).
* **Authorization**: Non-whitelisted accounts and ordinary students are blocked (`403 Forbidden`).
* **Credentials Configured**:
  * Client ID: `493060599897-3eno2tujsceqc4guk9itf43l7s2jfpj9.apps.googleusercontent.com`
  * Client Secret: `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`

---

## 🎨 Design System & Visuals

* **Visual Standard**: Modeled after the Contact & Support page:
  * Google Font `Poppins` (weights 300 to 800).
  * Color combination: `--primary: #2E86AB`, `--primary-dark: #1B5E7A`, background `linear-gradient(135deg, #2E86AB 0%, #1B5E7A 100%)`.
  * Frosted glassmorphism navigation and header banners.
  * Rounded cards (`border-radius: 20px`) with top accent gradient stripe (`linear-gradient(90deg, #2E86AB, #1B5E7A)`).
  * Pill buttons (`border-radius: 50px`) with hover shimmer animation.
* **Preserved Animations**:
  * Interactive laptop/TV screen animation with studying figure and phone.
  * Floating books animation (`PDF`, `DOC`, `EPUB`, `PDF`) inside the screen.
  * Clickable book interaction (click to trigger float animation).
* **Company Branding Footer**:
  * Clean, minimal footer featuring exclusively:
    1. Company Logo: `https://aivontraa.com/assets/images/ai.png`
    2. Company Website Link: `https://aivontraa.com/`
    3. Text: **Developed by Aivontraa**
  * Zero personal names, founder details, or social profile credits.
* **Contact & Support Page**:
  * Coin-style radio selection for 5 support categories:
    1. Login Problems (`login_problems`)
    2. Library Access Issues (`library_access`)
    3. Book-Related Issues (`book_issues`)
    4. Technical Difficulties (`technical_difficulties`)
    5. General Queries (`general_queries`)
  * Displays official Aivontraa support contact info (`support@aivontraa.com`, `https://aivontraa.com/`).

---

## 🛡️ Security Audit & Protection Measures

| Protection | Implementation | Status |
| :--- | :--- | :---: |
| **Zero Drive URL Leaks** | Raw Google Drive URLs are stripped from student responses; document access is governed by 5-minute single-use HMAC-SHA256 viewing tokens (`/api/document/token/<id>`). | ✅ **Enforced** |
| **Print & Copy Suppression** | `@media print { body { display: none !important; } }`, right-click disabling, and blocking Ctrl+P, Ctrl+S, Ctrl+U, F12. | ✅ **Enforced** |
| **Dynamic Watermarking** | Full-screen repeating diagonal watermark with student ID, timestamp, and copyright notice. | ✅ **Enforced** |
| **Continuous Geofencing** | Background GPS verification every 5 seconds; auto-pauses when tab is hidden; immediate redirection if user leaves campus boundary. | ✅ **Enforced** |
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
Executes all 26 automated unit and integration tests covering authentication, geofencing, branding, security tokens, and null-safety.

---

## 👨‍💻 Platform Engineering

* **Developed By**: **Aivontraa**
* **Website**: [https://aivontraa.com](https://aivontraa.com)
* **Support Email**: `support@aivontraa.com`
* **Application**: Vault E-Library (Institutional Edition)
* **Client**: Sphoorthy Engineering College
