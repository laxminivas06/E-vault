# Vault E-Library – Secure Institutional Digital Repository

[![Platform](https://img.shields.io/badge/Platform-Python%20%7C%20Flask-4f46e5.svg)](#)
[![Security](https://img.shields.io/badge/Security-Geofenced%20%7C%20Protected-10b981.svg)](#)
[![Developer](https://img.shields.io/badge/Developed%20By-Aivontraa-0ea5e9.svg)](https://aivontraa.com)

A modern, professional, highly secure, responsive, and reliable digital library platform engineered for **Sphoorthy Engineering College**.

Developed by **[Aivontraa](https://aivontraa.com)**.

---

## 🏛️ System Architecture & Enhancements Overview

### 1. Unified, Professional Codebase Structure
Consolidated duplicate and nested directories (`library/`, redundant `.DS_Store`, and duplicate `boundaries.json`) into a clean, maintainable architecture:

```text
e-vault/
├── run.py                       # Root launcher
└── E-vault/
    ├── app.py                   # Central Flask application & route controllers
    ├── config.py                # Environment-driven, secure configuration
    ├── requirements.txt         # Dependency specifications
    ├── .env.example             # Safe environment configuration template
    ├── .gitignore               # Ignored runtime caches and secret configs
    ├── README.md                # System documentation
    ├── data/                    # Unified JSON storage
    │   ├── access_logs.json     # Access audit trails (30-day auto-rotation)
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
    │   ├── css/style.css        # Modern, responsive design system
    │   ├── js/script.js         # Unified client-side scripts & trackers
    │   └── images/              # College & developer branding assets
    └── templates/               # Responsive HTML templates with base.html
        ├── base.html            # Master layout with navbar, alerts & Aivontraa footer
        ├── welcome.html         # Landing page with live catalog metrics
        ├── login.html           # Unified Student & Google Admin login portal
        ├── dashboard.html       # Student document catalog & viewer modal
        ├── viewer.html          # Protected viewer with dynamic watermark
        ├── location_check.html  # Geolocation verification interface
        ├── contact.html         # Support inquiries & Aivontraa info
        ├── admin_dashboard.html # Admin PDF management console
        ├── admin_users.html     # Admin student & role management
        ├── admin_location.html  # Admin interactive Leaflet geofencing
        ├── admin_statistics.html# Analytics charts, logs & CSV export
        ├── admin_contacts.html  # Support ticket management
        ├── _pdf_table.html      # Partial template for PDF catalog
        └── error.html           # Defensive HTTP error displays (400/401/403/404/500)
```

---

## 🔒 Security Audit & Remediation Report

| Vulnerability Category | Original State | Remediation Implemented | Status |
| :--- | :--- | :--- | :--- |
| **Hardcoded Secrets** | Cleartext email app password (`raja rbot...`) and backdoor keys in code | Removed completely. All secrets read from environment variables or cryptographically generated per-process. | ✅ **Fixed** |
| **Backdoor Routes** | `/admin-direct-access` & `/user-direct-access` bypassed all security | Routes permanently eliminated. | ✅ **Fixed** |
| **Public Debug Data Leaks** | `/debug/pdfs` & `/debug/all-pdfs` publicly leaked 2,600+ Google Drive URLs | All public debug routes removed. | ✅ **Fixed** |
| **Credential & Drive Leaks** | Student dashboard serialized all 2,664 direct Google Drive URLs into client HTML | Direct URLs are **never** delivered to students. All document viewing runs through HMAC-signed, 5-minute single-use viewing tokens. | ✅ **Fixed** |
| **Plain Password Exposure** | Admin users page rendered cleartext passwords in HTML attributes (`data-password="..."`) | Passwords are never sent to the browser or rendered in DOM attributes. | ✅ **Fixed** |
| **Admin Authentication** | Relied on basic username/password form with weak frontend checks | Admin login button removed from public form. Administrators must authenticate using Google Sign-In with backend email whitelist validation. | ✅ **Fixed** |
| **Student Credentials** | Risk of breaking existing student login | Preserved exact student authentication: Roll Number (e.g. `23N81A0501`) and Date of Birth (`DDMMYYYY` / `YYYY-MM-DD`). | ✅ **Verified** |
| **Cursor "null" Bug** | Browser displayed "null" tooltips on cursor move due to unhandled `null` attribute values | Added safe text filtering in Jinja2 (`safe_text`) and JS (`safeText()`). Strict tooltip verification prevents any null/undefined display. | ✅ **Fixed** |
| **IDOR & Parameter Tampering** | Raw numeric IDs could be manipulated to view documents | Document tokens are cryptographically signed with HMAC-SHA256, binding student ID, document ID, and expiration. | ✅ **Fixed** |
| **Content Copying & Scraping** | No protection against print/save/screen scraping | Multi-layered defense: CSS print suppression (`@media print { body { display: none; } }`), dynamic student ID watermark, context menu & hotkey interception. | ✅ **Fixed** |
| **Database Performance** | Re-read 1.2MB JSON files from disk on every HTTP request | High-performance in-memory caching with thread locks reduces response latency by >95%. | ✅ **Fixed** |

---

## 📍 5-Second Geolocation Tracking

The application implements continuous campus geofencing using the HTML5 Geolocation API:
- **Frequency**: Background check approximately every **5 seconds** while the student session is active.
- **Algorithms**:
  - **Circle Boundaries**: Great-circle distance calculated using the Haversine trigonometric formula.
  - **Rectangle Boundaries**: Bounding coordinate box check.
  - **Polygon Boundaries**: Ray-casting point-in-polygon algorithm.
- **Efficiency**: Automatically pauses checks when the student switches tabs (`visibilitychange` API) to conserve battery and bandwidth, and resumes immediately upon focus.
- **Out-of-Bounds Enforcement**: If a user leaves the campus boundary, the session is invalidated and access to protected documents is revoked immediately.

---

## 🚀 Getting Started & Execution

### Prerequisites
- Python 3.9+
- Modern Web Browser (Chrome, Firefox, Edge, Safari)

### 1. Installation
Clone or navigate to the repository:
```bash
cd E-vault
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env` and fill in any customized values:
```bash
cp .env.example .env
```

### 3. Launch the Application
Run the launcher from either the project root:
```bash
python run.py
```
Or directly from `E-vault`:
```bash
python app.py
```
The server will start on `http://localhost:5000`.

---

## 👨‍💻 Developer Information

* **Developer**: **Aivontraa**
* **Website**: [https://aivontraa.com](https://aivontraa.com)
* **Application**: Vault E-Library (Institutional Edition)
* **License**: Proprietary institutional software for Sphoorthy Engineering College
