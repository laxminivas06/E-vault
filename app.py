import os
import io
import csv
import logging
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, send_file, make_response
)
from werkzeug.utils import secure_filename
import pandas as pd

from config import Config
from services.data_store import db
from services.auth_service import (
    AuthService, require_login, require_admin, require_student,
    require_location_verification
)
from services.location_service import LocationService
from services.document_service import DocumentService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask App
app = Flask(
    __name__,
    static_folder=str(Config.STATIC_DIR),
    template_folder=str(Config.TEMPLATES_DIR)
)
app.config.from_object(Config)

# Register Jinja2 safe text filter to prevent any "None" or "null" displays
@app.template_filter('safe_text')
def safe_text_filter(val, fallback=''):
    if val is None or str(val).strip().lower() in ['none', 'null', 'undefined']:
        return fallback
    return str(val)

@app.context_processor
def inject_common_variables():
    """Inject global context variables available across all templates."""
    return {
        'current_year': datetime.now().year,
        'app_name': Config.APP_NAME,
        'college_name': Config.COLLEGE_NAME,
        'company_name': Config.COMPANY_NAME,
        'company_url': Config.COMPANY_URL,
        'company_logo_url': Config.COMPANY_LOGO_URL,
        'developer_credit': Config.DEVELOPER_CREDIT,
        'support_email': Config.SUPPORT_EMAIL,
        'google_client_id': Config.GOOGLE_CLIENT_ID,
        'location_check_interval_ms': Config.LOCATION_CHECK_INTERVAL_MS,
        'user_id': session.get('user_id'),
        'user_name': session.get('user_name', session.get('user_id', '')),
        'user_role': session.get('user_role'),
        'location_verified': session.get('location_verified', False),
        'verified_location': session.get('verified_location', 'Campus')
    }

@app.after_request
def add_security_headers(response):
    """Add defensive HTTP security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ==================== PUBLIC & AUTH ROUTES ====================

@app.route('/')
def index():
    if session.get('user_id'):
        if session.get('user_role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('welcome'))

@app.route('/welcome')
def welcome():
    stats = {
        'total_users': len(db.get_users()),
        'total_pdfs': len(db.get_pdfs())
    }
    return render_template('welcome.html', stats=stats)

@app.route('/api/stats')
def api_stats():
    """Public stats for welcome page."""
    return jsonify({
        'success': True,
        'stats': {
            'total_users': len(db.get_users()),
            'total_pdfs': len(db.get_pdfs())
        }
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Dedicated Student Login Portal:
    - Authenticates using Rule Number and Date of Birth (DDMMYYYY).
    - Validates against registered student records.
    - Clear validation messages.
    """
    if session.get('user_id'):
        if session.get('user_role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Accept Rule Number (or Username) and Date of Birth (or Password)
        rule_number = request.form.get('rule_number', request.form.get('username', '')).strip()
        dob = request.form.get('dob', request.form.get('password', '')).strip()

        # Rate limiting check
        client_ip = request.remote_addr or '127.0.0.1'
        if AuthService.is_rate_limited(client_ip):
            flash('Too many login attempts. Please wait 60 seconds before trying again.', 'error')
            return render_template('login.html'), 429

        if not rule_number or not dob:
            flash('Please enter both your Rule Number and Date of Birth.', 'error')
            return render_template('login.html')

        # Student authentication
        success, msg, user = AuthService.authenticate_student(rule_number, dob)
        if success and user:
            session.clear()
            session['user_id'] = user['username']
            session['user_name'] = user.get('name', user['username'])
            session['user_role'] = 'student'
            session['login_time'] = datetime.now().isoformat()
            session['auth_method'] = 'credentials'
            session.permanent = True

            current_loc = session.get('verified_location', 'Campus')
            db.log_access(user['username'], 'student_login', current_loc)
            logger.info(f"Student logged in: {user['username']}")

            flash(f"Welcome back, {user.get('name', user['username'])}!", 'success')
            intended = session.pop('intended_url', None)
            return redirect(intended or url_for('dashboard'))
        else:
            db.log_access(rule_number, 'failed_student_login', session.get('verified_location', 'Unknown'))
            flash(msg, 'error')

    return render_template('login.html')

@app.route('/admin/login', methods=['GET'])
def admin_login():
    """
    Dedicated Administrator Sign-In Portal:
    - Purely administrator authentication via Google Sign-In.
    - Completely separate from student credentials.
    """
    if session.get('user_id'):
        if session.get('user_role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        flash('You are signed in as a student. Admin privileges required.', 'warning')
        return redirect(url_for('dashboard'))

    return render_template('admin_login.html')

@app.route('/api/auth/google', methods=['POST'])
def api_auth_google():
    """
    Secure Administrator Google Sign-In Endpoint.
    Validates Google ID token server-side and enforces authorized admin email whitelist.
    """
    data = request.get_json(silent=True) or {}
    id_token = data.get('credential') or data.get('id_token')

    if not id_token:
        return jsonify({'success': False, 'message': 'Google authentication credential is required.'}), 400

    # Verify ID token with Google's servers
    success, msg, admin_info = AuthService.verify_google_id_token(id_token)

    if not success or not admin_info:
        logger.warning(f"Failed Google Admin Login: {msg}")
        return jsonify({'success': False, 'message': msg}), 403

    # Authenticated & Authorized Administrator
    email = admin_info['email']
    name = admin_info.get('name', 'Administrator')

    session.clear()
    session['user_id'] = email
    session['user_name'] = name
    session['user_role'] = 'admin'
    session['auth_method'] = 'google'
    session['login_time'] = datetime.now().isoformat()
    session['location_verified'] = True
    session['verified_location'] = 'Administrative Portal'
    session.permanent = True

    db.log_access(email, 'admin_google_login', 'Administrative Console')
    logger.info(f"Authorized Admin logged in via Google: {email}")

    return jsonify({
        'success': True,
        'message': f"Welcome Administrator {name}!",
        'redirect_url': url_for('admin_dashboard')
    })

@app.route('/logout')
def logout():
    username = session.get('user_id', 'user')
    loc = session.get('verified_location', 'Unknown')
    db.log_access(username, 'logout', loc)
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('login'))

# ==================== GEOLOCATION VERIFICATION ====================

@app.route('/location-check', methods=['GET', 'POST'])
def location_check():
    """Initial location verification page."""
    if not session.get('user_id'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        lat = data.get('latitude')
        lon = data.get('longitude')

        allowed, loc_name = LocationService.check_user_location(lat, lon)
        if allowed:
            session['location_verified'] = True
            session['verified_location'] = loc_name or Config.DEFAULT_CAMPUS_NAME
            session['last_location_check'] = datetime.now().isoformat()

            db.log_access(session.get('user_id'), 'location_verified', loc_name)

            intended = session.pop('intended_url', None)
            target_url = intended or (url_for('admin_dashboard') if session.get('user_role') == 'admin' else url_for('dashboard'))

            if request.is_json:
                return jsonify({'success': True, 'location': loc_name, 'redirect_url': target_url})
            flash(f"Location verified: {loc_name}", 'success')
            return redirect(target_url)
        else:
            msg = "You are currently outside the authorized campus boundary."
            if request.is_json:
                return jsonify({'success': False, 'message': msg}), 403
            flash(msg, 'error')

    return render_template('location_check.html')

@app.route('/check-boundary', methods=['POST'])
def check_boundary():
    """Single boundary check endpoint."""
    data = request.get_json(silent=True) or {}
    lat = data.get('latitude')
    lon = data.get('longitude')

    allowed, loc_name = LocationService.check_user_location(lat, lon)
    if allowed:
        session['location_verified'] = True
        session['verified_location'] = loc_name or Config.DEFAULT_CAMPUS_NAME
        return jsonify({'success': True, 'location': loc_name})

    session['location_verified'] = False
    return jsonify({
        'success': False,
        'message': 'Outside allowed area',
        'redirect': True,
        'redirect_url': url_for('location_check')
    }), 403

@app.route('/api/check-location-continuous', methods=['POST'])
@app.route('/real-time-location-check', methods=['POST'])
def api_check_location_continuous():
    """
    Continuous 5-second location tracking endpoint.
    Validates user coordinates, updates verified status, and stops/redirects if out of bounds.
    """
    if not session.get('user_id'):
        return jsonify({'success': False, 'message': 'Session expired. Please log in.', 'redirect': True, 'redirect_url': url_for('login')}), 401

    data = request.get_json(silent=True) or {}
    lat = data.get('latitude')
    lon = data.get('longitude')

    if lat is None or lon is None:
        return jsonify({'success': False, 'message': 'Coordinates missing.'}), 400

    allowed, loc_name = LocationService.check_user_location(lat, lon)

    if allowed:
        session['location_verified'] = True
        session['verified_location'] = loc_name or Config.DEFAULT_CAMPUS_NAME
        session['last_location_check'] = datetime.now().isoformat()
        return jsonify({
            'success': True,
            'location': loc_name or Config.DEFAULT_CAMPUS_NAME,
            'interval': Config.LOCATION_CHECK_INTERVAL_SECONDS
        })
    else:
        session['location_verified'] = False
        db.log_access(session.get('user_id'), 'boundary_violation', 'Outside Boundary')
        return jsonify({
            'success': False,
            'message': 'You are outside the designated campus boundary. Access to vault documents is restricted.',
            'redirect': True,
            'redirect_url': url_for('location_check')
        }), 403

# ==================== STUDENT DASHBOARD & DOCUMENT ACCESS ====================

@app.route('/dashboard')
@require_login
@require_location_verification
def dashboard():
    """
    Student document library dashboard.
    Enforces server-side pagination and sanitized document records.
    Direct Google Drive URLs are NEVER transmitted to the client.
    """
    user_role = session.get('user_role')
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    per_page = Config.DEFAULT_PER_PAGE_PDFS

    all_pdfs = db.get_pdfs()

    if search_query:
        q = search_query.lower()
        filtered_pdfs = [
            p for p in all_pdfs
            if q in str(p.get('title', '')).lower()
            or q in str(p.get('subject', '')).lower()
            or q in str(p.get('branch', '')).lower()
        ]
    else:
        filtered_pdfs = all_pdfs

    total_pdfs = len(filtered_pdfs)
    total_pages = max(1, (total_pdfs + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start = (page - 1) * per_page
    end = start + per_page
    page_pdfs_raw = filtered_pdfs[start:end]

    # Sanitize: Strip all raw drive_link fields from student view data
    page_pdfs = [DocumentService.sanitize_pdf_for_student(p) for p in page_pdfs_raw]

    user_stats = {
        'total_pdfs': len(all_pdfs),
        'documents_viewed': session.get('documents_viewed', 0),
        'last_login': session.get('login_time', 'Recently')[:10] if session.get('login_time') else 'Recently'
    }

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'pdfs': page_pdfs,
            'page': page,
            'total_pages': total_pages,
            'total_pdfs': total_pdfs,
            'per_page': per_page
        })

    return render_template(
        'dashboard.html',
        pdfs=page_pdfs,
        page=page,
        total_pages=total_pages,
        total_pdfs=total_pdfs,
        per_page=per_page,
        search_query=search_query,
        user_stats=user_stats
    )

@app.route('/api/document/token/<int:pdf_id>', methods=['POST'])
@require_login
@require_location_verification
def api_get_document_token(pdf_id):
    """
    Generate an authenticated, short-lived, HMAC-signed token for viewing a document.
    Prevents URL enumeration, IDOR, and unauthorized link sharing.
    """
    pdf = db.get_pdf(pdf_id)
    if not pdf:
        return jsonify({'success': False, 'message': 'Document not found.'}), 404

    user_id = session.get('user_id')
    token = DocumentService.generate_view_token(pdf_id, user_id)

    db.log_access(user_id, 'pdf_token_requested', session.get('verified_location'), pdf_id)
    session['documents_viewed'] = session.get('documents_viewed', 0) + 1

    return jsonify({
        'success': True,
        'pdf_title': pdf.get('title', 'Document Viewer'),
        'view_url': url_for('view_document', pdf_id=pdf_id, token=token)
    })

@app.route('/viewer/<int:pdf_id>')
@require_login
@require_location_verification
def view_document(pdf_id):
    """
    Secure document viewer with visual watermarking, print blocking, and content controls.
    """
    token = request.args.get('token')
    user_id = session.get('user_id')

    if not DocumentService.verify_view_token(token, pdf_id, user_id):
        flash('Invalid or expired document viewing session.', 'error')
        return redirect(url_for('dashboard'))

    pdf = db.get_pdf(pdf_id)
    if not pdf:
        flash('Document not found.', 'error')
        return redirect(url_for('dashboard'))

    embed_url = DocumentService.get_secure_embed_url(pdf.get('drive_link', ''))
    watermark_text = f"VAULT E-LIBRARY • {user_id} • {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    response = make_response(render_template(
        'viewer.html',
        pdf_title=pdf.get('title', 'Protected Document'),
        embed_url=embed_url,
        watermark_text=watermark_text
    ))

    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/track-pdf-view', methods=['POST'])
@require_login
def track_pdf_view():
    data = request.get_json(silent=True) or {}
    pdf_id = data.get('pdf_id')
    try:
        pid = int(pdf_id)
        db.log_access(session.get('user_id'), 'pdf_view', session.get('verified_location'), pid)
        session['documents_viewed'] = session.get('documents_viewed', 0) + 1
        return jsonify({'success': True})
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid PDF ID'}), 400

# ==================== CONTACT / SUPPORT ====================

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        message_type = request.form.get('message_type', 'general_query').strip()
        message = request.form.get('message', '').strip()

        if not name or not email or not message:
            flash('Please complete all required fields.', 'error')
            return render_template('contact.html')

        contact_entry = {
            'name': name,
            'email': email,
            'contact_number': contact_number,
            'message_type': message_type,
            'message': message,
            'submitted_by': session.get('user_id', 'guest'),
            'location': session.get('verified_location', 'Online')
        }

        db.save_contact(contact_entry)
        db.log_access(session.get('user_id', email), 'contact_submitted')
        flash('Thank you! Your support request has been submitted to our team.', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

# ==================== ADMINISTRATOR CONSOLE ====================

@app.route('/admin')
@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    """Admin PDF management dashboard."""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    per_page = Config.DEFAULT_PER_PAGE_PDFS

    all_pdfs = db.get_pdfs()

    if search_query:
        q = search_query.lower()
        filtered = [p for p in all_pdfs if q in str(p.get('title', '')).lower()]
    else:
        filtered = all_pdfs

    total_pdfs = len(filtered)
    total_pages = max(1, (total_pdfs + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start = (page - 1) * per_page
    end = start + per_page
    page_pdfs = filtered[start:end]

    stats = {
        'total_pdfs': len(all_pdfs),
        'total_users': len(db.get_users()),
        'total_contacts': len([c for c in db.get_contacts() if c.get('status') == 'pending'])
    }

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template(
            '_pdf_table.html',
            pdfs=page_pdfs,
            page=page,
            total_pages=total_pages,
            total_pdfs=total_pdfs,
            per_page=per_page,
            search_query=search_query
        )

    return render_template(
        'admin_dashboard.html',
        pdfs=page_pdfs,
        page=page,
        total_pages=total_pages,
        total_pdfs=total_pdfs,
        per_page=per_page,
        search_query=search_query,
        stats=stats
    )

@app.route('/admin/add-pdf', methods=['POST'])
@require_admin
def admin_add_pdf():
    data = request.get_json(silent=True) or request.form
    title = str(data.get('title', '')).strip()
    drive_link = str(data.get('drive_link', '')).strip()

    if not title or not drive_link:
        return jsonify({'success': False, 'message': 'Title and Drive link are required.'}), 400

    pdf_entry = {
        'title': title,
        'drive_link': drive_link,
        'file_size': data.get('file_size', 'N/A'),
        'uploaded_by': session.get('user_id', 'admin'),
        'uploaded_at': datetime.now().isoformat(),
        'upload_date': datetime.now().strftime('%Y-%m-%d')
    }

    saved = db.save_pdf(pdf_entry)
    if saved:
        db.log_access(session.get('user_id'), 'admin_add_pdf')
        return jsonify({'success': True, 'message': 'PDF document added successfully!'})
    return jsonify({'success': False, 'message': 'Failed to save PDF.'}), 500

@app.route('/admin/delete-pdf/<int:pdf_id>', methods=['POST'])
@require_admin
def admin_delete_pdf(pdf_id):
    deleted = db.delete_pdf(pdf_id)
    if deleted:
        db.log_access(session.get('user_id'), 'admin_delete_pdf', pdf_id=pdf_id)
        return jsonify({'success': True, 'message': 'PDF deleted successfully.'})
    return jsonify({'success': False, 'message': 'PDF not found or could not be deleted.'}), 404

# ==================== ADMIN USER MANAGEMENT ====================

@app.route('/admin/users')
@require_admin
def admin_users():
    """Admin users management view."""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    per_page = Config.DEFAULT_PER_PAGE_USERS

    all_users = db.get_users()

    if search_query:
        q = search_query.lower()
        filtered = [
            u for u in all_users
            if q in str(u.get('username', '')).lower()
            or q in str(u.get('name', '')).lower()
            or q in str(u.get('role', '')).lower()
        ]
    else:
        filtered = all_users

    total_users = len(filtered)
    total_pages = max(1, (total_users + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start = (page - 1) * per_page
    end = start + per_page
    page_users = filtered[start:end]

    safe_users = []
    for u in page_users:
        u_copy = dict(u)
        u_copy['has_password'] = bool(u.get('password'))
        u_copy['password'] = '••••••••'
        safe_users.append(u_copy)

    return render_template(
        'admin_users.html',
        users=safe_users,
        page=page,
        total_pages=total_pages,
        total_users=total_users,
        per_page=per_page,
        search_query=search_query
    )

@app.route('/admin/search-users')
@require_admin
def admin_search_users():
    """AJAX user search endpoint with sanitized responses."""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    per_page = request.args.get('per_page', Config.DEFAULT_PER_PAGE_USERS, type=int)

    all_users = db.get_users()

    if search_query:
        q = search_query.lower()
        filtered = [
            u for u in all_users
            if q in str(u.get('username', '')).lower()
            or q in str(u.get('name', '')).lower()
            or q in str(u.get('role', '')).lower()
        ]
    else:
        filtered = all_users

    total_users = len(filtered)
    total_pages = max(1, (total_users + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start = (page - 1) * per_page
    end = start + per_page
    page_users = filtered[start:end]

    safe_users = []
    for u in page_users:
        safe_users.append({
            'id': u.get('id'),
            'username': u.get('username'),
            'name': u.get('name'),
            'role': u.get('role'),
            'created_at': u.get('created_at', ''),
            'password': '••••••••'
        })

    return jsonify({
        'success': True,
        'users': safe_users,
        'page': page,
        'total_pages': total_pages,
        'total_users': total_users,
        'per_page': per_page
    })

@app.route('/admin/add-user', methods=['POST'])
@require_admin
def admin_add_user():
    data = request.get_json(silent=True) or request.form
    username = str(data.get('username', '')).strip().upper()
    name = str(data.get('name', '')).strip()
    role = str(data.get('role', 'student')).strip().lower()
    raw_password = str(data.get('password', '')).strip()

    if not username or not raw_password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    if db.get_user(username):
        return jsonify({'success': False, 'message': f"User '{username}' already exists."}), 409

    password_to_store = raw_password
    if role == 'student' and len(raw_password) == 8 and raw_password.isdigit():
        iso_dob = AuthService.convert_dob_to_iso(raw_password)
        if iso_dob:
            password_to_store = iso_dob

    user_entry = {
        'username': username,
        'name': name or username,
        'role': role,
        'password': password_to_store,
        'created_by': session.get('user_id', 'admin'),
        'created_at': datetime.now().isoformat()
    }

    saved = db.save_user(user_entry)
    if saved:
        db.log_access(session.get('user_id'), 'admin_add_user')
        return jsonify({'success': True, 'message': f"User '{username}' created successfully."})
    return jsonify({'success': False, 'message': 'Failed to save user.'}), 500

@app.route('/admin/delete-user/<username>', methods=['POST'])
@require_admin
def admin_delete_user(username):
    if username.upper() == str(session.get('user_id', '')).upper():
        return jsonify({'success': False, 'message': 'You cannot delete your own account.'}), 400

    deleted = db.delete_user(username)
    if deleted:
        db.log_access(session.get('user_id'), 'admin_delete_user')
        return jsonify({'success': True, 'message': f"User '{username}' deleted successfully."})
    return jsonify({'success': False, 'message': 'User not found.'}), 404

# ==================== ADMIN SPREADSHEET IMPORTS & TEMPLATES ====================

@app.route('/admin/download-users-template')
@require_admin
def admin_download_users_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['username', 'name', 'password', 'role'])
    writer.writerow(['23N81A0501', 'Sample Student 1', '15082003', 'student'])
    writer.writerow(['23N81A0502', 'Sample Student 2', '2004-05-12', 'student'])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)

    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name='users_template.csv'
    )

@app.route('/admin/download-pdfs-template')
@require_admin
def admin_download_pdfs_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['title', 'drive_link', 'file_size'])
    writer.writerow(['Data Structures and Algorithms', 'https://drive.google.com/file/d/example_id/view', '4.2 MB'])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)

    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name='pdfs_template.csv'
    )

@app.route('/admin/upload-users-excel', methods=['POST'])
@require_admin
def admin_upload_users_excel():
    if 'file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('admin_users'))

    file = request.files['file']
    if not file.filename:
        flash('No file selected.', 'error')
        return redirect(url_for('admin_users'))

    filename = secure_filename(file.filename)
    try:
        if filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file)
        else:
            flash('Unsupported format. Please upload CSV or Excel files.', 'error')
            return redirect(url_for('admin_users'))

        new_users = []
        for _, row in df.iterrows():
            uname = str(row.get('username', '')).strip().upper()
            if not uname or uname == 'NAN':
                continue
            pwd = str(row.get('password', '')).strip()
            if len(pwd) == 8 and pwd.isdigit():
                iso = AuthService.convert_dob_to_iso(pwd)
                if iso:
                    pwd = iso
            new_users.append({
                'username': uname,
                'name': str(row.get('name', uname)).strip(),
                'role': str(row.get('role', 'student')).strip().lower(),
                'password': pwd,
                'created_by': session.get('user_id', 'admin')
            })

        count = db.add_users_bulk(new_users)
        db.log_access(session.get('user_id'), 'admin_bulk_user_upload')
        flash(f'Successfully imported {count} new users!', 'success')
    except Exception as e:
        logger.error(f"User bulk upload failed: {e}")
        flash(f'Import error: {str(e)}', 'error')

    return redirect(url_for('admin_users'))

@app.route('/admin/upload-pdfs-excel', methods=['POST'])
@app.route('/admin/upload-pdfs-bulk', methods=['POST'])
@require_admin
def admin_upload_pdfs_excel():
    if 'file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('admin_dashboard'))

    file = request.files['file']
    if not file.filename:
        flash('No file selected.', 'error')
        return redirect(url_for('admin_dashboard'))

    filename = secure_filename(file.filename)
    try:
        if filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file)
        else:
            flash('Unsupported format. Please upload CSV or Excel files.', 'error')
            return redirect(url_for('admin_dashboard'))

        new_pdfs = []
        for _, row in df.iterrows():
            title = str(row.get('title', '')).strip()
            link = str(row.get('drive_link', '')).strip()
            if not title or title == 'NAN' or not link or link == 'NAN':
                continue
            new_pdfs.append({
                'title': title,
                'drive_link': link,
                'file_size': str(row.get('file_size', 'N/A')),
                'uploaded_by': session.get('user_id', 'admin')
            })

        count = db.add_pdfs_bulk(new_pdfs)
        db.log_access(session.get('user_id'), 'admin_bulk_pdf_upload')
        flash(f'Successfully imported {count} new PDF documents!', 'success')
    except Exception as e:
        logger.error(f"PDF bulk upload failed: {e}")
        flash(f'Import error: {str(e)}', 'error')

    return redirect(url_for('admin_dashboard'))

# ==================== ADMIN GEOLOCATION MANAGEMENT ====================

@app.route('/admin/location')
@require_admin
def admin_location():
    boundaries = db.get_boundaries()
    return render_template('admin_location.html', boundaries=boundaries)

@app.route('/admin/get-boundaries')
@require_admin
def admin_get_boundaries():
    return jsonify(db.get_boundaries())

@app.route('/admin/save-boundary', methods=['POST'])
@require_admin
def admin_save_boundary():
    data = request.get_json(silent=True) or request.form
    name = str(data.get('name', '')).strip()
    b_type = str(data.get('type', 'circle')).strip().lower()

    if not name:
        return jsonify({'success': False, 'message': 'Boundary name is required.'}), 400

    boundary_data = {
        'name': name,
        'type': b_type,
        'created_by': session.get('user_id', 'admin')
    }

    if b_type == 'circle':
        try:
            boundary_data['latitude'] = float(data.get('latitude'))
            boundary_data['longitude'] = float(data.get('longitude'))
            boundary_data['radius_km'] = float(data.get('radius_km', 1.0))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid latitude, longitude, or radius.'}), 400

    elif b_type == 'rectangle':
        try:
            boundary_data['south'] = float(data.get('south'))
            boundary_data['north'] = float(data.get('north'))
            boundary_data['west'] = float(data.get('west'))
            boundary_data['east'] = float(data.get('east'))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid rectangle coordinate bounds.'}), 400

    elif b_type == 'polygon':
        coords = data.get('coordinates', [])
        if not coords or len(coords) < 3:
            return jsonify({'success': False, 'message': 'Polygon requires at least 3 coordinate points.'}), 400
        boundary_data['coordinates'] = coords

    saved = db.save_boundary(boundary_data)
    if saved:
        db.log_access(session.get('user_id'), 'admin_save_boundary')
        return jsonify({'success': True, 'message': 'Boundary saved successfully!'})
    return jsonify({'success': False, 'message': 'Failed to save boundary.'}), 500

@app.route('/admin/delete-boundary', methods=['POST'])
@require_admin
def admin_delete_boundary():
    data = request.get_json(silent=True) or request.form
    boundary_id = data.get('id')
    deleted = db.delete_boundary(boundary_id)
    if deleted:
        db.log_access(session.get('user_id'), 'admin_delete_boundary')
        return jsonify({'success': True, 'message': 'Boundary deleted successfully.'})
    return jsonify({'success': False, 'message': 'Boundary not found.'}), 404

# ==================== ADMIN STATISTICS & LOGS ====================

@app.route('/admin/statistics')
@require_admin
def admin_statistics():
    logs = db.get_access_logs()
    users = db.get_users()
    pdfs = db.get_pdfs()

    total_users = len(users)
    admins_count = len([u for u in users if u.get('role') == 'admin'])
    students_count = len([u for u in users if u.get('role') == 'student'])

    today_str = datetime.now().strftime('%Y-%m-%d')
    today_logs = [l for l in logs if l.get('date') == today_str]
    active_users = len(set(l.get('username') for l in logs))

    hourly_counts = {h: 0 for h in range(24)}
    for l in logs:
        hour = l.get('hour', 0)
        if isinstance(hour, int) and 0 <= hour <= 23:
            hourly_counts[hour] += 1

    location_counts = {}
    for l in logs:
        loc = l.get('location', 'Unknown')
        location_counts[loc] = location_counts.get(loc, 0) + 1

    pdf_views = {}
    for l in logs:
        if l.get('action') in ['pdf_view', 'pdf_token_requested'] and l.get('pdf_id'):
            pid = str(l.get('pdf_id'))
            pdf_views[pid] = pdf_views.get(pid, 0) + 1

    top_pdfs = []
    pdf_lookup = {str(p.get('id')): p for p in pdfs}
    for pid, count in sorted(pdf_views.items(), key=lambda x: x[1], reverse=True)[:5]:
        p = pdf_lookup.get(pid)
        if p:
            top_pdfs.append({
                'title': p.get('title'),
                'views': count
            })

    stats = {
        'total_users': total_users,
        'admins_count': admins_count,
        'students_count': students_count,
        'total_pdfs': len(pdfs),
        'active_users': active_users,
        'today_activity': len(today_logs),
        'total_logs': len(logs),
        'hourly_data': [hourly_counts[h] for h in range(24)],
        'location_labels': list(location_counts.keys())[:8],
        'location_data': list(location_counts.values())[:8],
        'top_pdfs': top_pdfs
    }

    recent_logs = sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:50]

    return render_template(
        'admin_statistics.html',
        stats=stats,
        recent_logs=recent_logs
    )

@app.route('/admin/export-statistics')
@require_admin
def export_statistics():
    logs = db.get_access_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Action', 'Location', 'PDF_ID', 'Timestamp', 'Date', 'Time'])

    for l in logs:
        writer.writerow([
            l.get('id', ''),
            l.get('username', ''),
            l.get('action', ''),
            l.get('location', ''),
            l.get('pdf_id', ''),
            l.get('timestamp', ''),
            l.get('date', ''),
            l.get('time', '')
        ])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)

    filename = f"vault_library_access_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# ==================== ADMIN SUPPORT CONTACTS ====================

@app.route('/admin/contacts')
@require_admin
def admin_contacts():
    contacts = db.get_contacts()
    sorted_contacts = sorted(
        contacts,
        key=lambda c: (0 if c.get('status') == 'pending' else 1, c.get('submitted_at', '')),
        reverse=False
    )
    return render_template('admin_contacts.html', contacts=sorted_contacts)

@app.route('/admin/update-contact-status', methods=['POST'])
@require_admin
def admin_update_contact_status():
    data = request.get_json(silent=True) or request.form
    contact_id = data.get('id')
    status = data.get('status', 'resolved')

    updated = db.update_contact_status(contact_id, status)
    if updated:
        return jsonify({'success': True, 'message': 'Status updated.'})
    return jsonify({'success': False, 'message': 'Contact not found.'}), 404

@app.route('/admin/delete-contact', methods=['POST'])
@require_admin
def admin_delete_contact():
    data = request.get_json(silent=True) or request.form
    contact_id = data.get('id')

    deleted = db.delete_contact(contact_id)
    if deleted:
        return jsonify({'success': True, 'message': 'Message deleted.'})
    return jsonify({'success': False, 'message': 'Contact not found.'}), 404

# ==================== ERROR HANDLERS ====================

@app.errorhandler(400)
def handle_bad_request(e):
    return render_template('error.html', error_code=400, error_title='Bad Request', error_message='The server could not understand the request.'), 400

@app.errorhandler(401)
def handle_unauthorized(e):
    return render_template('error.html', error_code=401, error_title='Authentication Required', error_message='Please log in to access this area.'), 401

@app.errorhandler(403)
def handle_forbidden(e):
    return render_template('error.html', error_code=403, error_title='Access Forbidden', error_message='You do not have permission to access this resource or you are outside the campus boundary.'), 403

@app.errorhandler(404)
def handle_not_found(e):
    return render_template('error.html', error_code=404, error_title='Page Not Found', error_message='The requested page or document could not be found.'), 404

@app.errorhandler(500)
def handle_server_error(e):
    logger.error(f"Internal server error: {e}")
    return render_template('error.html', error_code=500, error_title='Internal Server Error', error_message='A server error occurred. Our engineers have been alerted.'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
