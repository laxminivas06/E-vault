from flask_mail import Mail, Message
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, jsonify, flash
import json
import os
import pandas as pd
from math import radians, sin, cos, sqrt, atan2
from datetime import datetime, timedelta
from config import Config
from functools import wraps
from flask import send_file
import io
from io import BytesIO
import logging
import re
import pandas as pd
import numpy as np
import time
import traceback

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'smartnlightinnovations@gmail.com'
app.config['MAIL_PASSWORD'] = 'raja rbot qghf ywig'
app.config['MAIL_DEFAULT_SENDER'] = 'smartnlightinnovations@gmail.com'
app.config['MAIL_DEBUG'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize Flask-Mail
mail = Mail(app)

# Location verification settings
LOCATION_CHECK_INTERVAL = 150  # 2.5 minutes in seconds

def require_location_verification(f):
    """Simplified decorator for location verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip location check for static files and specific routes
        if request.endpoint in ['static', 'welcome', 'location_check', 'check_boundary', 'logout']:
            return f(*args, **kwargs)
        
        # Check if location needs verification
        needs_verification = needs_location_verification()
        
        if needs_verification:
            # Store intended destination
            session['intended_url'] = request.url
            return redirect(url_for('location_check'))
        
        return f(*args, **kwargs)
    
    return decorated_function

def needs_location_verification():
    """Check if location verification is needed"""
    # If location is not verified at all
    if not session.get('location_verified'):
        return True
    
    # Check if verification has expired
    last_check = session.get('last_location_check')
    if last_check:
        try:
            last_check_time = datetime.fromisoformat(last_check)
            time_since_check = (datetime.now() - last_check_time).total_seconds()
            if time_since_check > LOCATION_CHECK_INTERVAL:
                return True
        except Exception as e:
            logger.error(f"Error checking last location time: {str(e)}")
            return True
    
    return False

def update_location_verification(lat, lon, location_name):
    """Update session with new location verification"""
    session['location_verified'] = True
    session['verified_location'] = location_name
    session['last_location_check'] = datetime.now().isoformat()
    session['current_latitude'] = lat
    session['current_longitude'] = lon
    session['needs_location_verification'] = False

# ==================== HELPER FUNCTIONS ====================
def load_json_data(filename):
    """Load JSON data from file with better error handling"""
    filepath = f'data/{filename}'
    try:
        os.makedirs('data', exist_ok=True)
        
        if not os.path.exists(filepath):
            logger.info(f"File {filepath} does not exist, returning empty list")
            return []
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                logger.info(f"File {filepath} is empty, returning empty list")
                return []
            data = json.loads(content)
            return data
            
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {filename}: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Error loading {filename}: {str(e)}")
        return []

def save_json_data(filename, data):
    """Save data to JSON file with better error handling"""
    filepath = f'data/{filename}'
    try:
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return True
        
    except Exception as e:
        logger.error(f"Error saving to {filename}: {str(e)}")
        raise

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates in kilometers"""
    R = 6371  # Earth's radius in km
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c

def is_location_allowed(user_lat, user_lon):
    """Check if user is within any allowed location with multiple boundary types"""
    boundaries = load_json_data('boundaries.json')
    
    for boundary in boundaries:
        if boundary['type'] == 'circle':
            try:
                radius_km = float(boundary['radius_km'])
            except (ValueError, TypeError):
                logger.warning(f"Invalid radius_km value in boundary {boundary.get('name', 'unknown')}: {boundary.get('radius_km')}")
                continue
                
            distance = calculate_distance(
                user_lat, user_lon,
                boundary['latitude'], boundary['longitude']
            )
            if distance <= radius_km:
                return True, boundary['name']
        
        elif boundary['type'] == 'rectangle':
            if (boundary['south'] <= user_lat <= boundary['north'] and 
                boundary['west'] <= user_lon <= boundary['east']):
                return True, boundary['name']
        
        elif boundary['type'] == 'polygon':
            if is_point_in_polygon(user_lat, user_lon, boundary['coordinates']):
                return True, boundary['name']
    
    return False, None
# Add these helper functions for statistics
def track_user_access(username, action, location=None, pdf_id=None):
    """Track user access for statistics"""
    try:
        access_logs = load_json_data('access_logs.json')
        
        log_entry = {
            'id': len(access_logs) + 1,
            'username': username,
            'action': action,
            'location': location,
            'pdf_id': pdf_id,
            'timestamp': datetime.now().isoformat(),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'time': datetime.now().strftime('%H:%M:%S'),
            'hour': datetime.now().hour
        }
        
        access_logs.append(log_entry)
        
        # Keep only last 30 days of logs to prevent file from growing too large
        thirty_days_ago = datetime.now() - timedelta(days=30)
        access_logs = [log for log in access_logs 
                      if datetime.fromisoformat(log['timestamp']) > thirty_days_ago]
        
        save_json_data('access_logs.json', access_logs)
        
    except Exception as e:
        logger.error(f"Error tracking user access: {str(e)}")

@app.route('/admin/export-statistics')
@require_location_verification
def export_statistics():
    """Export statistics to Excel format"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Get all data
        stats = get_user_statistics()
        access_logs = load_json_data('access_logs.json')
        users = load_json_data('users.json')
        pdfs = load_json_data('pdfs.json')
        
        # Create Excel file in memory
        output = BytesIO()
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Summary Sheet
            summary_data = {
                'Metric': [
                    'Total Users', 'Active Users', 'Today Activity', 
                    'Average Session Duration (min)', 'Total Administrators', 
                    'Total Students', 'Total PDFs', 'Total Sessions Tracked'
                ],
                'Value': [
                    stats.get('total_users', 0),
                    stats.get('total_active_users', 0),
                    stats.get('today_activity', 0),
                    stats.get('avg_session_duration', 0),
                    stats.get('total_admins', 0),
                    stats.get('total_students', 0),
                    stats.get('total_pdfs', 0),
                    stats.get('total_sessions_tracked', 0)
                ]
            }
            df_summary = pd.DataFrame(summary_data)
            df_summary.to_excel(writer, sheet_name='Summary', index=False)
            
            # Activity Logs Sheet
            if access_logs:
                df_activity = pd.DataFrame(access_logs)
                # Convert timestamp to readable format
                if 'timestamp' in df_activity.columns:
                    df_activity['timestamp'] = pd.to_datetime(df_activity['timestamp'])
                    df_activity['timestamp'] = df_activity['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_activity.to_excel(writer, sheet_name='Activity Logs', index=False)
            
            # Users Sheet
            if users:
                df_users = pd.DataFrame(users)
                # Remove sensitive information
                if 'password' in df_users.columns:
                    df_users = df_users.drop('password', axis=1)
                df_users.to_excel(writer, sheet_name='Users', index=False)
            
            # Location Statistics Sheet
            location_stats = stats.get('location_stats', {})
            if location_stats:
                df_locations = pd.DataFrame(list(location_stats.items()), columns=['Location', 'Access Count'])
                df_locations = df_locations.sort_values('Access Count', ascending=False)
                df_locations.to_excel(writer, sheet_name='Locations', index=False)
            
            # Hourly Usage Sheet
            hourly_usage = stats.get('hourly_usage', {})
            if hourly_usage:
                df_hourly = pd.DataFrame(list(hourly_usage.items()), columns=['Hour', 'Access Count'])
                df_hourly = df_hourly.sort_values('Hour')
                df_hourly.to_excel(writer, sheet_name='Hourly Usage', index=False)
        
        output.seek(0)
        
        return send_file(
            output,
            as_attachment=True,
            download_name=f'statistics_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        logger.error(f"Error exporting statistics: {str(e)}")
        flash('Error exporting statistics', 'error')
        return redirect(url_for('admin_statistics'))


@app.route('/track-pdf-view', methods=['POST'])
@require_location_verification
def track_pdf_view():
    """Track when a user views a PDF"""
    if not session.get('user_id'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.get_json()
    pdf_id = data.get('pdf_id')
    pdf_title = data.get('pdf_title')
    
    if not pdf_id:
        return jsonify({'success': False, 'message': 'PDF ID required'}), 400
    
    try:
        # Convert pdf_id to integer to ensure consistency
        pdf_id = int(pdf_id)
        
        # Verify PDF exists
        pdfs = load_json_data('pdfs.json')
        pdf_exists = any(pdf['id'] == pdf_id for pdf in pdfs)
        
        if not pdf_exists:
            logger.warning(f"PDF ID {pdf_id} not found in database")
            return jsonify({'success': False, 'message': 'PDF not found'}), 404
        
        # Track PDF view with location
        current_location = session.get('verified_location', 'Unknown')
        track_user_access(session['user_id'], 'pdf_view', current_location, pdf_id)
        
        # Update session counter for user stats
        session['documents_viewed'] = session.get('documents_viewed', 0) + 1
        
        logger.info(f"User {session['user_id']} viewed PDF {pdf_id} ({pdf_title}) from {current_location}")
        
        return jsonify({'success': True, 'message': 'PDF view tracked'})
    
    except ValueError:
        logger.error(f"Invalid PDF ID format: {pdf_id}")
        return jsonify({'success': False, 'message': 'Invalid PDF ID format'}), 400
    except Exception as e:
        logger.error(f"Error tracking PDF view: {str(e)}")
        return jsonify({'success': False, 'message': 'Error tracking PDF view'}), 500
    
# Update the get_user_statistics function to handle PDF IDs properly
def get_user_statistics():
    """Get comprehensive user statistics"""
    try:
        users = load_json_data('users.json')
        access_logs = load_json_data('access_logs.json')
        pdfs = load_json_data('pdfs.json')
        
        # Basic counts
        total_users = len(users)
        total_admins = len([u for u in users if u.get('role') == 'admin'])
        total_students = len([u for u in users if u.get('role') == 'student'])
        total_pdfs = len(pdfs)
        
        # User activity analysis
        active_users = set(log['username'] for log in access_logs)
        total_active_users = len(active_users)
        
        # Time-based analysis
        today = datetime.now().strftime('%Y-%m-%d')
        today_logs = [log for log in access_logs if log['date'] == today]
        
        # Location analysis
        location_logs = [log for log in access_logs if log.get('location')]
        location_stats = {}
        for log in location_logs:
            location = log['location']
            location_stats[location] = location_stats.get(location, 0) + 1
        
        # Hourly usage pattern
        hourly_usage = {}
        for log in access_logs:
            hour = log.get('hour', 0)
            hourly_usage[hour] = hourly_usage.get(hour, 0) + 1
        
        # PDF access statistics - FIXED: Ensure PDF IDs are properly handled
        pdf_access = {}
        for log in access_logs:
            if log.get('pdf_id'):
                # Convert to string for consistency, as IDs might be stored as strings or integers
                pdf_id = str(log['pdf_id'])
                pdf_access[pdf_id] = pdf_access.get(pdf_id, 0) + 1
        
        # User session analysis
        user_sessions = {}
        for log in access_logs:
            username = log['username']
            if username not in user_sessions:
                user_sessions[username] = []
            user_sessions[username].append(log['timestamp'])
        
        # Calculate average session duration (simplified)
        session_durations = []
        for username, timestamps in user_sessions.items():
            if len(timestamps) > 1:
                timestamps.sort()
                # Simple duration calculation (first to last access)
                first_access = datetime.fromisoformat(timestamps[0])
                last_access = datetime.fromisoformat(timestamps[-1])
                duration = (last_access - first_access).total_seconds() / 60  # in minutes
                session_durations.append(duration)
        
        avg_session_duration = sum(session_durations) / len(session_durations) if session_durations else 0
        
        # Calculate day-wise average session duration
        today_sessions = {}
        for log in today_logs:
            username = log['username']
            if username not in today_sessions:
                today_sessions[username] = []
            today_sessions[username].append(log['timestamp'])
        
        today_durations = []
        for username, timestamps in today_sessions.items():
            if len(timestamps) > 1:
                timestamps.sort()
                first_access = datetime.fromisoformat(timestamps[0])
                last_access = datetime.fromisoformat(timestamps[-1])
                duration = (last_access - first_access).total_seconds() / 60
                today_durations.append(duration)
        
        day_avg_session_duration = sum(today_durations) / len(today_durations) if today_durations else 0
        
        stats = {
            'total_users': total_users,
            'total_admins': total_admins,
            'total_students': total_students,
            'total_pdfs': total_pdfs,
            'total_active_users': total_active_users,
            'today_activity': len(today_logs),
            'location_stats': location_stats,
            'hourly_usage': dict(sorted(hourly_usage.items())),
            'pdf_access': pdf_access,
            'avg_session_duration': round(avg_session_duration, 2),
            'day_avg_session_duration': round(day_avg_session_duration, 2),
            'total_sessions_tracked': len(access_logs)
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error generating statistics: {str(e)}")
        return {}

# Update the admin_statistics route to handle PDF IDs properly
@app.route('/admin/statistics')
@require_location_verification
def admin_statistics():
    """Admin statistics page with comprehensive user analytics"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get overall statistics
    stats = get_user_statistics()
    
    # Get user list for detailed views
    users = load_json_data('users.json')
    
    # Get recent activity (last 50 logs)
    access_logs = load_json_data('access_logs.json')
    recent_activity = sorted(access_logs, key=lambda x: x['timestamp'], reverse=True)[:50]
    
    # Get top PDFs - FIXED: Handle PDF ID conversion properly
    pdfs = load_json_data('pdfs.json')
    pdf_access_stats = stats.get('pdf_access', {})
    top_pdfs = []
    
    for pdf_id_str, count in pdf_access_stats.items():
        try:
            # Convert back to integer for comparison
            pdf_id = int(pdf_id_str)
            pdf_info = next((p for p in pdfs if p['id'] == pdf_id), None)
            if pdf_info:
                top_pdfs.append({
                    'title': pdf_info['title'],
                    'access_count': count,
                    'id': pdf_id
                })
        except (ValueError, TypeError):
            logger.warning(f"Invalid PDF ID in access stats: {pdf_id_str}")
            continue
    
    top_pdfs.sort(key=lambda x: x['access_count'], reverse=True)
    
    return render_template('admin_statistics.html',
                         stats=stats,
                         users=users,
                         recent_activity=recent_activity,
                         top_pdfs=top_pdfs[:10],
                         username=session.get('user_id'),
                         location=session.get('verified_location'),
                         format_date=format_date)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page for user feedback and queries - no location verification required"""
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        message = request.form.get('message', '').strip()
        message_type = request.form.get('message_type', 'general').strip()
        
        # Basic validation
        if not name or not email or not message:
            flash('Please fill in all required fields (Name, Email, Message)', 'error')
            return render_template('contact.html',
                                 username=session.get('user_id'),
                                 location=session.get('verified_location'))
        
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Please enter a valid email address', 'error')
            return render_template('contact.html',
                                 username=session.get('user_id'),
                                 location=session.get('verified_location'))
        
        # Validate contact number if provided
        if contact_number and not re.match(r'^[\d\s\+\-\(\)]{10,15}$', contact_number):
            flash('Please enter a valid contact number', 'error')
            return render_template('contact.html',
                                 username=session.get('user_id'),
                                 location=session.get('verified_location'))
        
        try:
            # Load existing contacts
            contacts = load_json_data('contacts.json')
            
            # Create new contact entry
            new_contact = {
                'id': len(contacts) + 1,
                'name': name,
                'email': email,
                'contact_number': contact_number,
                'message_type': message_type,
                'message': message,
                'submitted_by': session.get('user_id', 'guest'),
                'submitted_at': datetime.now().isoformat(),
                'submitted_date': datetime.now().strftime('%Y-%m-%d'),
                'status': 'new',
                'location': session.get('verified_location', 'Not verified')
            }
            
            # Save to contacts.json
            contacts.append(new_contact)
            save_json_data('contacts.json', contacts)
            
            # Send thank you email to user
            try:
                send_thank_you_email(name, email, message_type)
            except Exception as email_error:
                logger.error(f"Failed to send thank you email: {str(email_error)}")
                # Don't fail the entire submission if email fails
            
            # Track contact submission if user is logged in
            if session.get('user_id'):
                track_user_access(session['user_id'], 'contact_submission', 
                                session.get('verified_location', 'Not verified'))
            
            logger.info(f"New contact form submitted by {name} ({email})")
            flash('Thank you for your message! We will get back to you soon. A confirmation email has been sent.', 'success')
            
            return redirect(url_for('contact'))
            
        except Exception as e:
            logger.error(f"Error saving contact form: {str(e)}")
            flash('Sorry, there was an error submitting your message. Please try again.', 'error')
    
    return render_template('contact.html',
                         username=session.get('user_id'),
                         location=session.get('verified_location'))

def send_thank_you_email(name, email, message_type):
    """Send thank you email to user after contact form submission"""
    try:
        subject = f"Thank you for contacting E-Vault - {message_type.title()} Query"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #2E86AB 0%, #1B5E7A 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>E-Vault System</h1>
                    <p>Sphoorthy Engineering College</p>
                </div>
                <div class="content">
                    <h2>Thank You, {name}!</h2>
                    <p>We have received your {message_type} query and appreciate you reaching out to us.</p>
                    <p>Our team will review your message and get back to you as soon as possible.</p>
                    
                    <div style="background: white; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #2E86AB;">
                        <p><strong>Query Type:</strong> {message_type.title()}</p>
                        <p><strong>Submitted On:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                    </div>
                    
                    <p>If you have any urgent concerns, please feel free to contact us directly.</p>
                    
                    <p>Best regards,<br>
                    <strong>E-Vault Support Team</strong><br>
                    Sphoorthy Engineering College</p>
                </div>
                <div class="footer">
                    <p>This is an automated email. Please do not reply to this message.</p>
                    <p>&copy; {datetime.now().year} Sphoorthy Engineering College - E-Vault. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create message
        msg = Message(
            subject=subject,
            recipients=[email],
            html=html_body
        )
        
        # Send email
        mail.send(msg)
        logger.info(f"Thank you email sent to {email}")
        
    except Exception as e:
        logger.error(f"Error sending thank you email to {email}: {str(e)}")
        raise
    

@app.route('/admin/contacts')
@require_location_verification
def admin_contacts():
    """Admin page to view contact submissions"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status_filter = request.args.get('status', 'all')
    
    contacts = load_json_data('contacts.json')
    
    # Apply status filter
    if status_filter != 'all':
        contacts = [contact for contact in contacts if contact.get('status') == status_filter]
    
    # Sort by submission date (newest first)
    contacts.sort(key=lambda x: x.get('submitted_at', ''), reverse=True)
    
    total_contacts = len(contacts)
    total_pages = (total_contacts + per_page - 1) // per_page
    
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    paginated_contacts = contacts[start_idx:end_idx]
    
    # Statistics
    all_contacts = load_json_data('contacts.json')
    contact_stats = {
        'total': len(all_contacts),
        'new': len([c for c in all_contacts if c.get('status') == 'new']),
        'read': len([c for c in all_contacts if c.get('status') == 'read']),
        'replied': len([c for c in all_contacts if c.get('status') == 'replied'])
    }
    
    return render_template('admin_contacts.html',
                         contacts=paginated_contacts,
                         username=session.get('user_id'),
                         location=session.get('verified_location'),
                         format_date=format_date,
                         contact_stats=contact_stats,
                         status_filter=status_filter,
                         page=page,
                         per_page=per_page,
                         total_contacts=total_contacts,
                         total_pages=total_pages)

@app.route('/admin/update-contact-status', methods=['POST'])
@require_location_verification
def update_contact_status():
    """Update contact message status"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    data = request.get_json()
    contact_id = data.get('contact_id')
    new_status = data.get('status')
    
    if not contact_id or not new_status:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    if new_status not in ['new', 'read', 'replied']:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    
    try:
        contacts = load_json_data('contacts.json')
        
        for contact in contacts:
            if contact['id'] == contact_id:
                contact['status'] = new_status
                contact['updated_at'] = datetime.now().isoformat()
                contact['updated_by'] = session.get('user_id')
                break
        
        save_json_data('contacts.json', contacts)
        
        return jsonify({'success': True, 'message': 'Status updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating contact status: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating status'}), 500

@app.route('/admin/delete-contact', methods=['POST'])
@require_location_verification
def delete_contact():
    """Delete contact message"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    data = request.get_json()
    contact_id = data.get('contact_id')
    
    if not contact_id:
        return jsonify({'success': False, 'message': 'Contact ID required'}), 400
    
    try:
        contacts = load_json_data('contacts.json')
        initial_count = len(contacts)
        contacts = [contact for contact in contacts if contact['id'] != contact_id]
        
        if len(contacts) == initial_count:
            return jsonify({'success': False, 'message': 'Contact not found'}), 404
        
        save_json_data('contacts.json', contacts)
        
        return jsonify({'success': True, 'message': 'Contact deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting contact: {str(e)}")
        return jsonify({'success': False, 'message': 'Error deleting contact'}), 500
    


def get_user_detailed_stats(username):
    """Get detailed statistics for a specific user"""
    try:
        access_logs = load_json_data('access_logs.json')
        user_logs = [log for log in access_logs if log['username'] == username]
        
        if not user_logs:
            return None
        
        # Sort logs by timestamp
        user_logs.sort(key=lambda x: x['timestamp'])
        
        # Basic info
        first_access = user_logs[0]['timestamp'][:10]
        last_access = user_logs[-1]['timestamp'][:10]
        total_logins = len([log for log in user_logs if log['action'] == 'login'])
        
        # Location usage
        locations = {}
        for log in user_logs:
            location = log.get('location', 'Unknown')
            locations[location] = locations.get(location, 0) + 1
        
        # Preferred access times
        access_hours = {}
        for log in user_logs:
            hour = log.get('hour', 0)
            access_hours[hour] = access_hours.get(hour, 0) + 1
        
        # PDF access
        pdf_access = {}
        for log in user_logs:
            if log.get('pdf_id'):
                pdf_id = log['pdf_id']
                pdf_access[pdf_id] = pdf_access.get(pdf_id, 0) + 1
        
        user_stats = {
            'username': username,
            'first_access': first_access,
            'last_access': last_access,
            'total_sessions': len(user_logs),
            'total_logins': total_logins,
            'locations': locations,
            'access_hours': dict(sorted(access_hours.items())),
            'pdf_access_count': len(pdf_access),
            'preferred_locations': sorted(locations.items(), key=lambda x: x[1], reverse=True)[:3],
            'preferred_hours': sorted(access_hours.items(), key=lambda x: x[1], reverse=True)[:3]
        }
        
        return user_stats
        
    except Exception as e:
        logger.error(f"Error getting user detailed stats: {str(e)}")
        return None
    
def update_location_verification(lat, lon, location_name):
    """Update session with new location verification"""
    session['location_verified'] = True
    session['verified_location'] = location_name
    session['last_location_check'] = datetime.now().isoformat()
    session['current_latitude'] = lat
    session['current_longitude'] = lon
    session['needs_location_verification'] = False
    
    # Track location access if user is logged in
    if session.get('user_id'):
        track_user_access(session['user_id'], 'location_verify', location_name)



def is_point_in_polygon(lat, lon, polygon):
    """Check if a point is inside a polygon using ray casting algorithm"""
    n = len(polygon)
    inside = False
    
    j = n - 1
    for i in range(n):
        if (((polygon[i][1] > lon) != (polygon[j][1] > lon)) and
            (lat < (polygon[j][0] - polygon[i][0]) * (lon - polygon[i][1]) / 
             (polygon[j][1] - polygon[i][1]) + polygon[i][0])):
            inside = not inside
        j = i
    
    return inside

def validate_student_credentials(username, password):
    """Validate student credentials (rollno as username, DOB as password)"""
    users = load_json_data('users.json')
    user = next((u for u in users if u['username'] == username and u['role'] == 'student'), None)
    
    if user and user['password'] == password:
        return True, user
    return False, None

def validate_admin_credentials(username, password):
    """Validate admin credentials"""
    users = load_json_data('users.json')
    user = next((u for u in users if u['username'] == username and u['role'] == 'admin'), None)
    
    if user and user['password'] == password:
        return True, user
    return False, None

def is_valid_rollno(rollno):
    """Check if roll number is valid (alphanumeric, 10 characters)"""
    return bool(re.match(r'^[A-Za-z0-9]{10}$', rollno))

def is_valid_dob(dob):
    """Strict DOB validation (DDMMYYYY format - exactly 8 digits, no separators)"""
    try:
        if len(dob) != 8 or not dob.isdigit():
            return False
        
        day = int(dob[:2])
        month = int(dob[2:4])
        year = int(dob[4:8])
        
        if month < 1 or month > 12:
            return False
        
        if day < 1 or day > 31:
            return False
        
        if year < 1900 or year > datetime.now().year:
            return False
        
        if month in [4, 6, 9, 11] and day > 30:
            return False
        
        if month == 2:
            if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                if day > 29:
                    return False
            else:
                if day > 28:
                    return False
        
        datetime(year, month, day)
        return True
    except (ValueError, IndexError):
        return False

def convert_to_iso_date(dob_string):
    """Convert DDMMYYYY to ISO format (YYYY-MM-DD) for storage"""
    try:
        if len(dob_string) == 8 and dob_string.isdigit():
            day = int(dob_string[:2])
            month = int(dob_string[2:4])
            year = int(dob_string[4:8])
            date_obj = datetime(year, month, day)
            return date_obj.strftime('%Y-%m-%d')
        return dob_string
    except ValueError:
        return dob_string

def format_date(date_string):
    """Format date string for display"""
    try:
        if isinstance(date_string, str):
            return date_string[:10]
        return "Unknown"
    except:
        return "Unknown"

def process_excel_users(file):
    """Process Excel file for bulk user upload"""
    try:
        df = pd.read_excel(file)
        required_columns = ['username', 'password', 'role', 'name']
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return False, f"Missing columns: {', '.join(missing_columns)}"
        
        users = load_json_data('users.json')
        new_users = []
        errors = []
        
        for index, row in df.iterrows():
            username = str(row['username']).strip()
            password = str(row['password']).strip()
            role = str(row['role']).strip().lower()
            name = str(row['name']).strip()
            
            if role not in ['admin', 'student']:
                errors.append(f"Row {index+2}: Invalid role '{role}'. Must be 'admin' or 'student'")
                continue
            
            if role == 'student':
                if not is_valid_rollno(username):
                    errors.append(f"Row {index+2}: Invalid roll number '{username}'. Must be exactly 10 alphanumeric characters")
                    continue
                
                clean_password = ''.join(filter(str.isdigit, password))
                if not is_valid_dob(clean_password):
                    errors.append(f"Row {index+2}: Invalid date of birth '{password}'. Use DDMMYYYY format (8 digits)")
                    continue
                
                password = convert_to_iso_date(clean_password)
            
            if any(user['username'] == username for user in users):
                errors.append(f"Row {index+2}: Username '{username}' already exists")
                continue
            
            new_user = {
                'id': len(users) + len(new_users) + 1,
                'username': username,
                'password': password,
                'role': role,
                'name': name,
                'created_at': datetime.now().isoformat(),
                'created_by': session.get('user_id', 'admin')
            }
            new_users.append(new_user)
        
        if errors:
            return False, ";\n".join(errors)
        
        users.extend(new_users)
        save_json_data('users.json', users)
        
        return True, f"Successfully added {len(new_users)} users"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return False, f"Error processing Excel file: {str(e)}"

def process_excel_pdfs(file):
    """Process Excel file for bulk PDF upload"""
    try:
        df = pd.read_excel(file)
        required_columns = ['title', 'drive_link']
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return False, f"Missing columns: {', '.join(missing_columns)}"
        
        pdfs = load_json_data('pdfs.json')
        new_pdfs = []
        errors = []
        
        for index, row in df.iterrows():
            title = str(row['title']).strip()
            drive_link = str(row['drive_link']).strip()
            
            if not title:
                errors.append(f"Row {index+2}: Title is required")
                continue
            
            if not drive_link.startswith(('http://', 'https://')):
                errors.append(f"Row {index+2}: Invalid drive link")
                continue
            
            file_size = str(row['file_size']).strip() if 'file_size' in df.columns and pd.notna(row.get('file_size')) else 'N/A'
            
            new_pdf = {
                'id': len(pdfs) + len(new_pdfs) + 1,
                'title': title,
                'drive_link': drive_link,
                'file_size': file_size,
                'uploaded_by': session.get('user_id', 'admin'),
                'uploaded_at': datetime.now().isoformat(),
                'upload_date': datetime.now().strftime('%Y-%m-%d')
            }
            new_pdfs.append(new_pdf)
        
        if errors:
            return False, ";\n".join(errors)
        
        pdfs.extend(new_pdfs)
        save_json_data('pdfs.json', pdfs)
        
        return True, f"Successfully added {len(new_pdfs)} PDFs"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return False, f"Error processing Excel file: {str(e)}"

# ==================== ROUTES ====================

@app.route('/')
def welcome():
    """Welcome page"""
    location_keys = ['location_verified', 'verified_location', 'last_location_check', 
                    'current_latitude', 'current_longitude', 'needs_location_verification',
                    'intended_url']
    for key in location_keys:
        session.pop(key, None)
    
    logger.info("Welcome page accessed")
    
    users = load_json_data('users.json')
    pdfs = load_json_data('pdfs.json')
    
    user_stats = {
        'total_users': len(users),
        'total_pdfs': len(pdfs)
    }
    
    return render_template('welcome.html', user_stats=user_stats)

@app.route('/location-check', methods=['GET', 'POST'])
def location_check():
    """Location verification endpoint"""
    if not needs_location_verification() and session.get('location_verified'):
        intended_url = session.get('intended_url', url_for('login'))
        session.pop('intended_url', None)
        return redirect(intended_url)
    
    if request.method == 'POST':
        data = request.get_json()
        user_lat = data.get('latitude')
        user_lon = data.get('longitude')
        
        if user_lat is None or user_lon is None:
            return jsonify({
                'success': False, 
                'message': 'Location data not provided.'
            })
        
        try:
            user_lat = float(user_lat)
            user_lon = float(user_lon)
        except (TypeError, ValueError):
            return jsonify({
                'success': False, 
                'message': 'Invalid location data.'
            })
        
        allowed, location_name = is_location_allowed(user_lat, user_lon)
        
        if allowed:
            update_location_verification(user_lat, user_lon, location_name)
            
            logger.info(f"Location verified: {location_name}")
            
            intended_url = session.get('intended_url')
            if intended_url:
                session.pop('intended_url', None)
                redirect_url = intended_url
            else:
                if session.get('user_id'):
                    redirect_url = url_for('dashboard')
                else:
                    redirect_url = url_for('login')
            
            return jsonify({
                'success': True, 
                'location': location_name,
                'redirect_url': redirect_url
            })
        else:
            logger.warning(f"Location denied: {user_lat}, {user_lon}")
            session.clear()
            return jsonify({
                'success': False, 
                'message': 'Access Denied: You are outside the allowed area.'
            })
    
    return render_template('location_check.html')

@app.route('/login', methods=['GET', 'POST'])
@require_location_verification
def login():
    """Login page with location verification"""
    direct_admin = session.pop('direct_admin', False)
    direct_user = session.pop('direct_user', False)
    
    direct_admin = bool(direct_admin)
    direct_user = bool(direct_user)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill all fields', 'error')
            return render_template('login.html', 
                                 direct_admin=direct_admin, 
                                 direct_user=direct_user)
        
        # Try admin login first
        is_valid_admin, admin_user = validate_admin_credentials(username, password)
        if is_valid_admin and admin_user:
            session['user_id'] = admin_user['username']
            session['user_role'] = admin_user['role']
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            
            # Track admin login with location
            current_location = session.get('verified_location', 'Unknown')
            track_user_access(admin_user['username'], 'login', current_location)
            
            logger.info(f"Admin logged in: {admin_user['username']} from {current_location}")
            flash(f'Welcome Administrator {admin_user["username"]}!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        # Try student login
        if is_valid_rollno(username):
            clean_password = ''.join(filter(str.isdigit, password))
            
            if any(not char.isdigit() for char in password):
                flash('Date of birth should contain only digits (DDMMYYYY format). No special characters or spaces allowed.', 'error')
                return render_template('login.html', 
                                     direct_admin=direct_admin, 
                                     direct_user=direct_user)
            
            if not is_valid_dob(clean_password):
                flash('Invalid date of birth. Please use DDMMYYYY format (8 digits only). Example: 15082002 for 15th August 2002.', 'error')
                return render_template('login.html', 
                                     direct_admin=direct_admin, 
                                     direct_user=direct_user)
            
            iso_password = convert_to_iso_date(clean_password)
            is_valid_student, student_user = validate_student_credentials(username, iso_password)
            
            if is_valid_student and student_user:
                session['user_id'] = student_user['username']
                session['user_role'] = student_user['role']
                session['login_time'] = datetime.now().isoformat()
                session.permanent = True
                
                # Track student login with location
                current_location = session.get('verified_location', 'Unknown')
                track_user_access(student_user['username'], 'login', current_location)
                
                logger.info(f"Student logged in: {student_user['username']} from {current_location}")
                flash(f'Welcome {student_user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
        
        # Track failed login attempt
        if username:
            track_user_access(username, 'failed_login', session.get('verified_location', 'Unknown'))
        
        logger.warning(f"Failed login attempt for username: {username}")
        flash('Invalid credentials or user not found', 'error')
    
    return render_template('login.html', 
                         direct_admin=direct_admin, 
                         direct_user=direct_user)

@app.route('/init-access-logs')
def init_access_logs():
    """Initialize access logs file (for first-time setup)"""
    try:
        save_json_data('access_logs.json', [])
        return jsonify({'success': True, 'message': 'Access logs initialized'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    
@app.route('/dashboard')
@require_location_verification
def dashboard():
    """PDF dashboard with location verification"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    pdfs = load_json_data('pdfs.json')
    users = load_json_data('users.json')
    
    current_user = next((u for u in users if u['username'] == session.get('user_id')), None)
    search_query = request.args.get('search', '')
    
    filtered_pdfs = pdfs
    if search_query:
        filtered_pdfs = [pdf for pdf in filtered_pdfs 
                        if search_query.lower() in pdf['title'].lower() 
                        or any(search_query.lower() in tag.lower() for tag in pdf.get('tags', []))]
    
    total_pdfs = len(filtered_pdfs)
    total_pages = (total_pdfs + per_page - 1) // per_page if total_pdfs > 0 else 1
    
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_pdfs = filtered_pdfs[start_idx:end_idx]
    
    # Track dashboard access
    current_location = session.get('verified_location', 'Unknown')
    track_user_access(session['user_id'], 'dashboard_access', current_location)
    
    # Handle AJAX requests for pagination
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'pdfs_html': render_template_string('''
                {% for pdf in pdfs %}
                <div class="pdf-card" data-pdf-id="{{ pdf.id }}">
                    <div class="pdf-header">
                        <div class="pdf-icon">
                            <i class="fas fa-file-pdf"></i>
                        </div>
                        <div class="pdf-info">
                            <h3 class="pdf-title">{{ pdf.title }}</h3>
                            <div class="pdf-meta">
                                <span><i class="fas fa-calendar"></i> {{ pdf.upload_date }}</span>
                            </div>
                            {% if pdf.tags %}
                            <div class="pdf-tags">
                                {% for tag in pdf.tags %}
                                <span class="pdf-tag">{{ tag }}</span>
                                {% endfor %}
                            </div>
                            {% endif %}
                        </div>
                    </div>
                    <div class="pdf-actions">
                        <button class="btn btn-primary" onclick="openPdfViewer('{{ pdf.id }}', '{{ pdf.title }}')">
                            <i class="fas fa-eye"></i> View PDF
                        </button>
                    </div>
                </div>
                {% else %}
                <div class="no-results">
                    <i class="fas fa-search"></i>
                    <h3>No documents found</h3>
                    <p>Try adjusting your search terms or filters</p>
                    {% if user_role == 'admin' %}
                    <a href="{{ url_for('admin_dashboard') }}" class="btn btn-primary" style="margin-top: 15px;">
                        <i class="fas fa-plus"></i> Add PDFs in Admin Panel
                    </a>
                    {% endif %}
                </div>
                {% endfor %}
            ''', pdfs=paginated_pdfs, user_role=session.get('user_role')),
            'pagination_html': render_template_string('''
                {% if total_pages > 1 %}
                <div class="pagination-container">
                    <div class="pagination-info">
                        Showing {{ ((page - 1) * per_page) + 1 }} to {{ [page * per_page, total_pdfs]|min }} of {{ total_pdfs }} PDFs
                    </div>
                    <nav aria-label="PDF pagination">
                        <ul class="pagination">
                            <!-- Previous Page -->
                            {% if page > 1 %}
                            <li class="page-item">
                                <a class="page-link" href="#" data-page="{{ page-1 }}" aria-label="Previous">
                                    <i class="fas fa-chevron-left"></i>
                                </a>
                            </li>
                            {% else %}
                            <li class="page-item disabled">
                                <span class="page-link"><i class="fas fa-chevron-left"></i></span>
                            </li>
                            {% endif %}
                            
                            <!-- Page Numbers -->
                            {% set start_page = [1, page-2]|max %}
                            {% set end_page = [start_page + 4, total_pages]|min %}
                            
                            {% if start_page > 1 %}
                            <li class="page-item"><a class="page-link" href="#" data-page="1">1</a></li>
                            {% if start_page > 2 %}
                            <li class="page-item disabled"><span class="page-link">...</span></li>
                            {% endif %}
                            {% endif %}
                            
                            {% for page_num in range(start_page, end_page + 1) %}
                                {% if page_num == page %}
                                <li class="page-item active"><span class="page-link">{{ page_num }}</span></li>
                                {% else %}
                                <li class="page-item"><a class="page-link" href="#" data-page="{{ page_num }}">{{ page_num }}</a></li>
                                {% endif %}
                            {% endfor %}
                            
                            {% if end_page < total_pages %}
                            {% if end_page < total_pages - 1 %}
                            <li class="page-item disabled"><span class="page-link">...</span></li>
                            {% endif %}
                            <li class="page-item"><a class="page-link" href="#" data-page="{{ total_pages }}">{{ total_pages }}</a></li>
                            {% endif %}
                            
                            <!-- Next Page -->
                            {% if page < total_pages %}
                            <li class="page-item">
                                <a class="page-link" href="#" data-page="{{ page+1 }}" aria-label="Next">
                                    <i class="fas fa-chevron-right"></i>
                                </a>
                            </li>
                            {% else %}
                            <li class="page-item disabled">
                                <span class="page-link"><i class="fas fa-chevron-right"></i></span>
                            </li>
                            {% endif %}
                        </ul>
                    </nav>
                </div>
                {% endif %}
            ''', page=page, per_page=per_page, total_pdfs=total_pdfs, total_pages=total_pages, search_query=search_query),
            'pagination_data': {
                'page': page,
                'per_page': per_page,
                'total_pdfs': total_pdfs,
                'total_pages': total_pages,
                'showing_start': (page - 1) * per_page + 1,
                'showing_end': min(page * per_page, total_pdfs)
            }
        })
    
    user_stats = {
        'total_users': len(users),
        'total_pdfs': len(pdfs),
        'documents_viewed': session.get('documents_viewed', 0),
        'last_login': session.get('login_time', 'First time')[:10] if session.get('login_time') else 'First time'
    }
    
    return render_template('dashboard.html', 
                          pdfs=paginated_pdfs,
                          search_query=search_query,
                          username=session.get('user_id', 'user'),
                          user_role=session.get('user_role', 'user'),
                          location=session.get('verified_location'),
                          user_stats=user_stats,
                          user_profile=current_user,
                          page=page,
                          per_page=per_page,
                          total_pdfs=total_pdfs,
                          total_pages=total_pages)



@app.route('/admin')
@require_location_verification
def admin_dashboard():
    """Admin dashboard with location verification"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    pdfs = load_json_data('pdfs.json')
    users = load_json_data('users.json')
    
    for user in users:
        user.setdefault('created_at', 'Unknown')
        user.setdefault('name', 'Unknown')
    
    user_stats = {
        'total_users': len(users),
        'total_pdfs': len(pdfs)
    }
    
    total_pdfs = len(pdfs)
    total_pages = (total_pdfs + per_page - 1) // per_page
    
    page = max(1, min(page, total_pages))
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    pdfs_page = pdfs[start_idx:end_idx]
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('_pdf_table.html',
                             pdfs=pdfs_page,
                             page=page,
                             per_page=per_page,
                             total_pdfs=total_pdfs,
                             total_pages=total_pages)
    
    return render_template('admin_dashboard.html',
                         pdfs=pdfs_page,
                         users=users,
                         username=session.get('user_id'),
                         location=session.get('verified_location'),
                         format_date=format_date,
                         user_stats=user_stats,
                         page=page,
                         per_page=per_page,
                         total_pdfs=total_pdfs,
                         total_pages=total_pages)

@app.route('/admin/users')
@require_location_verification
def admin_users():
    """Admin users management page"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    users = load_json_data('users.json')
    
    for user in users:
        user.setdefault('created_at', 'Unknown')
        user.setdefault('name', 'Unknown')
    
    total_users = len(users)
    total_pages = (total_users + per_page - 1) // per_page
    
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    paginated_users = users[start_idx:end_idx]
    
    user_stats = {
        'total_users': total_users,
        'admin_users': sum(1 for user in users if user.get('role') == 'admin'),
        'student_users': sum(1 for user in users if user.get('role') == 'student')
    }
    
    return render_template('admin_users.html',
                         users=paginated_users,
                         username=session.get('user_id'),
                         location=session.get('verified_location'),
                         format_date=format_date,
                         user_stats=user_stats,
                         page=page,
                         per_page=per_page,
                         total_users=total_users,
                         total_pages=total_pages)

@app.route('/admin/location')
@require_location_verification
def admin_location():
    """Admin location boundary management page"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('admin_location.html',
                         username=session.get('user_id'),
                         location=session.get('verified_location'))

@app.route('/check-boundary', methods=['POST'])
@require_location_verification
def check_boundary():
    """API endpoint to check if user is within allowed boundary"""
    data = request.get_json()
    user_lat = data.get('latitude')
    user_lon = data.get('longitude')
    
    if user_lat is None or user_lon is None:
        return jsonify({
            'success': False,
            'message': 'Location data required'
        }), 400
    
    try:
        user_lat = float(user_lat)
        user_lon = float(user_lon)
    except (TypeError, ValueError):
        return jsonify({
            'success': False,
            'message': 'Invalid location data'
        }), 400
    
    allowed, location_name = is_location_allowed(user_lat, user_lon)
    
    if not allowed:
        session.clear()
        logger.warning(f"User moved outside boundary: {user_lat}, {user_lon}")
        return jsonify({
            'success': False,
            'message': 'You have moved outside the allowed boundary. Please return to the designated area.',
            'redirect': True,
            'redirect_url': url_for('welcome')
        }), 403
    
    update_location_verification(user_lat, user_lon, location_name)
    
    return jsonify({
        'success': True,
        'message': 'Location verified',
        'location': location_name
    })

@app.route('/admin/add-user', methods=['POST'])
@require_location_verification
def add_user():
    """Add new user (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    data = request.get_json()
    
    required_fields = ['username', 'password', 'role', 'name']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
    
    if data['role'] == 'student':
        if not is_valid_rollno(data['username']):
            return jsonify({'success': False, 'message': 'Student username must be 10-digit alphanumeric roll number'}), 400
        
        clean_password = ''.join(filter(str.isdigit, data['password']))
        
        if any(not char.isdigit() for char in data['password']):
            return jsonify({'success': False, 'message': 'Student password should contain only digits (DDMMYYYY format). No special characters or spaces allowed.'}), 400
        
        if not is_valid_dob(clean_password):
            return jsonify({'success': False, 'message': 'Invalid date of birth format. Use DDMMYYYY (8 digits only, no separators)'}), 400
        
        data['password'] = convert_to_iso_date(clean_password)
    
    users = load_json_data('users.json')
    
    if any(user['username'] == data['username'] for user in users):
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    new_user = {
        'id': len(users) + 1,
        'username': data['username'],
        'password': data['password'],
        'role': data['role'],
        'name': data['name'],
        'created_at': datetime.now().isoformat(),
        'created_by': session.get('user_id')
    }
    
    users.append(new_user)
    save_json_data('users.json', users)
    
    return jsonify({'success': True, 'message': 'User added successfully'})

@app.route('/admin/add-pdf', methods=['POST'])
@require_location_verification
def add_pdf():
    """Add new PDF (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    data = request.get_json()
    
    required_fields = ['title', 'drive_link']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
    
    pdfs = load_json_data('pdfs.json')
    
    new_pdf = {
        'id': len(pdfs) + 1,
        'title': data['title'],
        'drive_link': data['drive_link'],
        'file_size': data.get('file_size', 'N/A'),
        'uploaded_by': session.get('user_id'),
        'uploaded_at': datetime.now().isoformat(),
        'upload_date': datetime.now().strftime('%Y-%m-%d')
    }
    
    pdfs.append(new_pdf)
    save_json_data('pdfs.json', pdfs)
    
    return jsonify({'success': True, 'message': 'PDF added successfully'})

@app.route('/admin/delete-user/<username>', methods=['POST'])
@require_location_verification
def delete_user(username):
    """Delete user (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    users = load_json_data('users.json')
    users = [user for user in users if user['username'] != username]
    save_json_data('users.json', users)
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/admin/delete-pdf/<int:pdf_id>', methods=['POST'])
@require_location_verification
def delete_pdf(pdf_id):
    """Delete PDF (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    pdfs = load_json_data('pdfs.json')
    pdfs = [pdf for pdf in pdfs if pdf['id'] != pdf_id]
    save_json_data('pdfs.json', pdfs)
    
    return jsonify({'success': True, 'message': 'PDF deleted successfully'})

@app.route('/admin/upload-users-excel', methods=['POST'])
@require_location_verification
def upload_users_excel():
    """Upload users via Excel file"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if 'excel_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    file = request.files['excel_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'success': False, 'message': 'Please upload an Excel file (.xlsx or .xls)'}), 400
    
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 50 * 1024 * 1024:
        return jsonify({'success': False, 'message': 'File size too large. Maximum 50MB allowed.'}), 400
    
    start_time = time.time()
    success, message = process_excel_users(file)
    processing_time = time.time() - start_time
    
    logger.info(f"Bulk user upload completed in {processing_time:.2f} seconds")
    
    if success:
        return jsonify({
            'success': True, 
            'message': f"{message}. Processing time: {processing_time:.2f}s"
        })
    else:
        return jsonify({'success': False, 'message': message}), 400

@app.route('/admin/upload-pdfs-excel', methods=['POST'])
@require_location_verification
def upload_pdfs_excel():
    """Upload PDFs via Excel file"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if 'excel_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    file = request.files['excel_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'success': False, 'message': 'Please upload an Excel file (.xlsx or .xls)'}), 400
    
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 50 * 1024 * 1024:
        return jsonify({'success': False, 'message': 'File size too large. Maximum 50MB allowed.'}), 400
    
    start_time = time.time()
    success, message = process_excel_pdfs(file)
    processing_time = time.time() - start_time
    
    logger.info(f"Bulk PDF upload completed in {processing_time:.2f} seconds")
    
    if success:
        return jsonify({
            'success': True, 
            'message': f"{message}. Processing time: {processing_time:.2f}s"
        })
    else:
        return jsonify({'success': False, 'message': message}), 400

@app.route('/admin/download-users-template')
@require_location_verification
def download_users_template():
    """Download Users template Excel file"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    df = pd.DataFrame(columns=['username', 'password', 'role', 'name'])
    
    examples = [
        {'username': '23N81A62B0', 'password': '15082002', 'role': 'student', 'name': 'Rajesh Kumar'},
        {'username': '22M91A12C5', 'password': '23112001', 'role': 'student', 'name': 'Priya Sharma'},
        {'username': 'admin2', 'password': 'securepassword123', 'role': 'admin', 'name': 'Library Manager'}
    ]
    
    df = pd.concat([df, pd.DataFrame(examples)], ignore_index=True)
    
    buffer = BytesIO()
    
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Users Template', index=False)
    
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name='users_template.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/admin/download-pdfs-template')
@require_location_verification
def download_pdfs_template():
    """Download PDFs template Excel file"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    df = pd.DataFrame(columns=['title', 'drive_link', 'file_size'])
    
    examples = [
        {
            'title': 'Advanced Python Programming', 
            'drive_link': 'https://drive.google.com/file/d/python_advanced_2023/view',
            'file_size': '15.2 MB'
        },
        {
            'title': 'Machine Learning Fundamentals', 
            'drive_link': 'https://drive.google.com/file/d/ml_fundamentals_2023/view',
            'file_size': '8.7 MB'
        }
    ]
    
    df = pd.concat([df, pd.DataFrame(examples)], ignore_index=True)
    
    buffer = BytesIO()
    
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='PDFs Template', index=False)
    
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name='pdfs_template.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/admin/save-boundary', methods=['POST'])
@require_location_verification
def save_boundary():
    """Save location boundary (Admin only)"""
    try:
        if session.get('user_role') != 'admin':
            logger.warning(f"Unauthorized access attempt by user: {session.get('user_id')}")
            return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        logger.info(f"Received boundary data: {data}")
        
        required_fields = ['name', 'type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
        
        if data['type'] == 'circle':
            circle_fields = ['latitude', 'longitude', 'radius_km']
            for field in circle_fields:
                if field not in data:
                    return jsonify({'success': False, 'message': f'Missing circle field: {field}'}), 400
                try:
                    data[field] = float(data[field])
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'message': f'Invalid {field} value: {data[field]}'}), 400
        
        elif data['type'] == 'rectangle':
            rect_fields = ['north', 'south', 'east', 'west']
            for field in rect_fields:
                if field not in data:
                    return jsonify({'success': False, 'message': f'Missing rectangle field: {field}'}), 400
                try:
                    data[field] = float(data[field])
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'message': f'Invalid {field} value: {data[field]}'}), 400
        
        elif data['type'] == 'polygon':
            if 'coordinates' not in data or not data['coordinates']:
                return jsonify({'success': False, 'message': 'Missing polygon coordinates'}), 400
            try:
                for i, coord in enumerate(data['coordinates']):
                    if len(coord) != 2:
                        return jsonify({'success': False, 'message': f'Invalid coordinate at index {i}'}), 400
                    data['coordinates'][i] = [float(coord[0]), float(coord[1])]
            except (ValueError, TypeError) as e:
                return jsonify({'success': False, 'message': f'Invalid coordinate format: {str(e)}'}), 400
        
        else:
            return jsonify({'success': False, 'message': f'Invalid boundary type: {data["type"]}'}), 400
        
        try:
            boundaries = load_json_data('boundaries.json')
        except Exception as e:
            logger.warning(f"Could not load boundaries, starting fresh: {str(e)}")
            boundaries = []
        
        existing_index = next((i for i, b in enumerate(boundaries) if b['name'] == data['name']), -1)
        
        if existing_index >= 0:
            boundaries[existing_index] = {
                **boundaries[existing_index],
                **data,
                'updated_at': datetime.now().isoformat(),
                'updated_by': session.get('user_id')
            }
            message = 'Boundary updated successfully'
            action = 'updated'
        else:
            new_boundary = {
                'id': len(boundaries) + 1,
                **data,
                'created_by': session.get('user_id'),
                'created_at': datetime.now().isoformat()
            }
            boundaries.append(new_boundary)
            message = 'Boundary saved successfully'
            action = 'created'
        
        save_json_data('boundaries.json', boundaries)
        
        logger.info(f"Boundary '{data['name']}' {action} successfully. Total boundaries: {len(boundaries)}")
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        logger.error(f"Error saving boundary: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Server error while saving boundary: {str(e)}'
        }), 500

@app.route('/admin/get-boundaries')
@require_location_verification
def get_boundaries():
    """Get all location boundaries"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        boundaries = load_json_data('boundaries.json')
        logger.info(f"Loaded {len(boundaries)} boundaries")
        return jsonify({'success': True, 'boundaries': boundaries})
        
    except Exception as e:
        logger.error(f"Error loading boundaries: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Error loading boundaries: {str(e)}',
            'boundaries': []
        }), 500

@app.route('/admin/delete-boundary', methods=['POST'])
@require_location_verification
def delete_boundary():
    """Delete location boundary (Admin only)"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        data = request.get_json()
        boundary_name = data.get('name')
        
        if not boundary_name:
            return jsonify({'success': False, 'message': 'Boundary name required'}), 400
        
        boundaries = load_json_data('boundaries.json')
        initial_count = len(boundaries)
        boundaries = [b for b in boundaries if b['name'] != boundary_name]
        
        if len(boundaries) == initial_count:
            return jsonify({'success': False, 'message': 'Boundary not found'}), 404
        
        save_json_data('boundaries.json', boundaries)
        
        logger.info(f"Boundary '{boundary_name}' deleted successfully. Remaining boundaries: {len(boundaries)}")
        return jsonify({'success': True, 'message': 'Boundary deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting boundary: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Error deleting boundary: {str(e)}'
        }), 500

@app.route('/api/pdfs')
@require_location_verification
def api_pdfs():
    """API endpoint for PDF data"""
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    pdfs = load_json_data('pdfs.json')
    return jsonify(pdfs)

@app.route('/api/search-pdfs')
@require_location_verification
def api_search_pdfs():
    """API endpoint for searching PDFs"""
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    query = request.args.get('q', '')
    
    pdfs = load_json_data('pdfs.json')
    
    filtered_pdfs = pdfs
    if query:
        filtered_pdfs = [pdf for pdf in filtered_pdfs 
                        if query.lower() in pdf['title'].lower() 
                        or any(query.lower() in tag.lower() for tag in pdf.get('tags', []))]
    
    return jsonify(filtered_pdfs[:50])

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    try:
        users = load_json_data('users.json')
        pdfs = load_json_data('pdfs.json')
        
        stats = {
            'total_users': len(users),
            'total_pdfs': len(pdfs),
            'total_categories': len(set(pdf['category'] for pdf in pdfs if 'category' in pdf)),
            'total_admins': len([user for user in users if user.get('role') == 'admin']),
            'total_students': len([user for user in users if user.get('role') == 'student'])
        }
        
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'success': False, 'message': 'Error loading statistics'}), 500

@app.route('/admin-direct-access')
def admin_direct_access():
    """Special route for direct admin access via keyboard shortcut"""
    secret_key = request.args.get('key', '')
    
    if secret_key == app.config.get('ADMIN_DIRECT_ACCESS_KEY', 'ctrl_j_secret'):
        session['direct_admin'] = True
        session['direct_access_timestamp'] = datetime.now().isoformat()
        return redirect(url_for('login'))
    
    return redirect(url_for('login'))

@app.route('/user-direct-access')
def user_direct_access():
    """Special route for direct user access via keyboard shortcut"""
    secret_key = request.args.get('key', '')
    
    if secret_key == app.config.get('USER_DIRECT_ACCESS_KEY', 'ctrl_k_secret'):
        session['direct_user'] = True
        session['direct_access_timestamp'] = datetime.now().isoformat()
        return redirect(url_for('login'))
    
    return redirect(url_for('login'))

@app.route('/debug/boundaries')
def debug_boundaries():
    """Debug endpoint to check boundaries data"""
    try:
        boundaries = load_json_data('boundaries.json')
        return jsonify({
            'success': True,
            'boundaries': boundaries,
            'file_exists': os.path.exists('data/boundaries.json')
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@app.route('/debug/save-test', methods=['POST'])
def debug_save_test():
    """Test endpoint to check if saving works"""
    try:
        data = request.get_json()
        logger.info(f"Received data: {data}")
        
        test_data = {
            'test': True,
            'timestamp': datetime.now().isoformat(),
            'received_data': data
        }
        
        save_json_data('test.json', [test_data])
        
        return jsonify({
            'success': True,
            'message': 'Test save successful',
            'saved_data': test_data
        })
    except Exception as e:
        logger.error(f"Debug save error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/logout')
def logout():
    """Logout endpoint with complete session clearing"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5001)