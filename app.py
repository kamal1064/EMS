"""
Employee Management System - Flask Backend (MongoDB Atlas)
===========================================================
Run with: python app.py
"""

# Load .env FIRST so all os.environ.get() calls throughout the app read correct values
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional; env vars may be set by the OS/host

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, Blueprint
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_cors import CORS
from pymongo import MongoClient
import pymongo.errors
from bson.objectid import ObjectId
import certifi


import hashlib
import secrets
import os
import csv
import io
import calendar
import bcrypt
import logging
import json
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from datetime import datetime, date, timedelta
from functools import wraps
import pyotp
import qrcode
import base64
from io import BytesIO
from utils.mailer import send_verification_email, send_reset_email

# ─────────────────────────────────────────
# SECURITY & MONITORING INIT
# ─────────────────────────────────────────

# Initialize Sentry Error Monitoring (if DSN provided)
sentry_dsn = os.environ.get('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        # Scrub header keys and potentially sensitive info
        before_send=lambda event, hint: {
            **event,
            'request': {**event.get('request', {}), 'headers': '[REDACTED]'}
        } if event else None,
    )

app = Flask(__name__)

# Enforce SECRET_KEY crash on startup if missing
secret = os.environ.get('SECRET_KEY')
if not secret:
    raise RuntimeError("SECRET_KEY environment variable is not set. Refusing to start.")
app.secret_key = secret

# Structured JSON Logging
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "level": record.levelname,
            "msg": record.getMessage(),
            "time": self.formatTime(record),
            "module": record.module,
        }
        if record.exc_info:
            log_entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

app.logger.handlers.clear()
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Flask-Cors configuration
cors_origins_env = os.environ.get('CORS_ORIGINS', 'http://127.0.0.1:5000')
CORS(app,
     origins=cors_origins_env.split(','),
     supports_credentials=True,
     methods=['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'])

# Flask-Talisman Security Headers
is_prod = os.environ.get('FLASK_ENV', 'production') == 'production'
Talisman(app,
    force_https=is_prod,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", "cdn.jsdelivr.net", "cdn.tailwindcss.com"],
        'style-src':  ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdn.jsdelivr.net"],
        'font-src':   ["'self'", "fonts.gstatic.com", "cdn.jsdelivr.net"],
        'img-src':    ["'self'", "data:", "*"],
    },
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
)

# Session Cookie Security
app.config.update(
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=is_prod,
)

# Request size limits (1MB max payload)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

@app.errorhandler(413)
def request_too_large(e):
    app.logger.warning("Payload size limit exceeded (413 error)")
    return jsonify({
        "success": False,
        "error": {
            "code": "PAYLOAD_TOO_LARGE",
            "message": "Request payload exceeds 1MB limit."
        }
    }), 413


# ─────────────────────────────────────────
# API V1 BLUEPRINT DECLARATION
# ─────────────────────────────────────────
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')



DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'database.db'))

# ─────────────────────────────────────────
# RATE LIMITER SETUP
# ─────────────────────────────────────────

limiter = Limiter(
    key_func=get_remote_address,      # limit by IP address
    app=app,
    default_limits=["300 per day", "60 per hour"],  # global fallback
    storage_uri="memory://",          # in-memory (switch to redis:// in prod)
)

@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Return JSON for API calls, friendly HTML for browser requests."""
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({
            'error': 'Too many requests',
            'message': str(e.description),
            'retry_after': e.retry_after if hasattr(e, 'retry_after') else 60
        }), 429
    # Browser-friendly 429 page
    retry = getattr(e, 'retry_after', 60)
    html = f"""<!DOCTYPE html>
<html><head><title>Too Many Requests — EMS</title>
<style>
  body{{font-family:'Plus Jakarta Sans',sans-serif;background:#0f172a;color:#f1f5f9;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}}
  .box{{text-align:center;padding:48px;background:#1e293b;border-radius:20px;
        border:1px solid rgba(255,255,255,0.08);max-width:420px;}}
  .icon{{font-size:52px;margin-bottom:16px;}}
  h1{{font-size:22px;font-weight:800;margin:0 0 10px;}}
  p{{color:#94a3b8;font-size:14px;line-height:1.7;}}
  .badge{{display:inline-block;margin-top:20px;padding:8px 20px;background:#3b82f6;
           border-radius:10px;font-size:13px;font-weight:700;color:#fff;}}
  a{{color:#3b82f6;text-decoration:none;}}
</style></head>
<body><div class="box">
  <div class="icon">🛑</div>
  <h1>Too Many Requests</h1>
  <p>{e.description}</p>
  <p>Please wait <strong>{retry} seconds</strong> before trying again.</p>
  <a href="/" class="badge">← Go Back</a>
</div></body></html>"""
    return html, 429


# ─────────────────────────────────────────
# DATABASE SETUP (MONGODB ATLAS)
# ─────────────────────────────────────────

mongo_uri = os.environ.get('MONGO_URI')
if not mongo_uri:
    raise RuntimeError("MONGO_URI environment variable is not set. Refusing to start.")

try:
    mongo_client = MongoClient(mongo_uri, tlsCAFile=certifi.where())
    # Ping database to check connection
    mongo_client.admin.command('ping')
    db = mongo_client.get_default_database()
except Exception as e:
    try:
        db = mongo_client['ems_db']
    except Exception:
        raise RuntimeError(f"Failed to initialize MongoDB connection: {e}")


def init_db():
    """Initialize MongoDB collections and create unique indexes."""
    try:
        db.users.create_index("email", unique=True)
        db.users.create_index("username", unique=True)
        app.logger.info("MongoDB indexes verified successfully.")
    except Exception as e:
        app.logger.error(f"Error initializing MongoDB: {e}", exc_info=True)


try:
    init_db()
except Exception as e:
    app.logger.error(f"Import time init_db error: {e}")
    pass


# ─────────────────────────────────────────
# HEALTH & READY ENDPOINTS
# ─────────────────────────────────────────

@app.route('/health')
def health():
    """Liveness probe returning simple OK status."""
    return jsonify({"status": "ok"}), 200


@app.route('/ready')
def ready():
    """Readiness probe checking MongoDB connection status."""
    try:
        db.client.admin.command('ping')
        return jsonify({"status": "ready", "database": "connected"}), 200
    except Exception as e:
        app.logger.error(f"Readiness probe failed: {e}")
        return jsonify({"status": "not_ready", "error": str(e)}), 503


# ─────────────────────────────────────────

# DOCUMENT SERIALIZATION HELPERS
# ─────────────────────────────────────────

def serialize_doc(doc):
    """Adds a string 'id' field to a MongoDB document based on its '_id'."""
    if not doc:
        return None
    doc = dict(doc)
    if '_id' in doc:
        doc['id'] = str(doc['_id'])
    return doc


def serialize_docs(docs):
    """Serialize a list of MongoDB documents."""
    return [serialize_doc(d) for d in docs]


def safe_object_id(val):
    """Safely cast value to ObjectId, returning None if invalid."""
    if not val:
        return None
    try:
        return ObjectId(str(val))
    except Exception:
        return None




# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def hash_password(password):
    """Hash password using bcrypt (rounds=12)."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')


def verify_and_migrate_password(user_id, password, stored_hash):
    """
    Verify password using bcrypt. If stored_hash is a legacy SHA-256 hash
    (64 chars, not starting with '$'), verify using SHA-256, and if successful,
    automatically upgrade/re-hash using bcrypt and update the database.
    """
    is_legacy = len(stored_hash) == 64 and not stored_hash.startswith('$')
    
    if is_legacy:
        sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if sha256_hash == stored_hash:
            new_bcrypt_hash = hash_password(password)
            db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": new_bcrypt_hash}})
            app.logger.info("Automatically migrated user password from SHA-256 to bcrypt", extra={"user_id": str(user_id)})
            return True
        return False
    else:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception as e:
            app.logger.error("Bcrypt check failed", exc_info=True)
            return False



def login_required(f):
    """Decorator to protect routes that need login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user_id():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user_id():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        # Validate that uid is a valid hex string of 24 characters (ObjectId)
        ObjectId(uid)
        return uid
    except Exception:
        # Force logout/clear of legacy SQLite integer user_id or corrupt session
        session.clear()
        return None



# ─────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per hour")            # 5 signups/hour per IP
def signup():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # Validation
        if not email or not password:
            return render_template('signup.html', error='All fields are required.')
        if '@' not in email or '.' not in email.split('@')[-1]:
            return render_template('signup.html', error='Please enter a valid email address.')
        if len(password) < 8:
            return render_template('signup.html', error='Password must be at least 8 characters.')
        if password != confirm:
            return render_template('signup.html', error='Passwords do not match.')

        username = email.split('@')[0]
        if db.users.find_one({"email": email}):
            return render_template('signup.html', error='An account with this email already exists.')
        if db.users.find_one({"username": username}):
            return render_template('signup.html', error='An account with this username already exists.')

        verify_token = secrets.token_urlsafe(32)
        try:
            db.users.insert_one({
                "username": username,
                "email": email,
                "password": hash_password(password),
                "otp_secret": None,
                "otp_enabled": False,
                "is_verified": False,
                "verify_token": verify_token,
                "reset_token": None,
                "reset_token_expiry": None,
                "created_at": datetime.utcnow().isoformat()
            })
        except pymongo.errors.DuplicateKeyError as e:
            # Fallback catch in case of race conditions
            app.logger.warning(f"Race condition DuplicateKeyError during signup: {e}")
            return render_template('signup.html', error='An account with this email or username already exists.')


        send_verification_email(email, verify_token)
        return render_template('signup.html', sent=True, email=email)

    return render_template('signup.html')


@app.route('/verify/<token>')
def verify_email(token):
    user = db.users.find_one({"verify_token": token, "is_verified": False})
    if not user:
        return render_template('verify_email.html', status='invalid')
    
    db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"is_verified": True, "verify_token": None}}
    )
    return render_template('verify_email.html', status='success')


@app.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per hour")
def resend_verification():
    email = request.form.get('email', '').strip().lower()
    if not email:
        return redirect(url_for('login'))
    
    user = db.users.find_one({"email": email, "is_verified": False})
    if user:
        new_token = secrets.token_urlsafe(32)
        db.users.update_one(
            {"_id": user['_id']},
            {"$set": {"verify_token": new_token}}
        )
        send_verification_email(email, new_token)
    return render_template('login.html', success='Verification email resent! Check your inbox.')



@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")         # 10 login attempts/min — brute-force protection
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    success = request.args.get('success')
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember_me') == 'on'

        if not email or not password:
            return render_template('login.html', error='Email and password are required.')

        user = db.users.find_one({"email": email})
        
        if user and verify_and_migrate_password(user['_id'], password, user['password']):
            # Password verification succeeded
            app.logger.info("User login successful", extra={"user_id": str(user['_id'])})
        else:
            user = None

        if not user:
            return render_template('login.html', error='Invalid email or password.')

        # Block unverified users
        if not user.get('is_verified', True):
            return render_template('login.html',
                error='Please verify your email before logging in.',
                unverified_email=email)

        session['user_id']  = str(user['_id'])
        session['username'] = user['username']
        session['last_login'] = datetime.now().strftime('%b %d, %Y at %I:%M %p')
        if remember:
            from flask import current_app
            session.permanent = True
            current_app.permanent_session_lifetime = timedelta(days=30)

        return redirect(url_for('dashboard'))

    return render_template('login.html', success=success)


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if email:
            user = db.users.find_one({"email": email})
            if user:
                token  = secrets.token_urlsafe(32)
                expiry = (datetime.utcnow() + timedelta(hours=1)).isoformat()
                db.users.update_one(
                    {"_id": user['_id']},
                    {"$set": {"reset_token": token, "reset_token_expiry": expiry}}
                )
                send_reset_email(email, token)
        # Always show success (prevents user enumeration)
        return render_template('forgot_password.html', sent=True, email=email)
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = db.users.find_one({"reset_token": token})

    # Token not found
    if not user:
        return render_template('reset_password.html', status='invalid')

    # Token expired
    if user.get('reset_token_expiry'):
        try:
            expiry = datetime.fromisoformat(user['reset_token_expiry'])
            if datetime.utcnow() > expiry:
                return render_template('reset_password.html', status='expired')
        except ValueError:
            return render_template('reset_password.html', status='invalid')

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        if len(password) < 8:
            return render_template('reset_password.html', status='form', token=token,
                                   error='Password must be at least 8 characters.')
        if password != confirm:
            return render_template('reset_password.html', status='form', token=token,
                                   error='Passwords do not match.')
        
        db.users.update_one(
            {"_id": user['_id']},
            {"$set": {
                "password": hash_password(password),
                "reset_token": None,
                "reset_token_expiry": None
            }}
        )
        return render_template('reset_password.html', status='success')

    # GET — show the form
    return render_template('reset_password.html', status='form', token=token)




@api_v1.route('/profile-info')
@login_required
def api_profile_info():
    """Return current user info as JSON for the profile popup."""
    user = db.users.find_one({"_id": ObjectId(get_current_user_id())})
    user = serialize_doc(user)
    return jsonify({
        'username':   user['username'] if user else session.get('username', ''),
        'email':      user['email']    if user else '',
        'last_login': session.get('last_login', 'Unknown'),
    })



@api_v1.route('/change-password', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def api_change_password():
    """Change password from the profile popup (JSON API)."""
    data        = request.get_json(silent=True) or {}
    current_pw  = data.get('current_password', '')
    new_pw      = data.get('new_password', '')
    confirm_pw  = data.get('confirm_password', '')

    if not current_pw or not new_pw or not confirm_pw:
        return jsonify({'ok': False, 'error': 'All fields are required.'}), 400
    if len(new_pw) < 8:
        return jsonify({'ok': False, 'error': 'Password must be at least 8 characters.'}), 400
    if new_pw != confirm_pw:
        return jsonify({'ok': False, 'error': 'New passwords do not match.'}), 400

    user = db.users.find_one({"_id": ObjectId(get_current_user_id())})
    
    if not user or not verify_and_migrate_password(user['_id'], current_pw, user['password']):
        return jsonify({'ok': False, 'error': 'Current password is incorrect.'}), 403

    db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"password": hash_password(new_pw)}}
    )
    return jsonify({'ok': True, 'message': 'Password changed successfully.'})


@app.route('/logout')

def logout():
    session.clear()
    return redirect(url_for('login'))





# ─────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────

@app.route('/dashboard')
@limiter.limit("120 per minute")        # generous — it's a read-only page
@login_required
def dashboard():
    uid = get_current_user_id()

    # Employees
    employees = list(db.employees.find({"user_id": ObjectId(uid)}))
    employees = serialize_docs(employees)
    
    total_emp = len(employees)
    avg_salary = round(sum(e.get('salary', 0.0) for e in employees) / total_emp, 2) if total_emp else 0
    avg_age = round(sum(e.get('age', 0) for e in employees) / total_emp, 1) if total_emp else 0
    total_hrs = sum(e.get('working_hours', 40.0) for e in employees)

    # Attendance summary
    emp_ids = [ObjectId(e['id']) for e in employees]
    present_count = 0
    absent_count = 0
    
    if emp_ids:
        # In SQLite, missing date = Present, absent rows = Absent.
        absent_count = db.attendance.count_documents({"emp_id": {"$in": emp_ids}, "status": "Absent"})
        present_count = db.attendance.count_documents({"emp_id": {"$in": emp_ids}, "status": "Present"})

    # Salary distribution for chart
    salary_data = [{'name': e['name'], 'salary': e['salary']} for e in employees]

    # Recent attendance (last 10 records)
    recent_att = []
    if emp_ids:
        recent_rows = list(db.attendance.find({"emp_id": {"$in": emp_ids}}).sort("date", -1).limit(10))
        emp_dict = {ObjectId(e['id']): e['name'] for e in employees}
        for r in recent_rows:
            recent_att.append({
                'name': emp_dict.get(r['emp_id'], 'Unknown'),
                'date': r['date'],
                'status': r['status']
            })

    today = date.today().isoformat()

    return render_template('dashboard.html',
                           total_emp=total_emp,
                           avg_salary=avg_salary,
                           avg_age=avg_age,
                           total_hrs=total_hrs,
                           present_count=present_count,
                           absent_count=absent_count,
                           salary_data=salary_data,
                           recent_att=recent_att,
                           today=today)


# ─────────────────────────────────────────
# EMPLOYEES
# ─────────────────────────────────────────

@app.route('/employees')
@limiter.limit("120 per minute")
@login_required
def employees():
    uid = get_current_user_id()
    search = request.args.get('q', '').strip()

    if search:
        emps = list(db.employees.find({
            "user_id": ObjectId(uid),
            "name": {"$regex": search, "$options": "i"}
        }).sort("name", 1))
    else:
        emps = list(db.employees.find({"user_id": ObjectId(uid)}).sort("name", 1))

    emps = serialize_docs(emps)
    return render_template('employees.html', employees=emps, search=search)


@app.route('/employees/add', methods=['POST'])
@limiter.limit("30 per minute")         # prevent rapid bulk employee creation
@login_required
def add_employee():
    uid = get_current_user_id()
    name = request.form.get('name', '').strip()
    if not name:
        redirect_to = request.form.get('redirect_to')
        if redirect_to == 'part_time':
            return redirect(url_for('part_time'))
        return redirect(url_for('employees'))

    phone = request.form.get('phone', '').strip()
    gender = request.form.get('gender', '')

    try:
        age = int(request.form.get('age') or 0)
    except (TypeError, ValueError):
        age = 0
    age = max(age, 0)

    try:
        salary = float(request.form.get('salary') or 0.0)
    except (TypeError, ValueError):
        salary = 0.0
    salary = max(salary, 0.0)

    try:
        leaves = int(request.form.get('leaves') or 0)
    except (TypeError, ValueError):
        leaves = 0
    leaves = max(leaves, 0)

    try:
        hours = float(request.form.get('working_hours') or 40.0)
    except (TypeError, ValueError):
        hours = 40.0
    hours = max(hours, 0.0)

    db.employees.insert_one({
        "name": name,
        "phone": phone,
        "age": age,
        "gender": gender,
        "salary": salary,
        "leaves": leaves,
        "working_hours": hours,
        "user_id": ObjectId(uid),
        "created_at": datetime.utcnow().isoformat()
    })


    redirect_to = request.form.get('redirect_to')
    if redirect_to == 'part_time':
        return redirect(url_for('part_time'))
    return redirect(url_for('employees'))


@app.route('/employees/edit/<emp_id>', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
@login_required
def edit_employee(emp_id):
    uid = get_current_user_id()
    emp_id_obj = safe_object_id(emp_id)
    if not emp_id_obj:
        return redirect(url_for('employees'))

    if request.method == 'POST':
        try:
            age = int(request.form.get('age') or 0)
        except (TypeError, ValueError):
            age = 0
        age = max(age, 0)

        try:
            salary = float(request.form.get('salary') or 0.0)
        except (TypeError, ValueError):
            salary = 0.0
        salary = max(salary, 0.0)

        try:
            leaves = int(request.form.get('leaves') or 0)
        except (TypeError, ValueError):
            leaves = 0
        leaves = max(leaves, 0)

        try:
            hours = float(request.form.get('working_hours') or 40.0)
        except (TypeError, ValueError):
            hours = 40.0
        hours = max(hours, 0.0)

        db.employees.update_one(
            {"_id": emp_id_obj, "user_id": ObjectId(uid)},
            {"$set": {
                "name": request.form.get('name'),
                "phone": request.form.get('phone'),
                "age": age,
                "gender": request.form.get('gender'),
                "salary": salary,
                "leaves": leaves,
                "working_hours": hours
            }}
        )
        return redirect(url_for('employees'))

    emp = db.employees.find_one({"_id": emp_id_obj, "user_id": ObjectId(uid)})
    emp = serialize_doc(emp)
    if not emp:
        return redirect(url_for('employees'))
    return render_template('edit_employee.html', emp=emp)



@app.route('/employees/delete/<emp_id>', methods=['POST'])
@limiter.limit("20 per minute")         # prevent rapid deletion attacks
@login_required
def delete_employee(emp_id):
    uid = get_current_user_id()
    emp_id_obj = safe_object_id(emp_id)
    if not emp_id_obj:
        return redirect(url_for('employees'))

    db.attendance.delete_many({"emp_id": emp_id_obj})
    db.salary_records.delete_many({"emp_id": emp_id_obj})
    db.employees.delete_one({"_id": emp_id_obj, "user_id": ObjectId(uid)})
    return redirect(url_for('employees'))



# ─────────────────────────────────────────
# ATTENDANCE
# ─────────────────────────────────────────

@app.route('/attendance')
@limiter.limit("120 per minute")
@login_required
def attendance():
    uid = get_current_user_id()
    selected_date = request.args.get('date', date.today().isoformat())

    emps = list(db.employees.find({"user_id": ObjectId(uid)}).sort("name", 1))
    emps = serialize_docs(emps)
    att_map = {e['id']: 'Present' for e in emps}

    if emps:
        emp_ids = [ObjectId(e['id']) for e in emps]
        records = list(db.attendance.find({
            "date": selected_date,
            "emp_id": {"$in": emp_ids}
        }))
        for r in records:
            att_map[str(r['emp_id'])] = r['status']

    return render_template(
        'attendance.html',
        employees=emps,
        att_map=att_map,
        selected_date=selected_date,
        today=date.today().isoformat()
    )


@app.route('/attendance/mark', methods=['POST'])
@limiter.limit("120 per minute")        # high limit — real-time marking via JS clicks
@login_required
def mark_attendance():
    data = request.get_json()
    emp_id = data.get('emp_id')
    att_date = data.get('date')
    status = data.get('status')

    if not all([emp_id, att_date, status]):
        return jsonify({'success': False})

    try:
        if status == 'Present':
            db.attendance.delete_one({"emp_id": ObjectId(emp_id), "date": att_date})
        else:
            db.attendance.update_one(
                {"emp_id": ObjectId(emp_id), "date": att_date},
                {"$set": {"status": status}},
                upsert=True
            )
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        app.logger.error("Failed to mark attendance", exc_info=True)
        return jsonify({'success': False, 'message': str(e)})


@app.route('/attendance/summary')
@limiter.limit("60 per minute")
@login_required
def attendance_summary():
    uid = get_current_user_id()
    month_filter = request.args.get('month', datetime.now().strftime('%Y-%m'))

    emps = list(db.employees.find({"user_id": ObjectId(uid)}).sort("name", 1))
    emps = serialize_docs(emps)
    
    year, month_num = map(int, month_filter.split('-'))
    total_days = calendar.monthrange(year, month_num)[1]

    summary = []
    for e in emps:
        absent_days = db.attendance.count_documents({
            "emp_id": ObjectId(e['id']),
            "status": "Absent",
            "date": {"$regex": f"^{month_filter}"}
        })
        present_days = total_days - absent_days
        summary.append({
            'name': e['name'],
            'present': present_days,
            'absent': absent_days,
            'total': total_days
        })

    return render_template('attendance_summary.html', summary=summary, month_filter=month_filter)


# ─────────────────────────────────────────
# SALARY
# ─────────────────────────────────────────

@app.route('/salary')
@limiter.limit("60 per minute")
@login_required
def salary():
    uid = get_current_user_id()
    month_filter = request.args.get('month', datetime.now().strftime('%Y-%m'))

    emps = list(db.employees.find({"user_id": ObjectId(uid)}).sort("name", 1))
    emps = serialize_docs(emps)
    
    year, month_num = map(int, month_filter.split('-'))
    total_days = calendar.monthrange(year, month_num)[1]

    salary_details = []
    for e in emps:
        absent_days = db.attendance.count_documents({
            "emp_id": ObjectId(e['id']),
            "status": "Absent",
            "date": {"$regex": f"^{month_filter}"}
        })
        present_days = total_days - absent_days

        salary_per_day = e.get('salary', 0.0) / total_days
        final_salary = round(salary_per_day * present_days, 2)

        # Check existing record
        rec = db.salary_records.find_one({"emp_id": ObjectId(e['id']), "month": month_filter})

        if not rec:
            db.salary_records.insert_one({
                "emp_id": ObjectId(e['id']),
                "month": month_filter,
                "present_days": present_days,
                "total_salary": final_salary,
                "advance_amount_paid": 0.0,
                "advance_paid_at": None,
                "payment_status": "Unpaid",
                "paid_at": None
            })
            
            payment_status = 'Unpaid'
            paid_at = None
            advance_amount_paid = 0.0
            advance_paid_at = None
        else:
            if rec.get('payment_status') == 'Unpaid':
                db.salary_records.update_one(
                    {"_id": rec['_id']},
                    {"$set": {"present_days": present_days, "total_salary": final_salary}}
                )
            
            payment_status = rec.get('payment_status', 'Unpaid')
            paid_at = rec.get('paid_at')
            advance_amount_paid = rec.get('advance_amount_paid', 0.0)
            advance_paid_at = rec.get('advance_paid_at')

        net_payable = round(final_salary - advance_amount_paid, 2)

        salary_details.append({
            'id': e['id'],
            'name': e['name'],
            'monthly_salary': e['salary'],
            'present_days': present_days,
            'salary_per_day': round(salary_per_day, 2),
            'final_salary': final_salary,
            'advance_amount_paid': advance_amount_paid,
            'advance_paid_at': advance_paid_at,
            'net_payable': net_payable,
            'payment_status': payment_status,
            'paid_at': paid_at
        })

    return render_template('salary.html', salary_details=salary_details, month_filter=month_filter)


# ─────────────────────────────────────────
# PART-TIME EMPLOYEES
# ─────────────────────────────────────────

@app.route('/part-time')
@limiter.limit("60 per minute")
@login_required
def part_time():
    uid = get_current_user_id()
    search = request.args.get('q', '').strip()
    selected_client = request.args.get('client', '').strip()
    
    setup_error = None
    
    # Get decoupled part-time workers for the dropdown
    pt_workers = list(db.part_time_workers.find({"user_id": ObjectId(uid)}).sort("name", 1))
    worker_names = {str(w['_id']): w['name'] for w in pt_workers}
    
    # Get part-time logs mapped with worker name
    worker_ids = [ObjectId(wid) for wid in worker_names.keys()]
    logs = list(db.part_time_work_logs.find({"worker_id": {"$in": worker_ids}}).sort("_id", -1))
    
    records = []
    for log in logs:
        serialized = serialize_doc(log)
        serialized['worker_name'] = worker_names.get(str(log['worker_id']), 'Unknown Worker')
        records.append(serialized)
        
    part_time_workers = serialize_docs(pt_workers)

    for record in records:
        record['client_name'] = (record.get('client_name') or 'Unassigned').strip()
        record['advance_paid'] = float(record.get('advance_paid') or 0)
        record['total_price'] = float(record.get('total_price') or 0)
        record['slab_quantity'] = int(record.get('slab_quantity') or 0)
        
        fallback_balance = max(record['total_price'] - record['advance_paid'], 0)
        record['remaining_balance'] = float(
            record.get('remaining_balance')
            if record.get('remaining_balance') is not None
            else fallback_balance
        )
        record['payment_status'] = record.get('payment_status') or (
            'Paid' if record['remaining_balance'] <= 0 else 'Unpaid'
        )

    client_map = {}
    worker_map = {}
    monthly_map = {}
    recent_clients = []

    for record in records:
        client = record['client_name']
        worker = record.get('worker_name') or 'Unknown Worker'
        client_stats = client_map.setdefault(client, {
            'name': client,
            'entries': 0,
            'total_payout': 0,
            'advance_paid': 0,
            'remaining_balance': 0,
            'slabs': 0,
            'workers': set()
        })
        client_stats['entries'] += 1
        client_stats['total_payout'] += record['total_price']
        client_stats['advance_paid'] += record['advance_paid']
        client_stats['remaining_balance'] += record['remaining_balance']
        client_stats['slabs'] += record['slab_quantity']
        client_stats['workers'].add(worker)

        worker_stats = worker_map.setdefault(worker, {
            'name': worker,
            'clients': set(),
            'earnings': 0,
            'recent_assignments': []
        })
        worker_stats['clients'].add(client)
        worker_stats['earnings'] += record['total_price']
        if len(worker_stats['recent_assignments']) < 3:
            worker_stats['recent_assignments'].append({
                'client': client,
                'date': record.get('working_date'),
                'total': record['total_price']
            })

        work_month = (record.get('working_date') or '')[:7] or 'Undated'
        monthly_map[work_month] = monthly_map.get(work_month, 0) + record['total_price']

        if client not in recent_clients:
            recent_clients.append(client)

    client_summaries = sorted(client_map.values(), key=lambda c: c['total_payout'], reverse=True)
    for summary in client_summaries:
        summary['worker_count'] = len(summary['workers'])
        summary['workers'] = sorted(summary['workers'])

    filtered_records = records
    if selected_client:
        filtered_records = [
            record for record in filtered_records
            if record['client_name'].lower() == selected_client.lower()
        ]
    if search:
        needle = search.lower()
        filtered_records = [
            record for record in filtered_records
            if needle in record['client_name'].lower()
            or needle in (record.get('worker_name') or '').lower()
            or needle in (record.get('delivery_location') or '').lower()
        ]

    analytics = {
        'top_clients': client_summaries[:5],
        'workforce_allocation': sorted(client_summaries, key=lambda c: c['entries'], reverse=True)[:6],
        'monthly_client_expenses': [
            {'month': month, 'total': total}
            for month, total in sorted(monthly_map.items())
        ],
        'client_productivity': sorted(client_summaries, key=lambda c: c['slabs'], reverse=True)[:6],
        'total_payout': sum(record['total_price'] for record in filtered_records),
        'total_advance': sum(record['advance_paid'] for record in filtered_records),
        'total_remaining': sum(record['remaining_balance'] for record in filtered_records),
        'total_slabs': sum(record['slab_quantity'] for record in filtered_records)
    }

    worker_history = []
    for worker in sorted(worker_map.values(), key=lambda w: w['earnings'], reverse=True):
        worker_history.append({
            'name': worker['name'],
            'clients': sorted(worker['clients']),
            'earnings': worker['earnings'],
            'recent_assignments': worker['recent_assignments']
        })

    return render_template(
        'Part_time_employee.html',
        records=filtered_records,
        part_time_workers=part_time_workers,
        setup_error=setup_error,
        search=search,
        selected_client=selected_client,
        client_summaries=client_summaries,
        recent_clients=recent_clients[:6],
        analytics=analytics,
        worker_history=worker_history
    )


@app.route('/part-time/add', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def add_part_time_work():
    uid = get_current_user_id()
    worker_id = request.form.get('worker_id')
    client_name = request.form.get('client_name', '').strip()
    working_date = request.form.get('working_date', '').strip()
    location = request.form.get('location', '').strip()
    
    if not worker_id or not client_name or not working_date or not location:
        return redirect(url_for('part_time'))

    try:
        slab_quantity = int(request.form.get('slab_quantity'))
        slab_price = float(request.form.get('slab_price'))
        if slab_quantity <= 0 or slab_price < 0:
            return redirect(url_for('part_time'))
    except (TypeError, ValueError):
        return redirect(url_for('part_time'))

    total_price = slab_quantity * slab_price

    worker_id_obj = safe_object_id(worker_id)
    if not worker_id_obj:
        return redirect(url_for('part_time'))

    # Verify decoupled worker belongs to this user
    worker = db.part_time_workers.find_one({"_id": worker_id_obj, "user_id": ObjectId(uid)})
    if not worker:
        return redirect(url_for('part_time'))

    log_doc = {
        "worker_id": worker_id_obj,
        "client_name": client_name,
        "working_date": working_date,
        "delivery_location": location,
        "slab_quantity": slab_quantity,
        "slab_price": slab_price,
        "total_price": total_price,
        "advance_paid": 0.0,
        "remaining_balance": total_price,
        "payment_status": "Unpaid",
        "notes": "",
        "created_at": datetime.now().isoformat()
    }
    db.part_time_work_logs.insert_one(log_doc)

    return redirect(url_for('part_time'))


@app.route('/part-time/workers/add', methods=['POST'])
@limiter.limit("20 per minute")
@login_required
def add_part_time_worker():
    uid = get_current_user_id()
    name = request.form.get('name', '').strip()
    if not name:
        return redirect(url_for('part_time'))
    
    db.part_time_workers.insert_one({
        "name": name,
        "user_id": ObjectId(uid),
        "created_at": datetime.now().isoformat()
    })
    return redirect(url_for('part_time'))


# ─────────────────────────────────────────
# SALARY ACTIONS
# ─────────────────────────────────────────

@app.route('/salary/mark_paid', methods=['POST'])
@limiter.limit("30 per minute")         # prevent accidental bulk payment triggers
@login_required
def mark_paid():
    data = request.get_json() or {}
    emp_id = data.get('emp_id')
    month = data.get('month')
    paid_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    emp_id_obj = safe_object_id(emp_id)
    if not emp_id_obj:
        return jsonify({'success': False, 'message': 'Invalid Employee ID'}), 400

    db.salary_records.update_one(
        {"emp_id": emp_id_obj, "month": month},
        {"$set": {"payment_status": "Paid", "paid_at": paid_at}}
    )
    return jsonify({'success': True, 'paid_at': paid_at})


@app.route('/salary/set_advance', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def salary_set_advance():
    data = request.get_json() or {}
    emp_id = data.get('emp_id')
    month = data.get('month')
    advance_amount_paid = data.get('advance_amount_paid')

    emp_id_obj = safe_object_id(emp_id)
    if not emp_id_obj:
        return jsonify({'success': False, 'message': 'Invalid Employee ID'}), 400

    try:
        advance_amount_paid = float(advance_amount_paid)
        if advance_amount_paid < 0:
            return jsonify({'success': False, 'message': 'Advance must be >= 0'}), 400
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Advance must be a number'}), 400

    advance_paid_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    db.salary_records.update_one(
        {"emp_id": emp_id_obj, "month": month, "payment_status": {"$in": ["Unpaid", "Paid"]}},
        {"$set": {
            "advance_amount_paid": advance_amount_paid,
            "advance_paid_at": advance_paid_at
        }}
    )

    # Recalculate net payable from current salary record
    rec = db.salary_records.find_one({"emp_id": emp_id_obj, "month": month})
    earned = rec['total_salary'] if rec else 0
    net_payable = round(earned - advance_amount_paid, 2)

    return jsonify({
        'success': True,
        'advance_amount_paid': advance_amount_paid,
        'advance_paid_at': advance_paid_at,
        'net_payable': net_payable
    })


@app.route('/part-time/set_advance', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def part_time_set_advance():
    data = request.get_json()
    record_id = data.get('record_id')
    advance_amount_paid = data.get('advance_amount_paid')

    try:
        advance_amount_paid = float(advance_amount_paid)
        if advance_amount_paid < 0:
            return jsonify({'success': False, 'message': 'Advance must be >= 0'}), 400
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Advance must be a number'}), 400

    uid = get_current_user_id()
    
    record_id_obj = safe_object_id(record_id)
    if not record_id_obj:
        return jsonify({'success': False, 'message': 'Invalid Record ID'}), 400
        
    # Get record total_price and check ownership
    log_record = db.part_time_work_logs.find_one({"_id": record_id_obj})
    if not log_record:
        return jsonify({'success': False, 'message': 'Record not found'}), 404
        
    worker = db.part_time_workers.find_one({"_id": log_record['worker_id'], "user_id": ObjectId(uid)})
    if not worker:
        return jsonify({'success': False, 'message': 'Record not found'}), 404
        
    total_price = log_record['total_price']
    net_payable = round(total_price - advance_amount_paid, 2)   # can be negative
    remaining_balance = max(net_payable, 0)                     # floored for DB/status
    payment_status = 'Paid' if remaining_balance <= 0 else 'Unpaid'
    
    db.part_time_work_logs.update_one(
        {"_id": record_id_obj},
        {"$set": {
            "advance_paid": advance_amount_paid,
            "remaining_balance": remaining_balance,
            "payment_status": payment_status
        }}
    )

    return jsonify({
        'success': True,
        'advance_amount_paid': advance_amount_paid,
        'net_payable': net_payable,
        'remaining_balance': remaining_balance,
        'payment_status': payment_status
    })


# ─────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────

@app.route('/export')
@limiter.limit("10 per minute")         # CSV export is expensive — cap it
@login_required
def export_data():
    uid = get_current_user_id()

    output = io.StringIO()
    writer = csv.writer(output)

    # === EMPLOYEES ===
    writer.writerow(['=== EMPLOYEES ==='])
    writer.writerow(['ID', 'Name', 'Phone', 'Age', 'Gender',
                    'Monthly Salary', 'Leaves', 'Working Hours/Week'])
    emps = list(db.employees.find({"user_id": ObjectId(uid)}))
    emp_map = {}
    for e in emps:
        emp_id_str = str(e['_id'])
        emp_map[e['_id']] = e.get('name', 'Unknown')
        writer.writerow([
            emp_id_str, e.get('name'), e.get('phone'), e.get('age'),
            e.get('gender'), e.get('salary'), e.get('leaves'), e.get('working_hours')
        ])

    writer.writerow([])

    # === ATTENDANCE ===
    writer.writerow(['=== ATTENDANCE ==='])
    writer.writerow(['Employee ID', 'Employee Name', 'Date', 'Status'])
    emp_ids = list(emp_map.keys())
    attendance_records = list(db.attendance.find({"emp_id": {"$in": emp_ids}}).sort("date", -1))
    for a in attendance_records:
        writer.writerow([
            str(a['emp_id']),
            emp_map.get(a['emp_id'], 'Unknown'),
            a.get('date'),
            a.get('status')
        ])

    writer.writerow([])

    # === SALARY ===
    writer.writerow(['=== SALARY RECORDS ==='])
    writer.writerow(['Employee ID', 'Employee Name', 'Month',
                    'Present Days', 'Total Salary', 'Advance Amount Paid', 'Payment Status', 'Paid At'])
    salary_records = list(db.salary_records.find({"emp_id": {"$in": emp_ids}}).sort("month", -1))
    for s in salary_records:
        writer.writerow([
            str(s['emp_id']),
            emp_map.get(s['emp_id'], 'Unknown'),
            s.get('month'),
            s.get('present_days'),
            s.get('total_salary'),
            s.get('advance_amount_paid'),
            s.get('payment_status'),
            s.get('paid_at')
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'employee_data_{date.today().isoformat()}.csv'
    )


# ─────────────────────────────────────────
# API - CHART DATA
# ─────────────────────────────────────────

@api_v1.route('/chart/attendance')
@limiter.limit("60 per minute")         # chart API called on month change
@login_required
def chart_attendance():
    uid = get_current_user_id()
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))

    emps = list(db.employees.find({"user_id": ObjectId(uid)}))
    labels, present_data, absent_data = [], [], []

    for e in emps:
        emp_id = e['_id']
        p = db.attendance.count_documents({
            "emp_id": emp_id,
            "status": "Present",
            "date": {"$regex": f"^{month}"}
        })
        a = db.attendance.count_documents({
            "emp_id": emp_id,
            "status": "Absent",
            "date": {"$regex": f"^{month}"}
        })
        labels.append(e.get('name', 'Unknown'))
        present_data.append(p)
        absent_data.append(a)

    return jsonify({'labels': labels, 'present': present_data, 'absent': absent_data})


# Register api_v1 blueprint after all its routes are declared
app.register_blueprint(api_v1)


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') == 'development'
    print(f"Starting Employee Management System...")
    print(f"Open: http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
