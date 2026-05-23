"""
Employee Management System - Flask Backend (SQLite)
===================================================
Run with: python app.py
"""

# Load .env FIRST so all os.environ.get() calls throughout the app read correct values
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional; env vars may be set by the OS/host

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import hashlib
import secrets
import os
import csv
import io
import calendar
from datetime import datetime, date, timedelta
from functools import wraps
import pyotp
import qrcode
import base64
from io import BytesIO
from utils.mailer import send_verification_email, send_reset_email

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'emp_mgmt_secret_key_2024_change_in_prod')


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
# DATABASE SETUP
# ─────────────────────────────────────────

def get_db():
    """Connect to SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allows dict-like access
    return conn


def init_db():
    """Create all tables if they don't exist and perform migrations."""
    conn = get_db()
    c = conn.cursor()

    # Users table (owners/admins)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            otp_secret TEXT,
            otp_enabled BOOLEAN DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add auth columns to existing users table (safe migrations)
    for col_def in [
        ('otp_secret',         'TEXT'),
        ('otp_enabled',        'BOOLEAN DEFAULT 0'),
        ('is_verified',        'BOOLEAN DEFAULT 1'),   # default 1 so existing accounts stay valid
        ('verify_token',       'TEXT'),
        ('reset_token',        'TEXT'),
        ('reset_token_expiry', 'TEXT'),
    ]:
        try:
            c.execute(f'ALTER TABLE users ADD COLUMN {col_def[0]} {col_def[1]}')
        except sqlite3.OperationalError:
            pass  # column already exists

    # Employees table
    c.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT,
            age INTEGER,
            gender TEXT,
            salary REAL,
            leaves INTEGER DEFAULT 0,
            working_hours REAL DEFAULT 40,
            user_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Attendance table
    c.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL,
            UNIQUE(emp_id, date),
            FOREIGN KEY (emp_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    ''')

    # Salary records table
    c.execute('''
        CREATE TABLE IF NOT EXISTS salary_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id INTEGER NOT NULL,
            month TEXT NOT NULL,
            present_days INTEGER DEFAULT 0,
            total_salary REAL DEFAULT 0,
            advance_amount_paid REAL DEFAULT 0,
            advance_paid_at TEXT,
            payment_status TEXT DEFAULT 'Unpaid',
            paid_at TEXT,
            FOREIGN KEY (emp_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    ''')

    # Ensure advance columns exist in salary_records for older databases
    try:
        c.execute('ALTER TABLE salary_records ADD COLUMN advance_amount_paid REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass

    try:
        c.execute('ALTER TABLE salary_records ADD COLUMN advance_paid_at TEXT')
    except sqlite3.OperationalError:
        pass

    # Part-time workers table (completely decoupled from salaried employees)
    c.execute('''
        CREATE TABLE IF NOT EXISTS part_time_workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            user_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Part-time work logs table (linked to part_time_workers)
    c.execute('''
        CREATE TABLE IF NOT EXISTS part_time_work_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            worker_id INTEGER NOT NULL,
            client_name TEXT NOT NULL,
            working_date TEXT NOT NULL,
            slab_quantity INTEGER NOT NULL,
            slab_price REAL NOT NULL,
            total_price REAL NOT NULL,
            delivery_location TEXT NOT NULL,
            advance_paid REAL DEFAULT 0,
            payment_status TEXT DEFAULT 'Unpaid',
            remaining_balance REAL DEFAULT 0,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (worker_id) REFERENCES part_time_workers(id) ON DELETE CASCADE
        )
    ''')

    # Legacy part_time_employee table retained for migrations
    c.execute('''
        CREATE TABLE IF NOT EXISTS part_time_employee (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_name TEXT NOT NULL,
            working_date TEXT NOT NULL,
            slab_quantity INTEGER NOT NULL,
            slab_price REAL NOT NULL,
            total_price REAL NOT NULL,
            delivery_location TEXT NOT NULL,
            user_id INTEGER,
            advance_amount_paid REAL DEFAULT 0,
            advance_paid_at TEXT
        )
    ''')

    # Migration from employees/logs to decoupled part_time_workers table
    try:
        c.execute("SELECT COUNT(*) FROM part_time_workers")
        pt_workers_count = c.fetchone()[0]
        if pt_workers_count == 0:
            c.execute("SELECT * FROM part_time_work_logs")
            logs = c.fetchall()
            for log in logs:
                old_worker_id = log['worker_id']
                log_id = log['id']
                
                # Fetch employee name & user ID from salaried roster
                c.execute("SELECT name, user_id FROM employees WHERE id = ?", (old_worker_id,))
                emp_row = c.fetchone()
                if emp_row:
                    emp_name = emp_row['name']
                    user_id = emp_row['user_id']
                    
                    # See if this worker already exists in part_time_workers
                    c.execute("SELECT id FROM part_time_workers WHERE name = ? AND user_id = ? LIMIT 1", (emp_name, user_id))
                    pw_row = c.fetchone()
                    if pw_row:
                        new_worker_id = pw_row['id']
                    else:
                        c.execute("INSERT INTO part_time_workers (name, user_id) VALUES (?, ?)", (emp_name, user_id))
                        new_worker_id = c.lastrowid
                    
                    # Point log to the decoupled table
                    c.execute("UPDATE part_time_work_logs SET worker_id = ? WHERE id = ?", (new_worker_id, log_id))
    except Exception as e:
        print(f"Decoupled migration error: {e}")

    # Migration from legacy part_time_employee to modern part_time_work_logs
    try:
        c.execute("SELECT COUNT(*) FROM part_time_work_logs")
        logs_count = c.fetchone()[0]
        if logs_count == 0:
            c.execute("SELECT * FROM part_time_employee")
            old_rows = c.fetchall()
            if old_rows:
                for row in old_rows:
                    emp_name = row['employee_name']
                    user_id = row['user_id']
                    
                    # Try to find employee with similar name
                    c.execute("SELECT id FROM part_time_workers WHERE name = ? AND user_id = ? LIMIT 1", (emp_name, user_id))
                    emp_row = c.fetchone()
                    worker_id = emp_row['id'] if emp_row else None
                    
                    if not worker_id:
                        # Create a matching employee if none exists
                        c.execute("INSERT INTO part_time_workers (name, user_id) VALUES (?, ?)", (emp_name, user_id))
                        worker_id = c.lastrowid
                    
                    c.execute("""
                        INSERT INTO part_time_work_logs 
                        (worker_id, client_name, working_date, slab_quantity, slab_price, total_price, delivery_location, advance_paid, remaining_balance, payment_status)
                        VALUES (?, 'Unassigned', ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        worker_id,
                        row['working_date'],
                        row['slab_quantity'],
                        row['slab_price'],
                        row['total_price'],
                        row['delivery_location'],
                        row['advance_amount_paid'] or 0,
                        max(row['total_price'] - (row['advance_amount_paid'] or 0), 0),
                        'Paid' if (row['advance_amount_paid'] or 0) >= row['total_price'] else 'Unpaid'
                    ))
    except Exception as e:
        print(f"Legacy migration error: {e}")

    conn.commit()
    conn.close()


# Initialize database schema at import time
try:
    init_db()
except Exception as e:
    print(f"Import time init_db error: {e}")
    pass


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    """Decorator to protect routes that need login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user_id():
    return session.get('user_id')


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

        verify_token = secrets.token_urlsafe(32)
        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (username, email, password, is_verified, verify_token) VALUES (?, ?, ?, 0, ?)',
                (email.split('@')[0], email, hash_password(password), verify_token)
            )
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('signup.html', error='An account with this email already exists.')

        send_verification_email(email, verify_token)
        return render_template('signup.html', sent=True, email=email)

    return render_template('signup.html')


@app.route('/verify/<token>')
def verify_email(token):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE verify_token = ? AND is_verified = 0', (token,)
    ).fetchone()
    if not user:
        conn.close()
        return render_template('verify_email.html', status='invalid')
    conn.execute(
        'UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = ?', (user['id'],)
    )
    conn.commit()
    conn.close()
    return render_template('verify_email.html', status='success')


@app.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per hour")
def resend_verification():
    email = request.form.get('email', '').strip().lower()
    if not email:
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE email = ? AND is_verified = 0', (email,)
    ).fetchone()
    if user:
        new_token = secrets.token_urlsafe(32)
        conn.execute('UPDATE users SET verify_token = ? WHERE id = ?', (new_token, user['id']))
        conn.commit()
        send_verification_email(email, new_token)
    conn.close()
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

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND password = ?',
            (email, hash_password(password))
        ).fetchone()
        conn.close()

        if not user:
            return render_template('login.html', error='Invalid email or password.')

        # Block unverified users
        if not user['is_verified']:
            return render_template('login.html',
                error='Please verify your email before logging in.',
                unverified_email=email)

        session['user_id']  = user['id']
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
            conn = get_db()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user:
                token  = secrets.token_urlsafe(32)
                expiry = (datetime.utcnow() + timedelta(hours=1)).isoformat()
                conn.execute(
                    'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
                    (token, expiry, user['id'])
                )
                conn.commit()
                send_reset_email(email, token)
            conn.close()
        # Always show success (prevents user enumeration)
        return render_template('forgot_password.html', sent=True, email=email)
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE reset_token = ?', (token,)
    ).fetchone()

    # Token not found
    if not user:
        conn.close()
        return render_template('reset_password.html', status='invalid')

    # Token expired
    if user['reset_token_expiry']:
        try:
            expiry = datetime.fromisoformat(user['reset_token_expiry'])
            if datetime.utcnow() > expiry:
                conn.close()
                return render_template('reset_password.html', status='expired')
        except ValueError:
            conn.close()
            return render_template('reset_password.html', status='invalid')

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        if len(password) < 8:
            conn.close()
            return render_template('reset_password.html', status='form', token=token,
                                   error='Password must be at least 8 characters.')
        if password != confirm:
            conn.close()
            return render_template('reset_password.html', status='form', token=token,
                                   error='Passwords do not match.')
        conn.execute(
            'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            (hash_password(password), user['id'])
        )
        conn.commit()
        conn.close()
        return render_template('reset_password.html', status='success')

    # GET — show the form
    conn.close()
    return render_template('reset_password.html', status='form', token=token)




@app.route('/api/profile-info')
@login_required
def api_profile_info():
    """Return current user info as JSON for the profile popup."""
    conn = get_db()
    user = conn.execute('SELECT id, username, email FROM users WHERE id = ?',
                        (session['user_id'],)).fetchone()
    conn.close()
    return jsonify({
        'username':   user['username'] if user else session.get('username', ''),
        'email':      user['email']    if user else '',
        'last_login': session.get('last_login', 'Unknown'),
    })


@app.route('/api/change-password', methods=['POST'])
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

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ? AND password = ?',
        (session['user_id'], hash_password(current_pw))
    ).fetchone()
    if not user:
        conn.close()
        return jsonify({'ok': False, 'error': 'Current password is incorrect.'}), 403

    conn.execute('UPDATE users SET password = ? WHERE id = ?',
                 (hash_password(new_pw), session['user_id']))
    conn.commit()
    conn.close()
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
    conn = get_db()

    # Employees
    employees = [dict(r) for r in conn.execute('SELECT * FROM employees WHERE user_id = ?', (uid,)).fetchall()]
    total_emp = len(employees)
    avg_salary = round(sum(e['salary'] for e in employees) / total_emp, 2) if total_emp else 0
    avg_age = round(sum(e['age'] for e in employees) / total_emp, 1) if total_emp else 0
    total_hrs = sum(e['working_hours'] for e in employees)

    # Attendance summary
    emp_ids = [e['id'] for e in employees]
    present_count = 0
    absent_count = 0
    if emp_ids:
        placeholders = ','.join('?' for _ in emp_ids)
        att_rows = conn.execute(f'SELECT status, COUNT(*) as cnt FROM attendance WHERE emp_id IN ({placeholders}) GROUP BY status', emp_ids).fetchall()
        for row in att_rows:
            if row['status'] == 'Present':
                present_count = row['cnt']
            elif row['status'] == 'Absent':
                absent_count = row['cnt']

    # Salary distribution for chart
    salary_data = [{'name': e['name'], 'salary': e['salary']} for e in employees]

    # Recent attendance (last 10 records)
    recent_att = []
    if emp_ids:
        placeholders = ','.join('?' for _ in emp_ids)
        recent_rows = conn.execute(f'''
            SELECT a.date, a.status, e.name FROM attendance a
            JOIN employees e ON e.id = a.emp_id
            WHERE a.emp_id IN ({placeholders})
            ORDER BY a.date DESC LIMIT 10
        ''', emp_ids).fetchall()
        for row in recent_rows:
            recent_att.append({
                'name': row['name'],
                'date': row['date'],
                'status': row['status']
            })

    conn.close()
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
    conn = get_db()

    if search:
        emps = [dict(r) for r in conn.execute(
            'SELECT * FROM employees WHERE user_id = ? AND name LIKE ? ORDER BY name',
            (uid, f'%{search}%')
        ).fetchall()]
    else:
        emps = [dict(r) for r in conn.execute(
            'SELECT * FROM employees WHERE user_id = ? ORDER BY name', (uid,)
        ).fetchall()]

    conn.close()
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

    try:
        salary = float(request.form.get('salary') or 0)
    except (TypeError, ValueError):
        salary = 0

    try:
        leaves = int(request.form.get('leaves') or 0)
    except (TypeError, ValueError):
        leaves = 0

    try:
        hours = float(request.form.get('working_hours') or 40)
    except (TypeError, ValueError):
        hours = 40

    conn = get_db()
    conn.execute(
        'INSERT INTO employees (name, phone, age, gender, salary, leaves, working_hours, user_id) VALUES (?,?,?,?,?,?,?,?)',
        (name, phone, age, gender, salary, leaves, hours, uid)
    )
    conn.commit()
    conn.close()

    redirect_to = request.form.get('redirect_to')
    if redirect_to == 'part_time':
        return redirect(url_for('part_time'))
    return redirect(url_for('employees'))


@app.route('/employees/edit/<int:emp_id>', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
@login_required
def edit_employee(emp_id):
    uid = get_current_user_id()
    conn = get_db()

    if request.method == 'POST':
        conn.execute('''
            UPDATE employees SET name=?, phone=?, age=?, gender=?, salary=?, leaves=?, working_hours=?
            WHERE id=? AND user_id=?
        ''', (
            request.form.get('name'),
            request.form.get('phone'),
            int(request.form.get('age', 0)),
            request.form.get('gender'),
            float(request.form.get('salary', 0)),
            int(request.form.get('leaves', 0)),
            float(request.form.get('working_hours', 40)),
            emp_id, uid
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('employees'))

    emp = conn.execute('SELECT * FROM employees WHERE id=? AND user_id=?', (emp_id, uid)).fetchone()
    conn.close()
    if not emp:
        return redirect(url_for('employees'))
    return render_template('edit_employee.html', emp=emp)


@app.route('/employees/delete/<int:emp_id>', methods=['POST'])
@limiter.limit("20 per minute")         # prevent rapid deletion attacks
@login_required
def delete_employee(emp_id):
    uid = get_current_user_id()
    conn = get_db()
    conn.execute('DELETE FROM attendance WHERE emp_id=?', (emp_id,))
    conn.execute('DELETE FROM salary_records WHERE emp_id=?', (emp_id,))
    conn.execute('DELETE FROM employees WHERE id=? AND user_id=?', (emp_id, uid))
    conn.commit()
    conn.close()
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
    conn = get_db()

    emps = [dict(r) for r in conn.execute('SELECT * FROM employees WHERE user_id=? ORDER BY name', (uid,)).fetchall()]
    att_map = {e['id']: 'Present' for e in emps}

    if emps:
        emp_ids = [e['id'] for e in emps]
        placeholders = ','.join('?' for _ in emp_ids)
        query = f'SELECT emp_id, status FROM attendance WHERE date=? AND emp_id IN ({placeholders})'
        records = conn.execute(query, [selected_date] + emp_ids).fetchall()
        for r in records:
            att_map[r['emp_id']] = r['status']

    conn.close()
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

    conn = get_db()
    try:
        if status == 'Present':
            conn.execute('DELETE FROM attendance WHERE emp_id=? AND date=?', (emp_id, att_date))
        else:
            conn.execute('''
                INSERT INTO attendance (emp_id, date, status)
                VALUES (?, ?, ?)
                ON CONFLICT(emp_id, date)
                DO UPDATE SET status=excluded.status
            ''', (emp_id, att_date, status))
        conn.commit()
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()


@app.route('/attendance/summary')
@limiter.limit("60 per minute")
@login_required
def attendance_summary():
    uid = get_current_user_id()
    month_filter = request.args.get('month', datetime.now().strftime('%Y-%m'))
    conn = get_db()

    emps = [dict(r) for r in conn.execute('SELECT * FROM employees WHERE user_id=? ORDER BY name', (uid,)).fetchall()]
    
    year, month_num = map(int, month_filter.split('-'))
    total_days = calendar.monthrange(year, month_num)[1]

    summary = []
    for e in emps:
        row = conn.execute('''
            SELECT COUNT(*) as cnt FROM attendance
            WHERE emp_id=? AND status='Absent' AND date LIKE ?
        ''', (e['id'], f'{month_filter}%')).fetchone()
        absent_days = row['cnt'] if row else 0
        present_days = total_days - absent_days
        summary.append({
            'name': e['name'],
            'present': present_days,
            'absent': absent_days,
            'total': total_days
        })

    conn.close()
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
    conn = get_db()

    emps = [dict(r) for r in conn.execute('SELECT * FROM employees WHERE user_id=? ORDER BY name', (uid,)).fetchall()]
    
    year, month_num = map(int, month_filter.split('-'))
    total_days = calendar.monthrange(year, month_num)[1]

    salary_details = []
    for e in emps:
        row = conn.execute('''
            SELECT COUNT(*) as cnt FROM attendance
            WHERE emp_id=? AND status='Absent' AND date LIKE ?
        ''', (e['id'], f'{month_filter}%')).fetchone()
        absent_days = row['cnt'] if row else 0
        present_days = total_days - absent_days

        salary_per_day = e['salary'] / total_days
        final_salary = round(salary_per_day * present_days, 2)

        # Check existing record
        rec = conn.execute('SELECT * FROM salary_records WHERE emp_id=? AND month=?', (e['id'], month_filter)).fetchone()

        if not rec:
            conn.execute('''
                INSERT INTO salary_records (emp_id, month, present_days, total_salary, payment_status)
                VALUES (?, ?, ?, ?, 'Unpaid')
            ''', (e['id'], month_filter, present_days, final_salary))
            conn.commit()
            
            payment_status = 'Unpaid'
            paid_at = None
            advance_amount_paid = 0
            advance_paid_at = None
        else:
            if rec['payment_status'] == 'Unpaid':
                conn.execute('''
                    UPDATE salary_records
                    SET present_days=?, total_salary=?
                    WHERE emp_id=? AND month=? AND payment_status='Unpaid'
                ''', (present_days, final_salary, e['id'], month_filter))
                conn.commit()
            
            payment_status = rec['payment_status']
            paid_at = rec['paid_at']
            advance_amount_paid = rec['advance_amount_paid'] or 0
            advance_paid_at = rec['advance_paid_at']

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

    conn.close()
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
    
    conn = get_db()
    setup_error = None
    
    # Get decoupled part-time workers for the dropdown
    part_time_workers = [dict(r) for r in conn.execute(
        'SELECT id, name FROM part_time_workers WHERE user_id = ? ORDER BY name', (uid,)
    ).fetchall()]
    
    # Get part-time logs joined with part_time_workers
    records = [dict(r) for r in conn.execute('''
        SELECT r.*, w.name as worker_name FROM part_time_work_logs r
        JOIN part_time_workers w ON w.id = r.worker_id
        WHERE w.user_id = ?
        ORDER BY r.id DESC
    ''', (uid,)).fetchall()]
        
    conn.close()

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

    conn = get_db()
    # Verify decoupled worker belongs to this user
    worker = conn.execute('SELECT id FROM part_time_workers WHERE id = ? AND user_id = ?', (worker_id, uid)).fetchone()
    if not worker:
        conn.close()
        return redirect(url_for('part_time'))

    conn.execute('''
        INSERT INTO part_time_work_logs
        (worker_id, client_name, working_date, delivery_location, slab_quantity, slab_price, total_price, advance_paid, remaining_balance, payment_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'Unpaid')
    ''', (worker_id, client_name, working_date, location, slab_quantity, slab_price, total_price, total_price))
    
    conn.commit()
    conn.close()

    return redirect(url_for('part_time'))


@app.route('/part-time/workers/add', methods=['POST'])
@limiter.limit("20 per minute")
@login_required
def add_part_time_worker():
    uid = get_current_user_id()
    name = request.form.get('name', '').strip()
    if not name:
        return redirect(url_for('part_time'))
    
    conn = get_db()
    conn.execute('INSERT INTO part_time_workers (name, user_id) VALUES (?, ?)', (name, uid))
    conn.commit()
    conn.close()
    return redirect(url_for('part_time'))


# ─────────────────────────────────────────
# SALARY ACTIONS
# ─────────────────────────────────────────

@app.route('/salary/mark_paid', methods=['POST'])
@limiter.limit("30 per minute")         # prevent accidental bulk payment triggers
@login_required
def mark_paid():
    data = request.get_json()
    emp_id = data.get('emp_id')
    month = data.get('month')
    paid_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db()
    conn.execute('''
        UPDATE salary_records SET payment_status='Paid', paid_at=?
        WHERE emp_id=? AND month=?
    ''', (paid_at, emp_id, month))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'paid_at': paid_at})


@app.route('/salary/set_advance', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def salary_set_advance():
    data = request.get_json()
    emp_id = data.get('emp_id')
    month = data.get('month')
    advance_amount_paid = data.get('advance_amount_paid')

    try:
        advance_amount_paid = float(advance_amount_paid)
        if advance_amount_paid < 0:
            return jsonify({'success': False, 'message': 'Advance must be >= 0'}), 400
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Advance must be a number'}), 400

    advance_paid_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db()
    conn.execute('''
        UPDATE salary_records
        SET advance_amount_paid=?,
            advance_paid_at=?
        WHERE emp_id=? AND month=? AND payment_status IN ('Unpaid','Paid')
    ''', (advance_amount_paid, advance_paid_at, emp_id, month))
    conn.commit()
    conn.close()

    # Recalculate net payable from current salary record
    conn2 = get_db()
    rec = conn2.execute('SELECT total_salary FROM salary_records WHERE emp_id=? AND month=?', (emp_id, month)).fetchone()
    conn2.close()
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
    conn = get_db()
    
    # Get record total_price and check ownership
    record = conn.execute('''
        SELECT r.total_price, e.user_id FROM part_time_work_logs r
        JOIN part_time_workers e ON e.id = r.worker_id
        WHERE r.id = ? AND e.user_id = ?
    ''', (record_id, uid)).fetchone()
    
    if not record:
        conn.close()
        return jsonify({'success': False, 'message': 'Record not found'}), 404
        
    total_price = record['total_price']
    net_payable = round(total_price - advance_amount_paid, 2)   # can be negative
    remaining_balance = max(net_payable, 0)                     # floored for DB/status
    payment_status = 'Paid' if remaining_balance <= 0 else 'Unpaid'
    
    conn.execute('''
        UPDATE part_time_work_logs
        SET advance_paid = ?,
            remaining_balance = ?,
            payment_status = ?
        WHERE id = ?
    ''', (advance_amount_paid, remaining_balance, payment_status, record_id))
    
    conn.commit()
    conn.close()

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
    conn = get_db()

    output = io.StringIO()
    writer = csv.writer(output)

    # === EMPLOYEES ===
    writer.writerow(['=== EMPLOYEES ==='])
    writer.writerow(['ID', 'Name', 'Phone', 'Age', 'Gender',
                    'Monthly Salary', 'Leaves', 'Working Hours/Week'])
    emps = conn.execute(
        'SELECT * FROM employees WHERE user_id=?', (uid,)).fetchall()
    for e in emps:
        writer.writerow([e['id'], e['name'], e['phone'], e['age'],
                        e['gender'], e['salary'], e['leaves'], e['working_hours']])

    writer.writerow([])

    # === ATTENDANCE ===
    writer.writerow(['=== ATTENDANCE ==='])
    writer.writerow(['Employee ID', 'Employee Name', 'Date', 'Status'])
    att = conn.execute('''
        SELECT a.emp_id, e.name, a.date, a.status FROM attendance a
        JOIN employees e ON e.id = a.emp_id
        WHERE e.user_id=?
        ORDER BY a.date DESC
    ''', (uid,)).fetchall()
    for a in att:
        writer.writerow([a['emp_id'], a['name'], a['date'], a['status']])

    writer.writerow([])

    # === SALARY ===
    writer.writerow(['=== SALARY RECORDS ==='])
    writer.writerow(['Employee ID', 'Employee Name', 'Month',
                    'Present Days', 'Total Salary', 'Advance Amount Paid', 'Payment Status', 'Paid At'])
    sal = conn.execute('''
        SELECT s.emp_id, e.name, s.month, s.present_days, s.total_salary, s.advance_amount_paid, s.payment_status, s.paid_at
        FROM salary_records s
        JOIN employees e ON e.id = s.emp_id
        WHERE e.user_id=?
        ORDER BY s.month DESC
    ''', (uid,)).fetchall()
    for s in sal:
        writer.writerow([s['emp_id'], s['name'], s['month'], s['present_days'],
                        s['total_salary'], s['advance_amount_paid'], s['payment_status'], s['paid_at']])

    conn.close()

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

@app.route('/api/chart/attendance')
@limiter.limit("60 per minute")         # chart API called on month change
@login_required
def chart_attendance():
    uid = get_current_user_id()
    month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    conn = get_db()

    emps = conn.execute(
        'SELECT id, name FROM employees WHERE user_id=?', (uid,)).fetchall()
    labels, present_data, absent_data = [], [], []

    for e in emps:
        p = conn.execute(
            "SELECT COUNT(*) as c FROM attendance WHERE emp_id=? AND date LIKE ? AND status='Present'",
            (e['id'], f'{month}%')
        ).fetchone()['c']
        a = conn.execute(
            "SELECT COUNT(*) as c FROM attendance WHERE emp_id=? AND date LIKE ? AND status='Absent'",
            (e['id'], f'{month}%')
        ).fetchone()['c']
        labels.append(e['name'])
        present_data.append(p)
        absent_data.append(a)

    conn.close()
    return jsonify({'labels': labels, 'present': present_data, 'absent': absent_data})


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') == 'development'
    print(f"Starting Employee Management System...")
    print(f"Open: http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
