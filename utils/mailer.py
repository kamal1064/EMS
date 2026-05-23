"""
EMS Mailer Utility
==================
Sends verification and password-reset emails via Gmail SMTP.
Sends both HTML and plain-text parts so email clients don't mangle links.
Falls back to console logging if MAIL_USERNAME is not configured.
"""

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def _smtp_config():
    return {
        'server':   os.environ.get('MAIL_SERVER',    'smtp.gmail.com'),
        'port':     int(os.environ.get('MAIL_PORT',  '587')),
        'username': os.environ.get('MAIL_USERNAME',  ''),
        'password': os.environ.get('MAIL_PASSWORD',  ''),
        'from':     os.environ.get('MAIL_FROM',      ''),
        'name':     os.environ.get('MAIL_FROM_NAME', 'EMS'),
        'base_url': os.environ.get('APP_BASE_URL',   'http://127.0.0.1:5000'),
    }


def _send(to_email: str, subject: str, html_body: str, text_body: str) -> bool:
    cfg = _smtp_config()

    # Always print the link to console for easy local testing
    print(f"\n[EMS MAILER] Sending '{subject}' to {to_email}")

    # Dev fallback — print to console if not configured
    if not cfg['username'] or cfg['username'] == 'your_gmail@gmail.com':
        print(f"  [DEV MODE] SMTP not configured — email NOT sent.")
        print(f"  Plain text:\n{text_body}\n")
        return True

    try:
        # multipart/alternative: email clients pick the best version they support
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = f"{cfg['name']} <{cfg['from']}>"
        msg['To']      = to_email

        # Attach plain text FIRST (fallback), then HTML (preferred)
        msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        msg.attach(MIMEText(html_body, 'html',  'utf-8'))

        with smtplib.SMTP(cfg['server'], cfg['port']) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(cfg['username'], cfg['password'])
            smtp.sendmail(cfg['from'], to_email, msg.as_string())

        print(f"  [OK] Email sent successfully.")
        return True

    except Exception as e:
        print(f"  [ERROR] Failed to send email to {to_email}: {e}")
        return False


def send_verification_email(to_email: str, token: str) -> bool:
    cfg  = _smtp_config()
    link = f"{cfg['base_url']}/verify/{token}"

    print(f"  Verify link: {link}")  # Always visible in terminal

    # ── Plain text version (always works, no link mangling) ──
    text = f"""
EMS - Email Verification
=========================

Hi there!

Thanks for signing up for EMS (Employee Management System).

Please verify your email address by opening this link in your browser:

{link}

This link expires in 24 hours.

If you didn't create an EMS account, please ignore this email.

- EMS Team
"""

    # ── HTML version ─────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; margin: 0; padding: 40px 20px; }}
    .wrap {{ max-width: 520px; margin: 0 auto; }}
    .card {{ background: #111827; border: 1px solid rgba(255,255,255,0.08); border-radius: 20px; overflow: hidden; }}
    .header {{ background: linear-gradient(135deg, #3b82f6, #8b5cf6); padding: 32px; text-align: center; }}
    .header h1 {{ color: #fff; margin: 0; font-size: 22px; font-weight: 800; }}
    .header p  {{ color: rgba(255,255,255,0.8); margin: 6px 0 0; font-size: 13px; }}
    .body {{ padding: 32px; }}
    .body p {{ color: #94a3b8; font-size: 14px; line-height: 1.7; margin: 0 0 16px; }}
    .body strong {{ color: #e2e8f0; }}
    .btn-wrap {{ text-align: center; margin: 28px 0 20px; }}
    .btn {{ display: inline-block; padding: 14px 36px; background: #3b82f6; color: #ffffff !important;
            border-radius: 12px; font-weight: 700; font-size: 15px; text-decoration: none;
            letter-spacing: 0.01em; }}
    .divider {{ border: none; border-top: 1px solid rgba(255,255,255,0.06); margin: 20px 0; }}
    .link-label {{ font-size: 12px; color: #64748b; text-align: center; margin-bottom: 8px; }}
    .link-box {{ background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1);
                 border-radius: 10px; padding: 12px 16px; font-size: 12px; color: #94a3b8;
                 word-break: break-all; font-family: monospace; }}
    .footer {{ padding: 18px 32px; border-top: 1px solid rgba(255,255,255,0.05);
               text-align: center; font-size: 11px; color: #475569; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="header">
        <h1>&#128075; Verify your email</h1>
        <p>Employee Management System</p>
      </div>
      <div class="body">
        <p>Thanks for signing up! Click the button below to verify your email address and activate your EMS account.</p>
        <p>This link will expire in <strong>24 hours</strong>.</p>
        <div class="btn-wrap">
          <a href="{link}" class="btn" target="_blank">&#10003; Verify Email Address</a>
        </div>
        <hr class="divider">
        <p class="link-label">If the button doesn't work, copy and paste this link into your browser:</p>
        <div class="link-box">{link}</div>
      </div>
      <div class="footer">If you didn't create an EMS account, you can safely ignore this email.</div>
    </div>
  </div>
</body>
</html>"""

    return _send(to_email, 'Verify your EMS email address', html, text)


def send_reset_email(to_email: str, token: str) -> bool:
    cfg  = _smtp_config()
    link = f"{cfg['base_url']}/reset-password/{token}"

    print(f"  Reset link: {link}")  # Always visible in terminal

    # ── Plain text version ────────────────────────────────────
    text = f"""
EMS - Password Reset
=====================

Hi there!

We received a request to reset the password for your EMS account.

Open this link in your browser to reset your password:

{link}

This link expires in 1 HOUR. After that you'll need to request a new one.

If you didn't request a password reset, your account is safe — no changes were made.

- EMS Team
"""

    # ── HTML version ──────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; margin: 0; padding: 40px 20px; }}
    .wrap {{ max-width: 520px; margin: 0 auto; }}
    .card {{ background: #111827; border: 1px solid rgba(255,255,255,0.08); border-radius: 20px; overflow: hidden; }}
    .header {{ background: linear-gradient(135deg, #f59e0b, #ef4444); padding: 32px; text-align: center; }}
    .header h1 {{ color: #fff; margin: 0; font-size: 22px; font-weight: 800; }}
    .header p  {{ color: rgba(255,255,255,0.8); margin: 6px 0 0; font-size: 13px; }}
    .body {{ padding: 32px; }}
    .body p {{ color: #94a3b8; font-size: 14px; line-height: 1.7; margin: 0 0 16px; }}
    .body strong {{ color: #e2e8f0; }}
    .warn {{ background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25);
             border-radius: 10px; padding: 12px 16px; font-size: 12px; color: #fca5a5; margin-bottom: 20px; }}
    .btn-wrap {{ text-align: center; margin: 28px 0 20px; }}
    .btn {{ display: inline-block; padding: 14px 36px; background: #f59e0b; color: #000000 !important;
            border-radius: 12px; font-weight: 700; font-size: 15px; text-decoration: none; }}
    .divider {{ border: none; border-top: 1px solid rgba(255,255,255,0.06); margin: 20px 0; }}
    .link-label {{ font-size: 12px; color: #64748b; text-align: center; margin-bottom: 8px; }}
    .link-box {{ background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1);
                 border-radius: 10px; padding: 12px 16px; font-size: 12px; color: #94a3b8;
                 word-break: break-all; font-family: monospace; }}
    .footer {{ padding: 18px 32px; border-top: 1px solid rgba(255,255,255,0.05);
               text-align: center; font-size: 11px; color: #475569; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="header">
        <h1>&#128273; Reset your password</h1>
        <p>Employee Management System</p>
      </div>
      <div class="body">
        <div class="warn">&#9888;&#65039; This link expires in <strong>1 hour</strong>. If you didn't request this, ignore this email — your account is safe.</div>
        <p>We received a request to reset your EMS account password. Click the button below to choose a new password.</p>
        <div class="btn-wrap">
          <a href="{link}" class="btn" target="_blank">Reset My Password</a>
        </div>
        <hr class="divider">
        <p class="link-label">If the button doesn't work, copy and paste this link into your browser:</p>
        <div class="link-box">{link}</div>
      </div>
      <div class="footer">If you didn't request a password reset, your account is safe — no changes were made.</div>
    </div>
  </div>
</body>
</html>"""

    return _send(to_email, 'Reset your EMS password', html, text)
