#!/usr/bin/env python3
"""
EdgeIQ PhishSim — Core Flask Application

Handles:
- Campaign management (create, schedule, launch)
- Template management
- Email sending via SMTP (Mailgun)
- Click/open tracking (pixel + link tracking)
- Credential capture landing pages
- Training assignment dispatch
"""
import os, json, uuid, smtplib, ssl, requests as http_requests
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from flask import Flask, request, jsonify, redirect, make_response, send_file
from markupsafe import escape
import hashlib

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# ─── Config ───────────────────────────────────────────────────────────────
SMTP_HOST    = os.environ.get('SMTP_HOST', 'smtp.mailgun.org')
SMTP_PORT    = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER    = os.environ.get('SMTP_USER', '')
SMTP_PASS    = os.environ.get('SMTP_PASS', '')
SENDING_DOMAIN = os.environ.get('SENDING_DOMAIN', 'simulate.edgeiqlabs.com')
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', '')
MAILGUN_API_URL = f'https://api.mailgun.net/v3/{SENDING_DOMAIN}/messages'
FROM_NAME    = os.environ.get('FROM_NAME', 'EdgeIQ Security')
FROM_NAME    = os.environ.get('FROM_NAME', 'EdgeIQ Security')
APP_URL      = os.environ.get('APP_URL', 'https://simulate.edgeiqlabs.com')

# In-memory store (MVP — replace with PostgreSQL for production)
# Format: { campaign_id: { ... }, target_id: { ... }, ... }
_store = {
    "campaigns": {},
    "targets": {},
    "templates": {},
    "campaign_sends": {},
    "training_assignments": {},
}

# ─── Helpers ────────────────────────────────────────────────────────────────

def _gen_id():
    return uuid.uuid4().hex[:16]

def _now():
    return datetime.utcnow().isoformat()

def _send_email(to_email, subject, html_body, tracking_pixel_id=None):
    """Send email via Mailgun HTTP API. Returns (success, error_detail)."""
    if not MAILGUN_API_KEY:
        detail = 'MAILGUN_API_KEY missing'
        print(f"[DEBUG] Mailgun not configured — would send to {to_email}: {subject} | {detail}")
        return True, detail

    # Add tracking pixel
    if tracking_pixel_id:
        pixel_url = f"{APP_URL}/track/open/{tracking_pixel_id}"
        pixel_html = f'<img src="{pixel_url}" width="1" height="1" style="display:none" />'
        html_body = pixel_html + html_body

    try:
        resp = http_requests.post(
            MAILGUN_API_URL,
            auth=('api', MAILGUN_API_KEY),
            data={
                'from': f"{FROM_NAME} <noreply@{SENDING_DOMAIN}>",
                'to': to_email,
                'subject': subject,
                'html': html_body,
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            print(f"[DEBUG] Mailgun send OK to {to_email}: {resp.status_code}")
            return True, None
        else:
            detail = f"status={resp.status_code} {resp.text[:200]}"
            print(f"[ERROR] Mailgun send failed: {detail}")
            return False, detail
    except Exception as e:
        detail = f"{type(e).__name__}: {e}"
        print(f"[ERROR] Mailgun send exception: {detail}")
        return False, detail

def _render_template(template_html, template_vars):
    """Simple variable substitution: {{variable_name}}"""
    result = template_html
    for key, value in template_vars.items():
        result = result.replace(f"{{{{{key}}}}}", str(value))
    return result

def _substitute_target_vars(html, target):
    """Substitute per-target variables in email body."""
    defaults = {
        "first_name": target.get('first_name', 'there'),
        "last_name": target.get('last_name', ''),
        "email": target.get('email', ''),
        "department": target.get('department', ''),
        "company": target.get('company', 'your organization'),
        "title": target.get('title', ''),
    }
    return _render_template(html, defaults)

# ─── CORS ─────────────────────────────────────────────────────────────────

@app.after_request
def cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# ─── Health ────────────────────────────────────────────────────────────────


# ─── SMTP Debug ─────────────────────────────────────────────────────────────
@app.route('/api/debug/smtp-test', methods=['POST'])
def smtp_debug_test():
    """Direct SMTP connectivity test."""
    import smtplib, ssl, socket
    result = {
        'smtp_host': SMTP_HOST,
        'smtp_port': SMTP_PORT,
        'sending_domain': SENDING_DOMAIN,
        'smtp_user_set': bool(SMTP_USER),
        'smtp_pass_set': bool(SMTP_PASS),
        'connect_ok': None,
        'connect_error': None,
        'tls_ok': None,
        'login_ok': None,
        'login_error': None,
    }
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            result['connect_ok'] = True
            try:
                server.starttls(context=context, timeout=10)
                result['tls_ok'] = True
            except Exception as e:
                result['tls_ok'] = str(e)
            try:
                server.login(SMTP_USER, SMTP_PASS, timeout=10)
                result['login_ok'] = True
            except Exception as e:
                result['login_error'] = str(e)
    except Exception as e:
        result['connect_ok'] = False
        result['connect_error'] = str(e)
    return jsonify(result)

\n@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'edgeiq-phishsim', 'version': '1.0.0'})

# ─── Template Management ──────────────────────────────────────────────────

@app.route('/api/templates', methods=['GET'])
def list_templates():
    """List all phishing templates."""
    return jsonify({'templates': list(_store['templates'].values())})

@app.route('/api/templates', methods=['POST'])
def create_template():
    """Create a new phishing template."""
    data = request.json
    tid = _gen_id()
    template = {
        'id': tid,
        'name': data.get('name', 'Untitled'),
        'category': data.get('category', 'general'),
        'difficulty': data.get('difficulty', 'easy'),  # easy, medium, hard
        'subject': data.get('subject', ''),
        'html_body': data.get('html_body', ''),
        'landing_page_id': data.get('landing_page_id', ''),
        'credential_field': data.get('credential_field', 'password'),  # what to capture
        'created_at': _now(),
    }
    _store['templates'][tid] = template
    return jsonify(template), 201

@app.route('/api/templates/<tid>', methods=['GET'])
def get_template(tid):
    t = _store['templates'].get(tid)
    if not t:
        return jsonify({'error': 'Template not found'}), 404
    return jsonify(t)

# ─── Landing Pages ────────────────────────────────────────────────────────

@app.route('/lp/<template_id>/<tracking_id>', methods=['GET'])
def landing_page(template_id, tracking_id):
    """Serve credential harvest landing page."""
    template = _store['templates'].get(template_id)
    if not template:
        return "Template not found", 404

    lp_id = template.get('landing_page_id')
    lp_html = LANDING_PAGES.get(lp_id, LANDING_PAGES.get('microsoft_365'))

    # Update click tracking
    for send_id, send in _store['campaign_sends'].items():
        if send.get('tracking_id') == tracking_id:
            if not send.get('clicked_at'):
                send['clicked_at'] = _now()
            break

    resp = make_response(lp_html)
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.route('/api/capture', methods=['POST'])
def capture_credentials():
    """Record submitted credentials from landing page."""
    data = request.json
    tracking_id = data.get('tracking_id', '').strip()
    username = data.get('username', '')
    password = data.get('password', '')
    template_id = data.get('template_id', '')

    if not tracking_id:
        return jsonify({'error': 'tracking_id required'}), 400

    # Find the send record
    send_record = None
    for sid, send in _store['campaign_sends'].items():
        if send.get('tracking_id') == tracking_id:
            send_record = send
            send_record['submitted_at'] = _now()
            send_record['captured_username'] = username[:100]
            send_record['captured_password_hash'] = hashlib.sha256(password.encode()).hexdigest()[:32]
            break

    if not send_record:
        return jsonify({'error': 'Invalid tracking ID'}), 404

    # Trigger training assignment (async in production — for MVP just mark it)
    _assign_training(send_record)

    # Return "success" — the fake login "worked"
    return jsonify({
        'success': True,
        'message': 'Verification successful. You will receive training if required.'
    })

# ─── Campaign Management ──────────────────────────────────────────────────

@app.route('/api/campaigns', methods=['GET'])
def list_campaigns():
    return jsonify({'campaigns': list(_store['campaigns'].values())})

@app.route('/api/campaigns', methods=['POST'])
def create_campaign():
    """Create a campaign. Does NOT launch yet."""
    data = request.json
    cid = _gen_id()
    campaign = {
        'id': cid,
        'name': data.get('name', 'Untitled Campaign'),
        'template_id': data.get('template_id', ''),
        'target_group_id': data.get('target_group_id', ''),
        'status': 'draft',  # draft, scheduled, running, completed, aborted
        'scheduled_at': data.get('scheduled_at'),  # ISO timestamp or None
        'target_ids': data.get('target_ids', []),
        'created_at': _now(),
    }
    _store['campaigns'][cid] = campaign
    return jsonify(campaign), 201

@app.route('/api/campaigns/<cid>', methods=['GET'])
def get_campaign(cid):
    c = _store['campaigns'].get(cid)
    if not c:
        return jsonify({'error': 'Campaign not found'}), 404

    # Enrich with send stats
    sends = [s for s in _store['campaign_sends'].values() if s.get('campaign_id') == cid]
    stats = {
        'total': len(sends),
        'sent': sum(1 for s in sends if s.get('sent_at')),
        'opened': sum(1 for s in sends if s.get('opened_at')),
        'clicked': sum(1 for s in sends if s.get('clicked_at')),
        'submitted': sum(1 for s in sends if s.get('submitted_at')),
    }
    return jsonify({**c, 'stats': stats})

@app.route('/api/campaigns/<cid>/launch', methods=['POST'])
def launch_campaign(cid):
    """Send phishing emails to all campaign targets immediately."""
    campaign = _store['campaigns'].get(cid)
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    if campaign['status'] in ('running', 'completed'):
        return jsonify({'error': f"Cannot launch — campaign is {campaign['status']}"}), 400

    template = _store['templates'].get(campaign['template_id'])
    if not template:
        return jsonify({'error': 'Template not found'}), 404

    campaign['status'] = 'running'
    sent = 0
    failed = 0

    for target_id in campaign['target_ids']:
        target = _store['targets'].get(target_id)
        if not target or not target.get('active', True):
            continue

        tracking_id = _gen_id()
        send_id = _gen_id()

        # Create send record
        send_record = {
            'id': send_id,
            'campaign_id': cid,
            'target_id': target_id,
            'tracking_id': tracking_id,
            'template_id': template['id'],
            'sent_at': None,
            'opened_at': None,
            'clicked_at': None,
            'submitted_at': None,
            'captured_username': None,
            'captured_password_hash': None,
        }
        _store['campaign_sends'][send_id] = send_record

        # Build email
        lp_url = f"{APP_URL}/lp/{template['id']}/{tracking_id}"
        html_body = _substitute_target_vars(template['html_body'], target)
        # Replace {{link}} with actual tracked link
        html_body = html_body.replace("{{link}}", lp_url)

        # Send
        subject = _substitute_target_vars(template['subject'], target)
        ok, error_detail = _send_email(target['email'], subject, html_body, tracking_id)

        if ok:
            send_record['sent_at'] = _now()
            sent += 1
        else:
            send_record['error'] = error_detail
            failed += 1

    if sent > 0:
        campaign['status'] = 'running'

    failed_details = [
        {
            'target_id': s.get('target_id'),
            'email': _store['targets'].get(s.get('target_id'), {}).get('email', ''),
            'error': s.get('error')
        }
        for s in _store['campaign_sends'].values()
        if s.get('campaign_id') == cid and s.get('error')
    ]

    return jsonify({
        'campaign_id': cid,
        'sent': sent,
        'failed': failed,
        'status': campaign['status'],
        'failed_details': failed_details
    })

@app.route('/api/campaigns/<cid>/abort', methods=['POST'])
def abort_campaign(cid):
    campaign = _store['campaigns'].get(cid)
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    campaign['status'] = 'aborted'
    return jsonify({'campaign_id': cid, 'status': 'aborted'})

# ─── Target Management ────────────────────────────────────────────────────

@app.route('/api/targets', methods=['GET'])
def list_targets():
    group_id = request.args.get('group_id')
    targets = list(_store['targets'].values())
    if group_id:
        targets = [t for t in targets if t.get('group_id') == group_id]
    return jsonify({'targets': targets})

@app.route('/api/targets', methods=['POST'])
def create_target():
    """Add a single target."""
    data = request.json
    tid = _gen_id()
    target = {
        'id': tid,
        'group_id': data.get('group_id', 'default'),
        'email': data.get('email', '').strip().lower(),
        'first_name': data.get('first_name', '').strip(),
        'last_name': data.get('last_name', '').strip(),
        'department': data.get('department', '').strip(),
        'title': data.get('title', '').strip(),
        'company': data.get('company', '').strip(),
        'active': True,
        'created_at': _now(),
    }
    if not target['email']:
        return jsonify({'error': 'email is required'}), 400
    _store['targets'][tid] = target
    return jsonify(target), 201

@app.route('/api/targets/bulk', methods=['POST'])
def bulk_import_targets():
    """Import targets from JSON array."""
    data = request.json
    group_id = data.get('group_id', 'default')
    targets_data = data.get('targets', [])
    created = []
    errors = []

    for i, t in enumerate(targets_data):
        if not t.get('email'):
            errors.append({'index': i, 'error': 'missing email'})
            continue
        tid = _gen_id()
        target = {
            'id': tid,
            'group_id': group_id,
            'email': t.get('email', '').strip().lower(),
            'first_name': t.get('first_name', '').strip(),
            'last_name': t.get('last_name', '').strip(),
            'department': t.get('department', '').strip(),
            'title': t.get('title', '').strip(),
            'company': t.get('company', '').strip(),
            'active': True,
            'created_at': _now(),
        }
        _store['targets'][tid] = target
        created.append(target)

    return jsonify({'created': len(created), 'errors': errors, 'targets': created}), 201

# ─── Tracking ─────────────────────────────────────────────────────────────

@app.route('/track/open/<tracking_id>', methods=['GET'])
def track_open(tracking_id):
    """1x1 transparent pixel — records email open."""
    for send in _store['campaign_sends'].values():
        if send.get('tracking_id') == tracking_id and not send.get('opened_at'):
            send['opened_at'] = _now()
            break

    # Return 1x1 transparent GIF
    pixel = bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
                   0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
                   0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
                   0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
                   0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
                   0x01, 0x00, 0x3b])
    resp = make_response(pixel)
    resp.headers['Content-Type'] = 'image/gif'
    resp.headers['Cache-Control'] = 'no-store, no-cache'
    return resp

# ─── Training Assignment ─────────────────────────────────────────────────

TRAINING_MODULES = [
    {
        'id': 'mod_phishing_101',
        'name': 'Phishing 101: How to Spot a Scam',
        'category': 'phishing',
        'duration_minutes': 8,
        'video_url': 'https://example.com/videos/phishing-101.mp4',
        'quiz': [
            {'q': 'Which is a sign of a phishing email?', 'options': ['Sender matches company domain', 'Urgent action required with a link', 'No grammatical errors'], 'answer': 1},
        ]
    },
    {
        'id': 'mod_password_hygiene',
        'name': 'Password Security: Best Practices',
        'category': 'passwords',
        'duration_minutes': 6,
        'video_url': 'https://example.com/videos/password-hygiene.mp4',
        'quiz': [
            {'q': 'Best password practice?', 'options': ['Use the same password everywhere', 'Use a password manager + unique passwords', 'Write passwords on sticky notes'], 'answer': 1},
        ]
    },
    {
        'id': 'mod_social_engineering',
        'name': 'Social Engineering: The Human Firewall',
        'category': 'social_engineering',
        'duration_minutes': 10,
        'video_url': 'https://example.com/videos/social-engineering.mp4',
        'quiz': [
            {'q': 'What should you do if your CEO asks for an urgent wire transfer via email?', 'options': ['Do it immediately', 'Verify via phone/Slack first', 'Ignore it'], 'answer': 1},
        ]
    },
]

def _assign_training(send_record):
    """Assign a random training module to a target who clicked/submitted."""
    import random
    module = random.choice(TRAINING_MODULES)
    assignment = {
        'id': _gen_id(),
        'send_id': send_record['id'],
        'target_id': send_record['target_id'],
        'module_id': module['id'],
        'module_name': module['name'],
        'assigned_at': _now(),
        'completed_at': None,
        'status': 'assigned',  # assigned, completed
    }
    _store['training_assignments'][assignment['id']] = assignment

    # Send training email to target
    target = _store['targets'].get(send_record['target_id'])
    if target and SMTP_USER:
        subject = f"Action Required: Security Training Assigned — {module['name']}"
        body = f"""
        <html><body>
        <p>Hi {target.get('first_name', 'there')},</p>
        <p>You recently clicked on a simulated phishing email as part of our security awareness program.</p>
        <p>No punishment — this is how we learn! Please complete the following short training:</p>
        <p><strong>{module['name']}</strong> ({module['duration_minutes']} min)</p>
        <p>Complete it here: {APP_URL}/training/{assignment['id']}</p>
        <p>— EdgeIQ Security Team</p>
        </body></html>
        """
        _send_email(target['email'], subject, body)

    return assignment

@app.route('/api/training/assignments', methods=['GET'])
def list_assignments():
    target_id = request.args.get('target_id')
    assignments = list(_store['training_assignments'].values())
    if target_id:
        assignments = [a for a in assignments if a.get('target_id') == target_id]
    return jsonify({'assignments': assignments})

@app.route('/training/<assignment_id>', methods=['GET'])
def training_page(assignment_id):
    assignment = _store['training_assignments'].get(assignment_id)
    if not assignment:
        return "Assignment not found", 404
    module = next((m for m in TRAINING_MODULES if m['id'] == assignment['module_id']), None)
    if not module:
        return "Module not found", 404
    return f"""
    <html><head><title>{module['name']}</title></head>
    <body>
    <h1>{module['name']}</h1>
    <p>Video would play here: {module['video_url']}</p>
    <p>Quiz would appear here (not yet interactive).</p>
    <p>Duration: {module['duration_minutes']} minutes</p>
    <form method="POST" action="/training/{assignment_id}/complete">
    <button type="submit">Mark Complete</button>
    </form>
    </body></html>
    """

@app.route('/training/<assignment_id>/complete', methods=['POST'])
def complete_training(assignment_id):
    assignment = _store['training_assignments'].get(assignment_id)
    if not assignment:
        return "Assignment not found", 404
    assignment['completed_at'] = _now()
    assignment['status'] = 'completed'
    return f"<html><body><h1>Training Complete!</h1><p>You have successfully completed {assignment['module_name']}.</p></body></html>"

# ─── Reporting ──────────────────────────────────────────────────────────

@app.route('/api/reports/campaign/<cid>', methods=['GET'])
def campaign_report(cid):
    """Full campaign report with funnel stats."""
    campaign = _store['campaigns'].get(cid)
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404

    sends = [s for s in _store['campaign_sends'].values() if s.get('campaign_id') == cid]
    total = len(sends)

    def pct(n):
        return round(n / total * 100, 1) if total > 0 else 0

    funnel = {
        'sent': sum(1 for s in sends if s.get('sent_at')),
        'opened': sum(1 for s in sends if s.get('opened_at')),
        'clicked': sum(1 for s in sends if s.get('clicked_at')),
        'submitted': sum(1 for s in sends if s.get('submitted_at')),
        'rates': {
            'open_rate': pct(sum(1 for s in sends if s.get('opened_at'))),
            'click_rate': pct(sum(1 for s in sends if s.get('clicked_at'))),
            'compromise_rate': pct(sum(1 for s in sends if s.get('submitted_at'))),
        }
    }

    # Top clickers
    clickers = []
    for s in sends:
        if s.get('submitted_at'):
            target = _store['targets'].get(s.get('target_id'), {})
            clickers.append({
                'email': target.get('email', ''),
                'name': f"{target.get('first_name', '')} {target.get('last_name', '')}".strip(),
                'department': target.get('department', ''),
            })

    return jsonify({
        'campaign': campaign,
        'funnel': funnel,
        'top_clickers': clickers,
    })

# ─── Built-in Template Library ───────────────────────────────────────────

def _init_templates():
    """Seed built-in phishing templates."""
    templates = [
        {
            'id': 'tpl_microsoft_365',
            'name': 'Microsoft 365 Password Expired',
            'category': 'credential',
            'difficulty': 'easy',
            'subject': '⚠️ Action Required: Your Microsoft 365 Password Has Expired',
            'html_body': '''
            <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:#0078d4;padding:20px;color:white;">
                <h2 style="margin:0;">Microsoft 365</h2>
            </div>
            <div style="padding:20px;border:1px solid #ddd;">
                <p>Hi {{first_name}},</p>
                <p>Your password for <strong>Microsoft 365</strong> has expired and you must reset it to continue using email and Teams.</p>
                <p style="text-align:center;margin:30px 0;">
                <a href="{{link}}" style="background:#0078d4;color:white;padding:12px 24px;text-decoration:none;border-radius:4px;font-weight:bold;">Reset Password Now</a>
                </p>
                <p style="color:#666;font-size:12px;">This link expires in 24 hours.<br>If you did not request this, please ignore this email.</p>
            </div>
            </body></html>
            '''.strip(),
            'landing_page_id': 'microsoft_365',
            'credential_field': 'password',
        },
        {
            'id': 'tpl_fedex_delivery',
            'name': 'FedEx Delivery Failed',
            'category': 'attachment',
            'difficulty': 'medium',
            'subject': 'FedEx: Your package delivery failed — action required',
            'html_body': '''
            <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:#004884;padding:20px;color:white;">
                <h2 style="margin:0;">FedEx</h2>
            </div>
            <div style="padding:20px;border:1px solid #ddd;">
                <p>Hello {{first_name}},</p>
                <p>We attempted to deliver your package but were unable to complete delivery.</p>
                <p><strong>Tracking:</strong> 7891-2345-6789</p>
                <p>Please review and reschedule delivery using the link below:</p>
                <p style="text-align:center;margin:30px 0;">
                <a href="{{link}}" style="background:#28a745;color:white;padding:12px 24px;text-decoration:none;border-radius:4px;font-weight:bold;">Reschedule Delivery</a>
                </p>
                <p style="color:#666;font-size:12px;">Package will be returned to sender after 5 business days.</p>
            </div>
            </body></html>
            '''.strip(),
            'landing_page_id': 'fedex_tracking',
            'credential_field': 'tracking',
        },
        {
            'id': 'tpl_ceo_fraud',
            'name': 'CEO Urgent Request',
            'category': 'social',
            'difficulty': 'hard',
            'subject': 'Quick favor needed — are you available?',
            'html_body': '''
            <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="padding:20px;">
                <p>Hi {{first_name}},</p>
                <p>I'm in a meeting and need you to handle something urgent. Can you buy {{{{company}}}} some gift cards?</p>
                <p>I can't talk right now — just reply to this email and I'll give you the details.</p>
                <p>Need this done within the hour.</p>
                <p>— Your CEO</p>
                <p style="color:#666;font-size:12px;">Sent from my iPhone</p>
            </div>
            </body></html>
            '''.strip(),
            'landing_page_id': 'ceo_request',
            'credential_field': 'gift_card',
        },
    ]
    for t in templates:
        _store['templates'][t['id']] = {**t, 'created_at': _now()}

# ─── Built-in Landing Pages ──────────────────────────────────────────────

LANDING_PAGES = {
    'microsoft_365': '''
    <html><head><meta charset="utf-8"><title>Sign in to Microsoft</title></head>
    <body style="margin:0;background:#f3f3f3;font-family:Segoe UI,Tahoma,sans-serif;">
    <div style="background:#0078d4;padding:12px 20px;"><h2 style="color:white;margin:0;font-size:18px;">Microsoft</h2></div>
    <div style="max-width:440px;margin:60px auto;background:white;border-radius:8px;padding:40px;box-shadow:0 4px 20px rgba(0,0,0,0.1);">
        <h1 style="font-size:24px;margin:0 0 8px;">Sign in</h1>
        <p style="color:#616161;margin:0 0 24px;">to continue to Microsoft 365</p>
        <form method="POST" action="/api/capture">
            <input type="hidden" name="template_id" value="tpl_microsoft_365">
            <input type="hidden" name="tracking_id" value="">
            <input type="email" name="username" placeholder="Email, phone, or Skype" required
                style="width:100%;padding:10px 12px;margin-bottom:12px;border:1px solid #8a8a8a;border-radius:4px;font-size:14px;box-sizing:border-box;">
            <input type="password" name="password" placeholder="Password" required
                style="width:100%;padding:10px 12px;margin-bottom:16px;border:1px solid #8a8a8a;border-radius:4px;font-size:14px;box-sizing:border-box;">
            <button type="submit" style="width:100%;padding:10px;background:#0078d4;color:white;border:none;border-radius:4px;font-size:14px;cursor:pointer;">Sign in</button>
        </form>
        <p style="text-align:center;margin-top:20px;font-size:12px;color:#616161;">
            <a href="#" style="color:#0078d4;text-decoration:none;">Can't access your account?</a>
        </p>
    </div>
    </body></html>
    '''.strip().replace('                ', ''),
}

# Initialize built-in templates on startup
_init_templates()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
