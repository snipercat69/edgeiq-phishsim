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
import os, json, uuid, smtplib, ssl, tempfile, threading
import requests as http_requests
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
FROM_NAME    = os.environ.get('FROM_NAME', 'EdgeIQ Security')
APP_URL      = os.environ.get('APP_URL', 'https://simulate.edgeiqlabs.com')
STORE_PATH   = os.environ.get('STORE_PATH', '/tmp/edgeiq-phishsim-store.json')
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', '')

# In-memory store (MVP — replace with PostgreSQL for production)
# Format: { campaign_id: { ... }, target_id: { ... }, ... }
def _default_store():
    return {
        "campaigns": {},
        "targets": {},
        "templates": {},
        "campaign_sends": {},
        "training_assignments": {},
    }

_store = _default_store()
_store_lock = threading.Lock()

def _load_store():
    """Load persisted store from disk if available."""
    global _store
    if not STORE_PATH:
        return
    try:
        if os.path.exists(STORE_PATH):
            with open(STORE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            base = _default_store()
            if isinstance(data, dict):
                for k in base.keys():
                    v = data.get(k, {})
                    base[k] = v if isinstance(v, dict) else {}
            _store = base
            print(f"[PERSIST] store loaded from {STORE_PATH}")
    except Exception as e:
        print(f"[PERSIST][WARN] failed to load store: {type(e).__name__}: {e}")

def _persist_store():
    """Persist store atomically to disk."""
    if not STORE_PATH:
        return
    try:
        os.makedirs(os.path.dirname(STORE_PATH) or '.', exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix='edgeiq-store-', suffix='.json', dir=os.path.dirname(STORE_PATH) or '.')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(_store, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STORE_PATH)
    except Exception as e:
        print(f"[PERSIST][WARN] failed to persist store: {type(e).__name__}: {e}")

_load_store()

# ─── Helpers ────────────────────────────────────────────────────────────────

def _gen_id():
    return uuid.uuid4().hex[:16]

def _now():
    return datetime.utcnow().isoformat()

def _send_email(to_email, subject, html_body, tracking_pixel_id=None):
    """Send email (Mailgun API preferred, SMTP fallback). Returns (success, error_detail)."""

    # Add tracking pixel
    if tracking_pixel_id:
        pixel_url = f"{APP_URL}/track/open/{tracking_pixel_id}"
        pixel_html = f'<img src="{pixel_url}" width="1" height="1" style="display:none" />'
        html_body = pixel_html + html_body

    # Preferred path: Mailgun HTTP API (more reliable on Render)
    if MAILGUN_API_KEY:
        try:
            api_url = f"https://api.mailgun.net/v3/{SENDING_DOMAIN}/messages"
            resp = http_requests.post(
                api_url,
                auth=('api', MAILGUN_API_KEY),
                data={
                    'from': f"{FROM_NAME} <noreply@{SENDING_DOMAIN}>",
                    'to': to_email,
                    'subject': subject,
                    'html': html_body,
                },
                timeout=20,
            )
            if resp.status_code in (200, 201):
                print(f"[DEBUG] Mailgun API send succeeded to {to_email}")
                return True, None
            detail = f"HTTP {resp.status_code}: {resp.text[:200]}"
            print(f"[ERROR] Mailgun API send failed: {detail}")
            return False, detail
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
            print(f"[ERROR] Mailgun API exception: {detail}")
            return False, detail

    # Fallback path: SMTP
    if not SMTP_USER or not SMTP_PASS:
        detail = 'SMTP_USER or SMTP_PASS missing'
        print(f"[DEBUG] SMTP not configured — would send to {to_email}: {subject} | {detail}")
        return True, detail

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"{FROM_NAME} <noreply@{SENDING_DOMAIN}>"
    msg['To'] = to_email

    html_part = MIMEText(html_body, 'html')
    msg.attach(html_part)

    try:
        print(
            f"[DEBUG] SMTP attempt host={SMTP_HOST} port={SMTP_PORT} user={SMTP_USER} "
            f"from=noreply@{SENDING_DOMAIN} to={to_email}"
        )
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.set_debuglevel(1)
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(f"noreply@{SENDING_DOMAIN}", to_email, msg.as_string())
        print(f"[DEBUG] SMTP send succeeded to {to_email}")
        return True, None
    except Exception as e:
        detail = f"{type(e).__name__}: {e}"
        print(f"[ERROR] SMTP send failed host={SMTP_HOST} port={SMTP_PORT} user={SMTP_USER} detail={detail}")
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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'edgeiq-phishsim', 'version': '1.0.0'})

@app.route('/', methods=['GET'])
def home():
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>EdgeIQ PhishSim — Phishing Simulation for SMBs</title>
      <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',Arial,sans-serif; background:#070d17; color:#ddeeff; line-height:1.6; }}
        .hero {{ text-align:center; padding:80px 20px 60px; background:linear-gradient(180deg,#0d1a2e 0%,#070d17 100%); }}
        .hero .badge {{ display:inline-block; background:#0d2847; color:#4da8ff; font-size:0.78rem; font-weight:700; letter-spacing:0.12em; text-transform:uppercase; padding:5px 14px; border-radius:20px; border:1px solid #1a4a7a; margin-bottom:20px; }}
        .hero h1 {{ font-size:2.6rem; font-weight:800; color:#fff; margin-bottom:16px; letter-spacing:-0.02em; }}
        .hero h1 span {{ color:#4da8ff; }}
        .hero p {{ font-size:1.15rem; color:#8ab0cc; max-width:580px; margin:0 auto 36px; }}
        .cta-row {{ display:flex; gap:14px; justify-content:center; flex-wrap:wrap; }}
        .btn {{ padding:13px 28px; border-radius:8px; font-weight:700; font-size:0.95rem; text-decoration:none; transition:all 0.2s; display:inline-block; }}
        .btn-primary {{ background:#4da8ff; color:#071018; }}
        .btn-primary:hover {{ background:#79bfff; transform:translateY(-1px); }}
        .btn-secondary {{ background:#0d2847; color:#4da8ff; border:1px solid #1a4a7a; }}
        .btn-secondary:hover {{ background:#1a4a7a; }}
        .stats {{ display:flex; gap:40px; justify-content:center; margin-top:50px; flex-wrap:wrap; }}
        .stat {{ text-align:center; }}
        .stat strong {{ display:block; font-size:2rem; font-weight:800; color:#4da8ff; }}
        .stat span {{ font-size:0.82rem; color:#6a8aaa; text-transform:uppercase; letter-spacing:0.08em; }}
        .section {{ padding:60px 20px; max-width:960px; margin:0 auto; }}
        .section h2 {{ font-size:1.7rem; font-weight:700; color:#fff; margin-bottom:8px; text-align:center; }}
        .section .sub {{ text-align:center; color:#6a8aaa; margin-bottom:40px; }}
        .features {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px; }}
        .feat {{ background:#0d1a2e; border:1px solid #1a3050; border-radius:12px; padding:24px; }}
        .feat-icon {{ font-size:1.8rem; margin-bottom:12px; }}
        .feat h3 {{ font-size:1rem; font-weight:700; color:#fff; margin-bottom:8px; }}
        .feat p {{ font-size:0.88rem; color:#8ab0cc; }}
        .pricing {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:20px; }}
        .plan {{ background:#0d1a2e; border:1px solid #1a3050; border-radius:12px; padding:28px 24px; display:flex; flex-direction:column; }}
        .plan.popular {{ border-color:#4da8ff; box-shadow:0 0 30px rgba(77,168,255,0.12); }}
        .plan .tag {{ font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; color:#4da8ff; margin-bottom:8px; }}
        .plan h3 {{ font-size:1.1rem; font-weight:700; color:#fff; margin-bottom:4px; }}
        .plan .price {{ font-size:2rem; font-weight:800; color:#fff; margin:12px 0; }}
        .plan .price span {{ font-size:0.85rem; font-weight:400; color:#6a8aaa; }}
        .plan ul {{ list-style:none; flex:1; margin:16px 0; }}
        .plan ul li {{ font-size:0.85rem; color:#8ab0cc; padding:4px 0; }}
        .plan ul li::before {{ content:'✔ '; color:#4da8ff; margin-right:6px; }}
        .plan .btn-block {{ display:block; text-align:center; padding:11px; border-radius:7px; font-weight:700; font-size:0.88rem; text-decoration:none; margin-top:auto; }}
        .tier-starter {{ background:#0d2847; color:#4da8ff; border:1px solid #1a4a7a; }}
        .tier-starter:hover {{ background:#1a4a7a; }}
        .tier-pro {{ background:#4da8ff; color:#071018; }}
        .tier-pro:hover {{ background:#79bfff; }}
        .tier-agency {{ background:#0d2847; color:#4da8ff; border:1px solid #1a4a7a; }}
        .tier-agency:hover {{ background:#1a4a7a; }}
        .proof {{ background:#0d1a2e; border:1px solid #1a3050; border-radius:12px; padding:32px; text-align:center; margin-top:40px; }}
        .proof p {{ font-size:1.05rem; color:#ddeeff; font-style:italic; margin-bottom:16px; }}
        .proof .attr {{ font-size:0.82rem; color:#6a8aaa; }}
        .footer {{ text-align:center; padding:30px 20px; border-top:1px solid #1a3050; margin-top:60px; color:#4a6080; font-size:0.82rem; }}
        .dashboard-teaser {{ background:#0d1a2e; border:1px solid #1a3050; border-radius:12px; padding:32px; text-align:center; margin-bottom:40px; }}
        .dashboard-teaser img {{ max-width:100%; border-radius:8px; border:1px solid #1a3050; margin-top:16px; }}
      </style>
    </head>
    <body>

      <!-- HERO -->
      <div class="hero">
        <div class="badge">Now Available for Teams</div>
        <h1>Stop Phishing Emails From<br><span>Ever Reaching Your Team</span></h1>
        <p>EdgeIQ PhishSim runs real-world phishing simulations against your employees — tracks who opens, clicks, and submits credentials — then automatically enrolls them in security awareness training to close the gap.</p>
        <div class="cta-row">
          <a href="https://buy.stripe.com/3cI28tdyjgRLbQoaIM7wA1C" class="btn btn-primary">Start Free Trial</a>
          <a href="#pricing" class="btn btn-secondary">View Pricing</a>
        </div>
        <div class="stats">
          <div class="stat"><strong>91%</strong><span>of breaches start with phishing</span></div>
          <div class="stat"><strong>&lt;3 min</strong><span>avg. time an attacker is inside</span></div>
          <div class="stat"><strong>$4.45M</strong><span>avg. phishing-related breach cost</span></div>
        </div>
      </div>

      <!-- HOW IT WORKS -->
      <div class="section">
        <h2>How PhishSim Works</h2>
        <p class="sub">Three steps to a more secure team — no IT department required</p>
        <div class="features">
          <div class="feat">
            <div class="feat-icon">🎯</div>
            <h3>1. Launch a Campaign</h3>
            <p>Pick from 20+ pre-built phishing templates or create your own. Target individual employees, teams, or your entire company in one click.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">📊</div>
            <h3>2. Track Who Takes the Bait</h3>
            <p>See real-time reports on who opened the email, clicked the link, submitted forms, or reported the phishing attempt. Per-user and aggregate views.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">🎓</div>
            <h3>3. Auto-Train High-Risk Users</h3>
            <p>Automatically assign follow-up security awareness training to employees who fell for the simulation. Close the human vulnerability gap fast.</p>
          </div>
        </div>
      </div>

      <!-- FEATURES -->
      <div class="section">
        <h2>Everything Your Security Team Needs</h2>
        <p class="sub">Built for lean SMB security teams — no enterprise budget required</p>
        <div class="features">
          <div class="feat">
            <div class="feat-icon">📧</div>
            <h3>Realistic Phishing Templates</h3>
            <p>20+ templates modeled on real-world attack techniques — impersonation, credential harvesting, malicious links, and attachment lures.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">👥</div>
            <h3>Bulk Target Import</h3>
            <p>Upload a CSV of employee emails and names. Assign targets to campaigns individually or in bulk with one click.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">📈</div>
            <h3>Campaign Analytics</h3>
            <p>Track opens, clicks, form submissions, and reports per campaign, per department, and per user. Export executive-ready PDF reports.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">🔗</div>
            <h3>Training Auto-Enrollment</h3>
            <p>Employees who click are automatically enrolled in follow-up training modules. No manual tracking needed.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">🏢</div>
            <h3>Multi-User &amp; Roles</h3>
            <p>Manager accounts can run their own campaigns. Admin view shows company-wide risk scores and training completion.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">🔒</div>
            <h3>SOC2-Aligned Data Handling</h3>
            <p>All tracking data is encrypted at rest. Simulation data is never used for any purpose other than your own security awareness program.</p>
          </div>
        </div>
      </div>

      <!-- PROOF -->
      <div class="section">
        <div class="proof">
          <p>"We ran our first phishing campaign on 50 employees. Within 2 weeks, click rates dropped 67% after auto-enrolled training. That's the kind of ROI that gets the board's attention."</p>
          <div class="attr">— IT Director, 75-person professional services firm</div>
        </div>
      </div>

      <!-- PRICING -->
      <div class="section" id="pricing">
        <h2>Simple, Predictable Pricing</h2>
        <p class="sub">No per-user surprise bills. One flat monthly rate per tier.</p>
        <div class="pricing">
          <div class="plan">
            <div class="tag">Starter</div>
            <h3>PhishSim Starter</h3>
            <div class="price">$29<span>/mo</span></div>
            <ul>
              <li>Up to 25 users</li>
              <li>10 campaigns/month</li>
              <li>20 phishing templates</li>
              <li>Basic campaign reports</li>
              <li>Email support</li>
            </ul>
            <a href="https://buy.stripe.com/3cI28tdyjgRLbQoaIM7wA1C" class="btn-block tier-starter">Start Free Trial</a>
          </div>
          <div class="plan popular">
            <div class="tag">Most Popular</div>
            <h3>PhishSim Pro</h3>
            <div class="price">$79<span>/mo</span></div>
            <ul>
              <li>Up to 100 users</li>
              <li>Unlimited campaigns</li>
              <li>20 phishing templates</li>
              <li>Advanced analytics &amp; PDF reports</li>
              <li>Training auto-enrollment</li>
              <li>Priority email support</li>
            </ul>
            <a href="https://buy.stripe.com/5kQ8wR9i3bxrbQoaIM7wA1D" class="btn-block tier-pro">Start Free Trial</a>
          </div>
          <div class="plan">
            <div class="tag">Agency / MSP</div>
            <h3>PhishSim Agency</h3>
            <div class="price">$149<span>/mo</span></div>
            <ul>
              <li>Up to 500 users</li>
              <li>Unlimited campaigns</li>
              <li>20 phishing templates</li>
              <li>White-label reporting</li>
              <li>Multi-client portal</li>
              <li>Dedicated account manager</li>
            </ul>
            <a href="https://buy.stripe.com/7sYcN7cuf6d7bQoaIM7wA1E" class="btn-block tier-agency">Start Free Trial</a>
          </div>
        </div>
      </div>

      <!-- FAQ -->
      <div class="section">
        <h2>Common Questions</h2>
        <p class="sub">
        <strong>Is this ethical?</strong> Yes — you are simulating phishing on your own employees to train them, which is exactly what KnowBe4, Cofense, and Proofpoint do. Never on external parties.<br><br>
        <strong>Do employees know they're being tested?</strong> Best practice is to notify your team upfront that phishing simulations are part of your security program. Transparency builds a stronger security culture.<br><br>
        <strong>What happens to simulation data?</strong> All data stays private to your organization. We never use, share, or monetize any campaign or employee data.<br><br>
        <strong>Can I import my existing training content?</strong> Yes — PhishSim Pro and Agency support custom training modules and can enroll employees automatically based on simulation results.
        </p>
      </div>

      <!-- FOOTER -->
      <div class="footer">
        <p>EdgeIQ PhishSim &copy; 2026 EdgeIQ Labs &nbsp;|&nbsp; <a href="/health" style="color:#4a6080;">System Status</a></p>
      </div>

    </body>
    </html>
    """

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
    _persist_store()
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
                _persist_store()
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
    _persist_store()

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
    _persist_store()
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

    _persist_store()

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
    _persist_store()
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
    _persist_store()
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

    _persist_store()

    return jsonify({'created': len(created), 'errors': errors, 'targets': created}), 201

# ─── Tracking ─────────────────────────────────────────────────────────────

@app.route('/track/open/<tracking_id>', methods=['GET'])
def track_open(tracking_id):
    """1x1 transparent pixel — records email open."""
    for send in _store['campaign_sends'].values():
        if send.get('tracking_id') == tracking_id and not send.get('opened_at'):
            send['opened_at'] = _now()
            _persist_store()
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
    _persist_store()

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
    _persist_store()
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
        if t['id'] not in _store['templates']:
            _store['templates'][t['id']] = {**t, 'created_at': _now()}
    _persist_store()

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
