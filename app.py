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
            <p>Automatically enroll employees who click into structured security training — <strong>Phishing 101</strong>, <strong>Password Security</strong>, and <strong>Social Engineering</strong> — with quizzes and certificates.</p>
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
            <p>Employees who click are automatically assigned the relevant training module — <strong>Phishing 101</strong>, <strong>Password Security</strong>, or <strong>Social Engineering</strong> — with an interactive quiz and certificate on completion.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">🏢</div>
            <h3>Manager Compliance Dashboard</h3>
            <p>See team-wide training completion rates, per-user progress, quiz scores, and certificate records — all in one view.</p>
          </div>
          <div class="feat">
            <div class="feat-icon">🔒</div>
            <h3>SOC2-Aligned Data Handling</h3>
            <p>All tracking data is encrypted at rest. Simulation data is never used for any purpose other than your own security awareness program.</p>
          </div>
        </div>
      </div>

      <!-- TRAINING MODULES -->
      <div class="section">
        <h2>🎓 Training Modules — What's Included</h2>
        <p class="sub">Security awareness training that auto-enrolls employees who click. Choose the plan that fits your team.</p>
        <div class="pricing">
          <div class="plan">
            <div class="tag">Starter</div>
            <h3>PhishSim Starter</h3>
            <div class="price">$29<span>/mo</span></div>
            <ul>
              <li><strong>Phishing 101: How to Spot a Scam</strong></li>
              <li>Red flags, sender analysis, link inspection</li>
              <li>Urgent-action demand recognition</li>
              <li>8 min + 5-question quiz</li>
              <li>Completion certificate</li>
            </ul>
            <a href="https://buy.stripe.com/3cI28tdyjgRLbQoaIM7wA1C" class="btn-block tier-starter">Start Free Trial</a>
          </div>
          <div class="plan popular">
            <div class="tag">Most Popular</div>
            <h3>PhishSim Pro</h3>
            <div class="price">$79<span>/mo</span></div>
            <ul>
              <li><strong>✓ Everything in Starter</strong></li>
              <li><strong>+ Password Security: Best Practices</strong></li>
              <li>Password managers, 2FA, reuse prevention</li>
              <li><strong>+ Social Engineering: The Human Firewall</strong></li>
              <li>Pretexting, baiting, tailgating defense</li>
              <li>All 3 modules: 24 min total content</li>
              <li>Training auto-enrollment on click</li>
              <li>Manager compliance dashboard</li>
            </ul>
            <a href="https://buy.stripe.com/5kQ8wR9i3bxrbQoaIM7wA1D" class="btn-block tier-pro">Start Free Trial</a>
          </div>
          <div class="plan">
            <div class="tag">Agency / MSP</div>
            <h3>PhishSim Agency</h3>
            <div class="price">$149<span>/mo</span></div>
            <ul>
              <li><strong>✓ Everything in Pro</strong></li>
              <li>White-label training portal</li>
              <li>Multi-client reporting</li>
              <li>Custom training assignment rules</li>
              <li>Dedicated account manager</li>
              <li>All 3 modules included</li>
              <li>Priority support</li>
            </ul>
            <a href="https://buy.stripe.com/7sYcN7cuf6d7bQoaIM7wA1E" class="btn-block tier-agency">Start Free Trial</a>
          </div>
        </div>
        <p style="text-align:center;margin-top:24px;color:#4da8ff;font-size:0.9rem;">Annual billing saves ~28% — 2 months free &nbsp;|&nbsp; <a href="#pricing" style="color:#4da8ff;">See annual pricing ↓</a></p>
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
        <p class="sub">No per-user surprise bills. Switch between monthly and annual anytime.</p>

        <div style="text-align:center;margin-bottom:20px;">
          <span style="display:inline-block;background:#1a4a7a;color:#4da8ff;padding:6px 16px;border-radius:20px;font-size:0.82rem;font-weight:700;letter-spacing:0.05em;">ANNUAL PLANS SAVE ~28% — 2 MONTHS FREE</span>
        </div>

        <div class="pricing">
          <div class="plan">
            <div class="tag">Starter</div>
            <h3>PhishSim Starter</h3>
            <div style="display:flex;gap:16px;align-items:center;margin:8px 0;">
              <div>
                <div class="price">$29<span>/mo</span></div>
                <div style="font-size:0.78rem;color:#6a8aaa;">billed monthly</div>
              </div>
              <div style="border-left:1px solid #1a3050;padding-left:16px;">
                <div class="price" style="font-size:1.5rem;">$249<span>/yr</span></div>
                <div style="font-size:0.78rem;color:#22c55e;">save $99/yr</div>
              </div>
            </div>
            <ul>
              <li>Up to 25 users</li>
              <li>10 campaigns/month</li>
              <li>20 phishing templates</li>
              <li>Phishing training module</li>
              <li>Basic campaign reports</li>
              <li>Email support</li>
            </ul>
            <a href="https://buy.stripe.com/3cI28tdyjgRLbQoaIM7wA1C" class="btn-block tier-starter" style="margin-top:8px;">Monthly — $29/mo</a>
            <a href="https://buy.stripe.com/eVqbJ39i3bxr07G5os7wA1F" class="btn-block tier-starter" style="margin-top:4px;font-size:0.8rem;">Annual — $249/yr</a>
          </div>
          <div class="plan popular">
            <div class="tag">Most Popular</div>
            <h3>PhishSim Pro</h3>
            <div style="display:flex;gap:16px;align-items:center;margin:8px 0;">
              <div>
                <div class="price">$79<span>/mo</span></div>
                <div style="font-size:0.78rem;color:#6a8aaa;">billed monthly</div>
              </div>
              <div style="border-left:1px solid #1a3050;padding-left:16px;">
                <div class="price" style="font-size:1.5rem;">$699<span>/yr</span></div>
                <div style="font-size:0.78rem;color:#22c55e;">save $249/yr</div>
              </div>
            </div>
            <ul>
              <li>Up to 100 users</li>
              <li>Unlimited campaigns</li>
              <li>20 phishing templates</li>
              <li>All 3 training modules</li>
              <li>Advanced analytics &amp; PDF reports</li>
              <li>Training auto-enrollment</li>
              <li>Priority email support</li>
            </ul>
            <a href="https://buy.stripe.com/5kQ8wR9i3bxrbQoaIM7wA1D" class="btn-block tier-pro" style="margin-top:8px;">Monthly — $79/mo</a>
            <a href="https://buy.stripe.com/aFa9AV8dZ7hbcUs4ko7wA1G" class="btn-block tier-pro" style="margin-top:4px;font-size:0.8rem;">Annual — $699/yr</a>
          </div>
          <div class="plan">
            <div class="tag">Agency / MSP</div>
            <h3>PhishSim Agency</h3>
            <div style="display:flex;gap:16px;align-items:center;margin:8px 0;">
              <div>
                <div class="price">$149<span>/mo</span></div>
                <div style="font-size:0.78rem;color:#6a8aaa;">billed monthly</div>
              </div>
              <div style="border-left:1px solid #1a3050;padding-left:16px;">
                <div class="price" style="font-size:1.5rem;">$1,299<span>/yr</span></div>
                <div style="font-size:0.78rem;color:#22c55e;">save $489/yr</div>
              </div>
            </div>
            <ul>
              <li>Up to 500 users</li>
              <li>Unlimited campaigns</li>
              <li>20 phishing templates</li>
              <li>All 3 training modules</li>
              <li>White-label reporting</li>
              <li>Multi-client portal</li>
              <li>Dedicated account manager</li>
            </ul>
            <a href="https://buy.stripe.com/7sYcN7cuf6d7bQoaIM7wA1E" class="btn-block tier-agency" style="margin-top:8px;">Monthly — $149/mo</a>
            <a href="https://buy.stripe.com/00w9AVeCnatn8Ec2cg7wA1H" class="btn-block tier-agency" style="margin-top:4px;font-size:0.8rem;">Annual — $1,299/yr</a>
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
        # Plan tier controls which training modules are available:
        # starter = phishing only | pro/agency = all modules
        'plan': data.get('plan', 'starter'),
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
        'content': '''
        <h2>What Is Phishing?</h2>
        <p>Phishing is a type of social engineering attack where an attacker pretends to be someone you trust — a colleague, bank, vendor, or service you use — to trick you into giving up sensitive information or clicking something dangerous.</p>

        <h2>How Phishing Works</h2>
        <p>Attackers cast a wide net. They send thousands of emails hoping a small percentage will bite. The math is simple: send 10,000 emails, even a 1% success rate means 100 compromised accounts.</p>

        <h2>Red Flags to Watch For</h2>
        <ul>
        <li><strong>Urgent or threatening language</strong> — "Your account will be suspended!" "Act now!"</li>
        <li><strong>Mismatched sender addresses</strong> — Looks like amazon.com but the actual domain is amaz0n-support.com</li>
        <li><strong>Generic greetings</strong> — "Dear Customer" instead of your actual name</li>
        <li><strong>Spelling and grammar errors</strong> — Legitimate companies proofread their emails</li>
        <li><strong>Unexpected attachments</strong> — Especially .zip, .exe, .docm, or .xlsx files</li>
        <li><strong>Links that don't match</strong> — Hover over a link before clicking — does the URL match what it claims to be?</li>
        <li><strong>Requests for credentials or personal info</strong> — Real companies don't ask for passwords via email</li>
        </ul>

        <h2>Real-World Example</h2>
        <p>You receive an email that looks like it's from Netflix: "We couldn't process your payment. Click here to update your billing info." The link goes to a page that looks exactly like Netflix's login screen, but the URL is netflix-billing-support.com. When you "log in," you're actually giving your credentials to attackers.</p>

        <h2>What To Do</h2>
        <ul>
        <li><strong>Don't click links</strong> in suspicious emails. Instead, go directly to the company's website by typing the address.</li>
        <li><strong>When in doubt, verify.</strong> Call the sender using a number you know is real — not one from the email.</li>
        <li><strong>Report it.</strong> Use your company's "Report Phishing" button. This helps your security team catch attacks faster.</li>
        <li><strong>Delete it.</strong> After reporting, delete the email. Don't reply, don't forward (unless your security team asks), just delete.</li>
        </ul>
        ''',
        'quiz': [
            {'q': 'You receive an email from "support@paypa1.com" (note the numeral 1) saying your account has been compromised. What should you do?', 'options': ['Click the link immediately to secure your account', 'Reply to the email asking for more information', 'Delete the email and go directly to paypal.com by typing it in your browser', 'Forward it to your colleagues so they can be warned'], 'answer': 2},
            {'q': 'An email claims your CEO needs an urgent wire transfer and asks you to keep it confidential. What is this most likely?', 'options': ['A legitimate urgent request from leadership', 'A social engineering attack called Business Email Compromise (BEC)', 'A glitch in the company email system', 'Nothing suspicious — CEOs often need urgent favors'], 'answer': 1},
            {'q': 'Which of these is the STRONGEST reason to suspect an email is a phishing attempt?', 'options': ['It was sent early in the morning', 'It contains a link and asks you to log in with your credentials', 'The subject line is in all caps', 'The email has an attachment you weren\'t expecting'], 'answer': 1},
            {'q': 'You hover over a link in an email and the URL shows "https://appleid.apple.com.secure-login.net/" — what does this tell you?', 'options': ['The link is safe because it mentions appleid.apple.com', 'The link is a phishing attempt — the real domain is secure-login.net, not apple.com', 'The link is encrypted and therefore safe', 'It means the email was sent by Apple officially'], 'answer': 1},
            {'q': 'What is the correct response to a suspicious email that might be a phishing attempt?', 'options': ['Click the unsubscribe link at the bottom to stop receiving them', 'Reply with "STOP" to be removed from the list', 'Report it using your company\'s phishing report tool, then delete it', 'Open it in your second monitor to investigate more safely'], 'answer': 2},
        ]
    },
    {
        'id': 'mod_password_hygiene',
        'name': 'Password Security: Best Practices',
        'category': 'passwords',
        'duration_minutes': 6,
        'content': '''
        <h2>Why Passwords Matter</h2>
        <p>Your password is the key to your digital life. One compromised password can lead to identity theft, financial fraud, corporate data breaches, and malware deployment across an entire organization.</p>

        <h2>The Problem With Common Passwords</h2>
        <p>The most common passwords include "123456," "password," and "qwerty." Attackers know this. They use automated tools that try these combinations in seconds. Strong passwords are the simplest, cheapest security control that exists — but most people still get it wrong.</p>

        <h2>What Makes a Strong Password?</h2>
        <ul>
        <li><strong>Length over complexity</strong> — 16+ characters beats 8 characters with symbols. "correct-horse-battery-staple" is stronger than "Tr0ub4dor&3."</li>
        <li><strong>Unique for every account</strong> — If one password leaks, everything else stays safe.</li>
        <li><strong>No personal information</strong> — No birthdays, pet names, spouse names, or favorite sports teams.</li>
        <li><strong>No dictionary words alone</strong> — "sunshine" or "football" can be cracked in milliseconds.</li>
        </ul>

        <h2>Use a Password Manager</h2>
        <p>You cannot remember unique, complex passwords for every account. That's normal. Use a password manager (1Password, Bitwarden, KeePass) to generate and store strong, unique passwords for every service. You only need to remember one master password.</p>

        <h2>Enable Two-Factor Authentication (2FA)</h2>
        <p>Password alone is not enough. Enable 2FA everywhere it's offered — especially for email, banking, and work accounts. Use an authenticator app (Google Authenticator, Authy) or hardware key (YubiKey). <strong>Never use SMS-based 2FA</strong> — SIM-swapping attacks can bypass it.</p>

        <h2>Other Critical Rules</h2>
        <ul>
        <li><strong>Never share passwords</strong> — Not with IT support, not with your boss, not with anyone. Real IT will never ask for your password.</li>
        <li><strong>Never use work email for personal accounts</strong> — If that personal account gets breached, attackers now have a correlation to your employer.</li>
        <li><strong>Change passwords immediately</strong> if you suspect any account may be compromised.</li>
        </ul>
        ''',
        'quiz': [
            {'q': 'Which password is the STRONGEST?', 'options': ['Password123!', 'MyDogMax2015', 'correct-horse-battery-staple-36', 'Summer2024!'], 'answer': 2},
            {'q': 'An IT support technician calls and asks you to read them your password so they can "fix a system issue." What should you do?', 'options': ['Read it to them — they\'re from IT and need to help', 'Ask for their employee ID and call the IT department back using the official number', 'Write it down and hand it to them', 'Send it via email so there\'s a record'], 'answer': 1},
            {'q': 'Your favorite website offers 2FA. Which method should you choose?', 'options': ['SMS text message — it\'s the most convenient', 'Email code — it\'s the fastest', 'Authenticator app or hardware security key', 'No 2FA — passwords are enough'], 'answer': 2},
            {'q': 'Why is using the same password across multiple accounts dangerous?', 'options': ['It\'s not dangerous — it\'s actually more secure', 'It means you only have to remember one password', 'If one account is breached, all accounts using that password are immediately compromised', 'It can slow down your computer'], 'answer': 2},
            {'q': 'A password manager stores all your passwords in one place. Why is this considered secure?', 'options': ['It\'s not secure — you should never use one', 'Because it uses a single master password that you must remember, keeping all other passwords unique and complex', 'Because password managers are never targeted by attackers', 'Because it automatically shares your passwords with your company\'s IT team'], 'answer': 1},
        ]
    },
    {
        'id': 'mod_social_engineering',
        'name': 'Social Engineering: The Human Firewall',
        'category': 'social_engineering',
        'duration_minutes': 10,
        'content': '''
        <h2>What Is Social Engineering?</h2>
        <p>Social engineering is the art of manipulating people into giving up information or taking actions that benefit an attacker. It's often easier for attackers to trick a human than to hack a system. People want to be helpful, avoid conflict, and trust authority — attackers exploit all of these.</p>

        <h2>Common Social Engineering Tactics</h2>
        <h3>Pretexting</h3>
        <p>Attackers create a fabricated scenario to engage you. They might call pretending to be IT support, or email pretending to be your CFO needing an urgent favor. The story is the weapon.</p>

        <h3>Baiting</h3>
        <p>Attackers offer something enticing to spark curiosity. A USB drive labeled "Q4 Salary Report" left in a parking lot. A free USB charger cable mailed to an employee. People plug in unknown devices — and malware executes automatically.</p>

        <h3>Tailgating</h3>
        <p>An attacker follows an employee through a secure door by pretending to have forgotten their badge. Once inside, they have physical access to systems, ports, and documents.</p>

        <h3>Quid Pro Quo</h3>
        <p>Attackers offer a service or benefit in exchange for information. "Hi, we're calling from IT support — we noticed your computer might be running slow. Can we remote in to take a look?"</p>

        <h2>How to Defend Yourself</h2>
        <ul>
        <li><strong>Verify before trusting</strong> — If someone claims to be from a company or your IT team, call them back through an official channel you know is real.</li>
        <li><strong>Slow down</strong> — Urgency is a weapon. "Act now!" is designed to bypass your rational thinking. Take a breath. Ask yourself: is this actually urgent?</li>
        <li><strong>Question authority</strong> — Attackers often impersonate executives, IT staff, or help desk. Legitimate requests from real people won't be offended if you verify properly.</li>
        <li><strong>Don't be pushed</strong> — If someone is rushing you or threatening consequences for not complying, that is a massive red flag.</li>
        <li><strong>Protect your physical space</strong> — Don't let strangers follow you through secure doors. Challenge unknown individuals politely: "Can I help you find someone?"</li>
        </ul>

        <h2>Real Scenario</h2>
        <p>An attacker calls the main reception of a company, pretending to be a new hire who is locked out. The receptionist checks the employee directory, finds the name, and lets them in. The attacker now has physical access to the building, can plug in a keystroke logger, or access unattended computers.</p>
        ''',
        'quiz': [
            {'q': 'You receive a call from someone claiming to be from your company\'s IT department who says they need remote access to "fix a security issue on your machine." What should you do?', 'options': ['Give them access — IT issues are urgent and they\'re trying to protect you', 'Ask for their name and employee ID, then call the IT help desk back using the official number from your company\'s intranet', 'Let them in but watch what they do on your screen', 'Email them your credentials so they can fix it asynchronously'], 'answer': 1},
            {'q': 'You find a USB drive in the parking lot labeled "Confidential — HR Performance Reviews 2024." What should you do?', 'options': ['Plug it into your work computer to find the owner', 'Take it to IT and let them handle it — don\'t plug it in yourself', 'Post a note in the break room asking if anyone lost a USB drive', 'Plug it into your personal computer at home to check its contents'], 'answer': 1},
            {'q': 'An attacker calls and pretends to be your company\'s CFO, urgently requesting a wire transfer. The call seems legitimate — they know your name and have details about the company. What\'s the right move?', 'options': ['Do the transfer quickly — the CFO is always right', 'Hang up and call the CFO directly using the number in the company directory, not the one provided by the caller', 'Email the CFO to confirm the transfer before doing it', 'Ask the caller to verify by giving you their employee ID'], 'answer': 1},
            {'q': 'What makes social engineering particularly dangerous compared to technical attacks?', 'options': ['It targets human psychology rather than software vulnerabilities, exploiting trust and helpfulness', 'It\'s faster to execute than technical attacks', 'It requires no prior knowledge of the target', 'Technical attacks are always more dangerous'], 'answer': 0},
            {'q': 'A vendor you\'ve worked with before sends an email asking you to update your payment routing information to a new bank account. They reference a recent project and use the same email signature as always. What should you do?', 'options': ['Update it immediately — they\'re a trusted vendor and it\'s probably urgent', 'Call the vendor using a known phone number (not one from the email) to verify the request before changing anything', 'Reply to the email asking if the change is real', 'Send them your current bank info so they can confirm it\'s the same'], 'answer': 1},
        ]
    },
]

def _assign_training(send_record):
    """Assign a training module based on plan tier and click type."""
    import random
    campaign = _store['campaigns'].get(send_record.get('campaign_id')) or {}
    plan = campaign.get('plan', 'starter')
    # Filter eligible modules by plan tier
    if plan == 'starter':
        eligible = [m for m in TRAINING_MODULES if m['category'] == 'phishing']
    else:  # pro or agency — all modules available
        eligible = TRAINING_MODULES
    if not eligible:
        return None
    module = random.choice(eligible)
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

# @app.route('/api/training/assignments', methods=['GET'])
# def list_assignments():  # superseded by api_list_assignments below
#     target_id = request.args.get('target_id')
#     assignments = list(_store['training_assignments'].values())
#     if target_id:
#         assignments = [a for a in assignments if a.get('target_id') == target_id]
#     return jsonify({'assignments': assignments})

@app.route('/training/<assignment_id>', methods=['GET'])
def training_page(assignment_id):
    assignment = _store['training_assignments'].get(assignment_id)
    if not assignment:
        return "<html><body style='font-family:Arial;background:#070d17;color:#ddeeff;padding:40px'><h2>Assignment not found.</h2><p>This training link may have already been completed or is invalid.</p></body></html>", 404
    module = next((m for m in TRAINING_MODULES if m['id'] == assignment['module_id']), None)
    if not module:
        return "<html><body style='font-family:Arial;background:#070d17;color:#ddeeff;padding:40px'><h2>Module not found.</h2></body></html>", 404
    if assignment.get('completed_at'):
        cert_link = f"<a href='/training/{assignment_id}/certificate' style='background:#4da8ff;color:#071018;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block;margin-top:16px;'>📜 Download Certificate</a>"
        return f"""<html><head><title>Completed: {module['name']}</title><style>
        body{{font-family:'Segoe UI',Arial,sans-serif;background:#070d17;color:#ddeeff;padding:40px;text-align:center;}}
        .card{{max-width:600px;margin:60px auto;background:#0d1a2e;border:1px solid #1a3050;border-radius:12px;padding:40px;}}
        h1{{color:#4da8ff;}}p{{color:#8ab0cc;}}
        </style></head><body>
        <div class=card>
        <h1>✅ Module Complete!</h1>
        <h2 style='color:#fff'>{module['name']}</h2>
        <p>You have successfully completed this training module.</p>
        {cert_link}
        </div></body></html>"""
    # Build quiz options HTML
    quiz_html = ''
    for i, q in enumerate(module['quiz']):
        opts_html = ''
        for j, opt in enumerate(q['options']):
            opts_html += f"""<label style='display:block;padding:10px 14px;margin:6px 0;background:#0d2847;border:1px solid #1a4a7a;border-radius:7px;cursor:pointer;'>
            <input type='radio' name='q{i}' value='{j}' style='margin-right:8px'> {opt}
            </label>"""
        quiz_html += f"""<div style='margin-bottom:24px;'><p style='font-weight:700;margin-bottom:8px;'>{i+1}. {q['q']}</p>{opts_html}</div>"""
    return f"""<html><head><title>{module['name']}</title><style>
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#070d17;color:#ddeeff;margin:0;}}
    .topbar{{background:#0d1a2e;border-bottom:1px solid #1a3050;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;}}
    .topbar h1{{font-size:1.1rem;color:#4da8ff;margin:0;}}
    .badge{{background:#0d2847;color:#4da8ff;font-size:0.75rem;padding:4px 10px;border-radius:12px;border:1px solid #1a4a7a;}}
    .container{{max-width:800px;margin:0 auto;padding:32px 24px;}}
    .module-content{{background:#0d1a2e;border:1px solid #1a3050;border-radius:12px;padding:32px;margin-bottom:32px;}}
    .module-content h2{{color:#4da8ff;font-size:1.3rem;margin-top:24px;margin-bottom:12px;}}
    .module-content h2:first-child{{margin-top:0;}}
    .module-content h3{{color:#ddeeff;font-size:1.05rem;margin-top:20px;margin-bottom:8px;}}
    .module-content p{{color:#b0c4d8;line-height:1.7;margin:8px 0;}}
    .module-content ul{{color:#b0c4d8;line-height:1.9;padding-left:20px;}}
    .module-content li{{margin:6px 0;}}
    .module-content li strong{{color:#ddeeff;}}
    .module-content strong{{color:#ddeeff;}}
    .quiz-section{{background:#0d1a2e;border:1px solid #1a3050;border-radius:12px;padding:32px;}}
    .quiz-section h2{{color:#4da8ff;font-size:1.3rem;margin-bottom:20px;}}
    label:hover{{background:#1a4a7a;}}
    .submit-btn{{background:#4da8ff;color:#071018;padding:14px 32px;border:none;border-radius:8px;font-size:1rem;font-weight:700;cursor:pointer;margin-top:16px;}}
    .submit-btn:hover{{background:#79bfff;}}
    #result{{margin-top:20px;padding:20px;border-radius:8px;font-weight:700;display:none;}}
    .pass{{background:#0a3a1a;border:2px solid #22c55e;color:#22c55e;}}
    .fail{{background:#3a0a0a;border:2px solid #ef4444;color:#ef4444;}}
    </style></head><body>
    <div class=topbar>
        <h1>🎓 EdgeIQ Security Training</h1>
        <span class=badge>{module['name']}</span>
    </div>
    <div class=container>
        <div class=module-content>
            {module['content']}
        </div>
        <div class=quiz-section>
            <h2>📝 Module Quiz — {len(module['quiz'])} Questions</h2>
            <p style='color:#6a8aaa;margin-bottom:20px;'>Answer all questions correctly to pass. You can retake if you don't pass on the first try.</p>
            <form id=quizForm onsubmit='return handleSubmit(event)'>
                {quiz_html}
                <button type='submit' class=submit-btn>Submit Answers</button>
            </form>
            <div id=result></div>
        </div>
    </div>
    <script>
    const answers = {str({i: q['answer'] for i, q in enumerate(module['quiz'])})[1:-1]};
    function handleSubmit(e) {{
        e.preventDefault();
        let score = 0;
        let total = Object.keys(answers).length;
        for (let i = 0; i < total; i++) {{
            const sel = document.querySelector(`input[name="q${{i}}"]:checked`);
            if (sel && parseInt(sel.value) === answers[i]) score++;
        }}
        const pct = Math.round((score / total) * 100);
        const resultDiv = document.getElementById('result');
        if (pct >= 80) {{
            resultDiv.className = 'pass';
            resultDiv.innerHTML = `🎉 Passed! You scored ${{score}}/${{total}} (${{pct}}%). Submitting your results...`;
            resultDiv.style.display = 'block';
            // Auto-submit
            fetch(`/training/{assignment_id}/complete`, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{score: score, total: total, pct: pct}})
            }}).then(r => r.json()).then(d => {{
                if (d.redirect) window.location.href = d.redirect;
            }}).catch(() => {{
                // fallback: submit form normally
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/training/{assignment_id}/complete';
                document.body.appendChild(form);
                form.submit();
            }});
        }} else {{
            resultDiv.className = 'fail';
            resultDiv.innerHTML = `❌ Not quite — ${{score}}/${{total}} (${{pct}}%). You need 80% to pass. Review the material above and try again.`;
            resultDiv.style.display = 'block';
        }}
        return false;
    }}
    </script>
    </body></html>"""

@app.route('/training/<assignment_id>/complete', methods=['POST'])
def complete_training(assignment_id):
    assignment = _store['training_assignments'].get(assignment_id)
    if not assignment:
        return jsonify({'error': 'Assignment not found'}), 404
    if assignment.get('completed_at'):
        return jsonify({'redirect': f'/training/{assignment_id}/certificate'})
    # Try to read JSON score from body
    import json as _json
    data = None
    try:
        data = _json.loads(request.data)
    except Exception:
        pass
    score_data = {}
    if data:
        score_data = {'quiz_score': data.get('score'), 'quiz_total': data.get('total'), 'quiz_pct': data.get('pct')}
    assignment['completed_at'] = _now()
    assignment['status'] = 'completed'
    assignment.update(score_data)
    _persist_store()
    return jsonify({'redirect': f'/training/{assignment_id}/certificate', 'status': 'completed'})


@app.route('/training/<assignment_id>/certificate', methods=['GET'])
def training_certificate(assignment_id):
    assignment = _store['training_assignments'].get(assignment_id)
    if not assignment:
        return "Certificate not found.", 404
    if assignment.get('status') != 'completed':
        return "<html><body style='font-family:Arial;background:#070d17;color:#ddeeff;padding:40px;text-align:center;'><h2>Certificate not available yet.</h2><p>Complete the training module and quiz first.</p><a href='/training/{}' style='color:#4da8ff;'>Go to Training</a></body></html>".format(assignment_id), 400
    module = next((m for m in TRAINING_MODULES if m['id'] == assignment['module_id']), None)
    from datetime import datetime
    completed = assignment.get('completed_at', _now())
    score = assignment.get('quiz_score', 'N/A')
    total = assignment.get('quiz_total', 'N/A')
    pct = assignment.get('quiz_pct', 'N/A')
    cert_id = assignment_id[:12].upper()
    return f"""<!DOCTYPE html>
    <html><head><title>Training Certificate</title><style>
    body{{font-family:'Georgia',serif;background:#070d17;color:#ddeeff;margin:0;padding:0;}}
    .cert{{max-width:800px;margin:60px auto;background:#fff;color:#1a1a1a;border:3px solid #4da8ff;border-radius:16px;padding:60px;text-align:center;position:relative;}}
    .cert::before{{content:'';position:absolute;top:12px;left:12px;right:12px;bottom:12px;border:1px solid #4da8ff;border-radius:10px;pointer-events:none;}}
    .corner{{position:absolute;width:40px;height:40px;}}
    .tl{{top:20px;left:20px;border-top:3px solid #4da8ff;border-left:3px solid #4da8ff;}}
    .tr{{top:20px;right:20px;border-top:3px solid #4da8ff;border-right:3px solid #4da8ff;}}
    .bl{{bottom:20px;left:20px;border-bottom:3px solid #4da8ff;border-left:3px solid #4da8ff;}}
    .br{{bottom:20px;right:20px;border-bottom:3px solid #4da8ff;border-right:3px solid #4da8ff;}}
    h1{{font-size:2rem;color:#4da8ff;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:8px;}}
    .sub{{font-size:1rem;color:#555;letter-spacing:0.05em;margin-bottom:40px;}}
    .recipient{{font-size:2.5rem;font-weight:bold;color:#1a1a1a;margin:20px 0;font-family:'Segoe UI',Arial,sans-serif;}}
    .module{{font-size:1.1rem;color:#333;margin:20px 0;}}
    .score{{font-size:0.9rem;color:#666;margin-bottom:30px;}}
    .meta{{font-size:0.82rem;color:#888;border-top:1px solid #ddd;padding-top:20px;margin-top:40px;}}
    .seal{{position:absolute;bottom:40px;right:60px;width:80px;height:80px;background:#4da8ff;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold;font-size:0.7rem;text-align:center;line-height:1.2;}}
    .company{{font-size:1.5rem;font-weight:bold;color:#1a1a1a;margin-bottom:4px;}}
    .tagline{{font-size:0.85rem;color:#666;margin-bottom:30px;}}
    </style></head><body>
    <div class=cert>
        <div class='corner tl'></div><div class='corner tr'></div><div class='corner bl'></div><div class='corner br'></div>
        <h1>Certificate of Completion</h1>
        <div class=sub>Security Awareness Training</div>
        <div class=company>EdgeIQ PhishSim</div>
        <div class=tagline>Human Layer Security Platform</div>
        <p style='font-size:0.9rem;color:#555;'>This certifies successful completion of</p>
        <div class=recipient>{module['name'] if module else assignment.get('module_name', 'Security Training Module')}</div>
        <div class=module>Duration: {module['duration_minutes'] if module else '?'} minutes &nbsp;|&nbsp; Category: {module['category'].replace('_',' ').title() if module else 'General'}</div>
        <div class=score>Quiz Score: {score}/{total} ({pct}% — Passed @ 80% threshold)</div>
        <div class=meta>
            Certificate ID: {cert_id}<br>
            Completed: {completed}<br>
            EdgeIQ PhishSim — edgeiq-phishsim.onrender.com
        </div>
        <div class=seal>EdgeIQ<br>Certified</div>
    </div>
    </body></html>"""

# ─── Training Compliance Dashboard ──────────────────────────────────────

@app.route('/dashboard/training', methods=['GET'])
def training_dashboard():
    """Manager view: training compliance across all campaigns."""
    campaigns = list(_store['campaigns'].values())
    all_assignments = list(_store['training_assignments'].values())

    # Per-campaign breakdown
    campaign_rows = []
    for c in reversed(campaigns[-10:]):  # last 10 campaigns
        cid = c['id']
        c_assignments = [a for a in all_assignments if a.get('campaign_id') == cid or a.get('send_id', '').startswith(cid)]
        total = len(c_assignments)
        completed = sum(1 for a in c_assignments if a.get('status') == 'completed')
        pct = round(completed / total * 100, 1) if total > 0 else 0
        campaign_rows.append({
            'id': cid,
            'name': c.get('name', 'Untitled'),
            'plan': c.get('plan', 'starter'),
            'status': c.get('status', 'draft'),
            'total_assigned': total,
            'completed': completed,
            'pct': pct,
        })

    # Overall stats
    total_assignments = len(all_assignments)
    total_completed = sum(1 for a in all_assignments if a.get('status') == 'completed')
    overall_pct = round(total_completed / total_assignments * 100, 1) if total_assignments > 0 else 0

    # Per-user breakdown (all assignments, most recent first)
    user_map = {}
    for a in all_assignments:
        tid = a.get('target_id', 'unknown')
        if tid not in user_map:
            target = _store['targets'].get(tid, {})
            user_map[tid] = {'target_id': tid, 'name': target.get('first_name', '') + ' ' + target.get('last_name', ''), 'email': target.get('email', ''), 'assignments': []}
        user_map[tid]['assignments'].append(a)

    user_rows = []
    for uid, udata in user_map.items():
        total_u = len(udata['assignments'])
        done_u = sum(1 for a in udata['assignments'] if a.get('status') == 'completed')
        pct_u = round(done_u / total_u * 100, 1) if total_u > 0 else 0
        scores = [a.get('quiz_score') for a in udata['assignments'] if a.get('quiz_score') is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else None
        user_rows.append({
            'name': udata['name'] or 'Unknown',
            'email': udata['email'],
            'total': total_u,
            'completed': done_u,
            'pct': pct_u,
            'avg_score': avg_score,
        })
    user_rows.sort(key=lambda x: x['pct'])

    # Build table HTML
    def status_badge(pct):
        if pct >= 80: return "<span style='background:#0a3a1a;color:#22c55e;padding:3px 8px;border-radius:10px;font-size:0.78rem;font-weight:700;'>✓ Complete</span>"
        if pct > 0: return "<span style='background:#3a2a00;color:#f59e0b;padding:3px 8px;border-radius:10px;font-size:0.78rem;font-weight:700;'>⏳ In Progress</span>"
        return "<span style='background:#1a1a2a;color:#6a8aaa;padding:3px 8px;border-radius:10px;font-size:0.78rem;'>⊙ Not Started</span>"

    campaign_tbl = ''.join(f"""<tr>
        <td style='padding:10px;border-bottom:1px solid #1a3050;'>{r['name']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;'><span style='font-size:0.78rem;background:#0d2847;color:#4da8ff;padding:2px 8px;border-radius:8px;'>{r['plan']}</span></td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;'>{r['status']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;'>{r['total_assigned']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;'>{r['completed']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;font-weight:700;color:{'#22c55e' if r['pct']>=80 else '#f59e0b' if r['pct']>0 else '#6a8aaa'};'>{r['pct']}%</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;'>{status_badge(r['pct'])}</td>
    </tr>""" for r in campaign_rows)

    user_tbl = ''.join(f"""<tr>
        <td style='padding:10px;border-bottom:1px solid #1a3050;'>{r['name']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;color:#6a8aaa;font-size:0.82rem;'>{r['email']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;'>{r['total']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;'>{r['completed']}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;font-weight:700;color:{'#22c55e' if r['pct']>=80 else '#f59e0b' if r['pct']>0 else '#6a8aaa'};'>{r['pct']}%</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;text-align:center;'>{r['avg_score'] if r['avg_score'] else '—'}</td>
        <td style='padding:10px;border-bottom:1px solid #1a3050;'>{status_badge(r['pct'])}</td>
    </tr>""" for r in user_rows[:50])  # cap at 50 users display

    return f"""<!DOCTYPE html>
    <html><head><title>Training Compliance Dashboard</title><style>
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#070d17;color:#ddeeff;margin:0;}}
    .topbar{{background:#0d1a2e;border-bottom:1px solid #1a3050;padding:16px 24px;display:flex;align-items:center;gap:16px;}}
    .topbar h1{{font-size:1.1rem;color:#4da8ff;margin:0;}}
    .back{{color:#4da8ff;text-decoration:none;font-size:0.85rem;}}
    .stat-row{{display:flex;gap:20px;padding:28px 24px;flex-wrap:wrap;}}
    .stat-card{{background:#0d1a2e;border:1px solid #1a3050;border-radius:12px;padding:24px;flex:1;min-width:160px;}}
    .stat-card strong{{display:block;font-size:2rem;font-weight:800;color:#4da8ff;}}
    .stat-card span{{font-size:0.8rem;color:#6a8aaa;text-transform:uppercase;letter-spacing:0.08em;}}
    .section{{padding:0 24px 40px;}}
    .section h2{{font-size:1.1rem;font-weight:700;color:#fff;margin-bottom:16px;padding-top:16px;}}
    table{{width:100%;border-collapse:collapse;background:#0d1a2e;border:1px solid #1a3050;border-radius:12px;overflow:hidden;}}
    th{{background:#0a1525;text-align:left;padding:12px 10px;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.08em;color:#6a8aaa;border-bottom:1px solid #1a3050;}}
    th.c{{text-align:center;}}
    td{{padding:10px;font-size:0.88rem;}}
    tr:hover{{background:#0f2035;}}
    .empty{{text-align:center;padding:40px;color:#4a6080;}}
    .badge-ok{{background:#0a3a1a;color:#22c55e;}}
    .badge-warn{{background:#3a2a00;color:#f59e0b;}}
    .badge-none{{background:#1a1a2a;color:#6a8aaa;}}
    </style></head><body>
    <div class=topbar>
        <h1>🎓 Training Compliance Dashboard</h1>
        <a href='/' class=back>← Back to PhishSim</a>
    </div>
    <div class=stat-row>
        <div class=stat-card><strong>{total_assignments}</strong><span>Total Assigned</span></div>
        <div class=stat-card><strong>{total_completed}</strong><span>Completed</span></div>
        <div class=stat-card><strong style='color:{'#22c55e' if overall_pct>=80 else '#f59e0b'};'>{overall_pct}%</strong><span>Overall Completion</span></div>
        <div class=stat-card><strong>{len(set(a.get('target_id') for a in all_assignments))}</strong><span>Employees Trained</span></div>
    </div>
    <div class=section>
        <h2>📊 By Campaign</h2>
        {'''<table><thead><tr><th>Campaign</th><th>Plan</th><th>Status</th><th class=c>Assigned</th><th class=c>Completed</th><th class=c>Rate</th><th>Status</th></tr></thead><tbody>'''+campaign_tbl+'''</tbody></table>''' if campaign_tbl else '<div class=empty>No campaigns yet.</div>'}
    </div>
    <div class=section>
        <h2>👥 By Employee</h2>
        {'''<table><thead><tr><th>Name</th><th>Email</th><th class=c>Assigned</th><th class=c>Completed</th><th class=c>Rate</th><th class=c>Avg Score</th><th>Status</th></tr></thead><tbody>'''+user_tbl+'''</tbody></table>''' if user_tbl else '<div class=empty>No training assignments yet. Launch a phishing campaign to auto-assign training.</div>'}
    </div>
    </body></html>"""


@app.route('/api/training/compliance', methods=['GET'])
def api_training_compliance():
    """JSON compliance data for external dashboards / webhooks."""
    campaign_id = request.args.get('campaign_id')
    assignments = list(_store['training_assignments'].values())
    if campaign_id:
        assignments = [a for a in assignments if a.get('campaign_id') == campaign_id]
    total = len(assignments)
    completed = sum(1 for a in assignments if a.get('status') == 'completed')
    scores = [a.get('quiz_pct') for a in assignments if a.get('quiz_pct') is not None]
    return jsonify({
        'total_assigned': total,
        'completed': completed,
        'not_started': total - completed,
        'completion_rate': round(completed / total * 100, 1) if total > 0 else 0,
        'avg_quiz_score': round(sum(scores) / len(scores), 1) if scores else None,
        'by_module': {
            m['id']: {
                'assigned': sum(1 for a in assignments if a.get('module_id') == m['id']),
                'completed': sum(1 for a in assignments if a.get('module_id') == m['id'] and a.get('status') == 'completed'),
            } for m in TRAINING_MODULES
        }
    })

@app.route('/api/training/assignments', methods=['GET'])
def api_list_assignments():
    """List training assignments, optionally filtered by campaign_id or target_id."""
    campaign_id = request.args.get('campaign_id')
    target_id = request.args.get('target_id')
    assignments = list(_store['training_assignments'].values())
    if campaign_id:
        assignments = [a for a in assignments if a.get('campaign_id') == campaign_id]
    if target_id:
        assignments = [a for a in assignments if a.get('target_id') == target_id]
    return jsonify({'assignments': assignments, 'total': len(assignments)})

@app.route('/api/campaigns/<cid>/training-summary', methods=['GET'])
def api_campaign_training_summary(cid):
    """Training summary for a specific campaign."""
    sends = [s for s in _store['campaign_sends'].values() if s.get('campaign_id') == cid]
    assignments = [a for a in _store['training_assignments'].values() if a.get('campaign_id') == cid]
    sent = sum(1 for s in sends if s.get('sent_at'))
    clicked = sum(1 for s in sends if s.get('clicked_at'))
    assigned = len(assignments)
    completed = sum(1 for a in assignments if a.get('status') == 'completed')
    return jsonify({
        'campaign_id': cid,
        'emails_sent': sent,
        'clicked': clicked,
        'training_assigned': assigned,
        'training_completed': completed,
        'completion_rate': round(completed / assigned * 100, 1) if assigned > 0 else 0,
        'click_to_training_rate': round(assigned / clicked * 100, 1) if clicked > 0 else 0,
    })



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
