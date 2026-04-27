# EdgeIQ PhishSim

Automated phishing simulation and security awareness training for SMBs.

## Quick Start

### 1. Deploy to Render
Connect the repo to Render.com and it will auto-deploy from `render.yaml`.

### 2. Configure SMTP
Set these environment variables in Render:

| Variable | Value |
|---|---|
| `SMTP_HOST` | `smtp.mailgun.org` |
| `SMTP_PORT` | `587` |
| `SMTP_USER` | Your Mailgun SMTP login |
| `SMTP_PASS` | Your Mailgun SMTP password |
| `SENDING_DOMAIN` | `simulate.edgeiqlabs.com` |
| `APP_URL` | Your Render app URL |

### 3. Set Up Mailgun DNS
Add these DNS records to `simulate.edgeiqlabs.com`:

```
Type    Name    Value
TXT     @       v=spf1 include:mailgun.org ~all
MX      @       mxa.mailgun.org
MX      @       mxb.mailgun.org
```

Verify with Mailgun before sending.

## API Reference

### Templates
```
GET    /api/templates          — List all templates
POST   /api/templates          — Create template
GET    /api/templates/:id       — Get template
```

### Campaigns
```
GET    /api/campaigns           — List campaigns
POST   /api/campaigns           — Create campaign (draft)
GET    /api/campaigns/:id      — Get campaign + stats
POST   /api/campaigns/:id/launch — Send emails now
POST   /api/campaigns/:id/abort — Stop campaign
```

### Targets
```
GET    /api/targets             — List targets
POST   /api/targets             — Add single target
POST   /api/targets/bulk       — Bulk import (JSON array)
```

### Reporting
```
GET    /api/reports/campaign/:id — Full funnel report
GET    /api/training/assignments — List training assignments
```

## Built-in Templates

| ID | Name | Difficulty |
|---|---|---|
| `tpl_microsoft_365` | Microsoft 365 Password Expired | Easy |
| `tpl_fedex_delivery` | FedEx Delivery Failed | Medium |
| `tpl_ceo_fraud` | CEO Urgent Request | Hard |

## Architecture

- **Flask** backend — campaign CRUD, tracking, reporting
- **SMTP** via Mailgun — email sending
- **In-memory store** (MVP) — swap for PostgreSQL in production
- **Render** free tier — spins down after 15 min inactivity (cold start ~30s)

## TODO

- [ ] PostgreSQL integration for persistent storage
- [ ] Training video player + quiz grading
- [ ] Employee risk scoring dashboard
- [ ] CSV target import
- [ ] Recurring campaign scheduling
- [ ] PDF report export
