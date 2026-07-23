# Tiny Second-hand Shopping Platform

A secure local demonstration marketplace built with Flask and SQLite.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:MARKET_SECRET = "replace-with-a-long-random-secret"
python app.py
```

Open `http://127.0.0.1:5000`. Every new account starts as a normal user with a virtual balance of 100,000 KRW.

Create a local administrator account when testing moderation:

```powershell
flask --app app create-admin --username admin
```

After logging in as that account, open `http://127.0.0.1:5000/admin`.

## Features

- Account registration and login
- Product listing, searching, and detail pages
- Seller messaging with a receiver block check
- Atomic virtual-balance transfer
- Administrator-only APIs for blocking a user or a product

## Security controls

- Passwords are stored with Werkzeug password hashing; session cookies are HTTPOnly and SameSite=Lax.
- Every database operation uses parameterized SQLite queries.
- Every POST form requires a per-session CSRF token.
- Authentication and administrator authorization are checked server-side.
- Input length, price, balance, ownership, and blocked-account checks are enforced in application code and database constraints.
- Jinja autoescaping protects rendered product and message content from stored XSS.

## Production notes

For a production deployment, use HTTPS, a managed secret store, rate limiting, audit logs, error monitoring, a separated database account, backups, and a proper authorization/audit workflow for administrator actions.
