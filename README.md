# CyberShield

A beginner-friendly cybersecurity awareness platform built with Python, Flask, SQLite, HTML, CSS, and JavaScript.

## Run locally

1. Install Python 3.10 or newer.
2. (Optional but recommended) Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install the one runtime dependency:

   ```powershell
   pip install -r requirements.txt
   ```

4. Set a stable secret key, then start Flask:

   ```powershell
   $env:SECRET_KEY = "replace-this-with-a-long-random-secret"
   flask --app app run --debug
   ```

   Open http://127.0.0.1:5000 and register an account. The SQLite database and starter quiz questions are created automatically.

5. To create the first administrator, open another terminal with the same `SECRET_KEY` and run:

   ```powershell
   flask --app app create-admin
   ```

   The command securely prompts for the admin password (minimum 12 characters). Existing accounts with that email are promoted instead of duplicated. Do not enable Flask debug mode or use the development server in production.

## Project layout

```text
app.py                  Flask routes, SQLite setup, and application logic
templates/              Jinja pages and shared layout
static/css/style.css    Responsive Y2K cyberpunk interface
static/js/app.js        Password meter, charts, and interface interactions
requirements.txt        Python dependency
cybershield.db          Created automatically when the app starts
```

## Features

- Secure registration, password hashing, login sessions, CSRF protection, and logout.
- Personal dashboard, quiz history, security activity, and interactive Chart.js visualization.
- Password strength recommendations. Passwords are analyzed transiently and are never stored.
- Local phishing heuristics for message text and URLs. URLs are not fetched; this is an educational indicator, not a reputation or malware scanner.
- Scored security quiz, per-user printable completion certificates, and starter questions.
- Awareness tips, profile progress, and an administrator panel for user roles, quiz questions, and aggregate statistics.

Use this app as an awareness-training demo, not as a replacement for professional security tools.
