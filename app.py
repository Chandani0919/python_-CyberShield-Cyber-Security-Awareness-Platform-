"""CyberShield: a beginner-friendly cybersecurity awareness platform."""

import os
import re
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

import click
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("CYBERSHIELD_DATABASE", os.path.join(app.root_path, "cybershield.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

STARTER_QUESTIONS = [
    ("What should you do with an unexpected link asking you to sign in?",
     ["Click it to check whether it looks legitimate", "Open the official site directly instead", "Forward it to coworkers", "Reply with your password"], 1,
     "Navigate to the service using a trusted bookmark or address."),
    ("Which password is the safest choice?",
     ["A unique, long passphrase stored in a password manager", "The same complex password everywhere", "Your pet's name plus your birth year", "A short password changed every week"], 0,
     "Use a unique, long password for every account and store it in a password manager."),
    ("Why should you enable multifactor authentication?",
     ["It replaces the need for updates", "It adds a second verification step if a password is stolen", "It makes every email encrypted", "It prevents all phishing"], 1,
     "MFA makes an account harder to access with a password alone."),
    ("You receive an unexpected attachment from a familiar contact. What is best?",
     ["Open it because you know the sender", "Verify the message with the sender through another channel", "Disable antivirus before opening", "Upload it to a public file-sharing site"], 1,
     "Compromised accounts can send malicious messages. Verify unexpected files independently."),
    ("What does HTTPS tell you about a website?",
     ["The site is trustworthy and safe", "The connection is encrypted, but the site itself may still be malicious", "The site cannot collect your data", "The site has no phishing content"], 1,
     "HTTPS protects data in transit; it does not prove that a website is legitimate."),
    ("What is the safest action when using public Wi-Fi?",
     ["Turn off device updates", "Use a trusted VPN and avoid sensitive activity on unknown networks", "Share files with nearby devices", "Reuse your work password"], 1,
     "Prefer trusted networks and use a reputable VPN when public Wi-Fi is unavoidable."),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def init_db():
    database = get_db()
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            options TEXT NOT NULL,
            answer INTEGER NOT NULL,
            explanation TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quiz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            score INTEGER NOT NULL,
            total INTEGER NOT NULL,
            completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    count = database.execute("SELECT COUNT(*) FROM quiz_questions").fetchone()[0]
    if count == 0:
        database.executemany(
            "INSERT INTO quiz_questions (question, options, answer, explanation) VALUES (?, ?, ?, ?)",
            [(q, "\n".join(options), answer, explanation)
             for q, options, answer, explanation in STARTER_QUESTIONS],
        )
    database.commit()


with app.app_context():
    init_db()


def log_activity(action, details=""):
    if g.get("user"):
        database = get_db()
        database.execute(
            "INSERT INTO security_logs (user_id, action, details) VALUES (?, ?, ?)",
            (g.user["id"], action, details[:200]),
        )
        database.commit()


@app.before_request
def load_user_and_check_csrf():
    user_id = session.get("user_id")
    g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() if user_id else None
    if request.method == "POST":
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        expected = session.get("csrf_token", "")
        if not submitted or not secrets.compare_digest(submitted, expected):
            abort(400, description="Your session token is missing or expired. Refresh the page and try again.")


@app.context_processor
def template_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Sign in to access your security dashboard.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def record_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%b %d, %Y")
    except (TypeError, ValueError):
        return value


@app.template_filter("date")
def format_date(value):
    return record_date(value)


@app.cli.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--email", prompt=True)
@click.password_option()
def create_admin(username, email, password):
    """Create or promote an administrator account."""
    if len(password) < 12:
        raise click.ClickException("Admin password must be at least 12 characters.")
    database = get_db()
    existing = database.execute("SELECT id FROM users WHERE email = ?", (email.strip(),)).fetchone()
    if existing:
        database.execute("UPDATE users SET role = 'admin' WHERE id = ?", (existing["id"],))
    else:
        database.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            (username.strip(), email.strip(), generate_password_hash(password)),
        )
    database.commit()
    click.echo(f"Administrator account ready for {email.strip()}.")


@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or len(username) > 40 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a display name (up to 40 characters) and a valid email address.", "error")
        elif len(password) < 10:
            flash("Choose a password with at least 10 characters.", "error")
        else:
            try:
                database = get_db()
                database.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                database.commit()
                user = database.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                g.user = user
                log_activity("Account created", "Welcome to CyberShield")
                flash("Your account is ready. Welcome to CyberShield!", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            g.user = user
            log_activity("Signed in")
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    log_activity("Signed out")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    database = get_db()
    results = database.execute(
        "SELECT * FROM quiz_results WHERE user_id = ? ORDER BY completed_at DESC LIMIT 5",
        (g.user["id"],),
    ).fetchall()
    activities = database.execute(
        "SELECT * FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 6",
        (g.user["id"],),
    ).fetchall()
    stats = database.execute(
        "SELECT COUNT(*) AS attempts, COALESCE(MAX(ROUND(score * 100.0 / total)), 0) AS best "
        "FROM quiz_results WHERE user_id = ?",
        (g.user["id"],),
    ).fetchone()
    total_questions = database.execute("SELECT COUNT(*) FROM quiz_questions").fetchone()[0]
    average = database.execute(
        "SELECT COALESCE(ROUND(AVG(score * 100.0 / total)), 0) "
        "FROM quiz_results WHERE user_id = ?", (g.user["id"],)
    ).fetchone()[0]
    return render_template(
        "dashboard.html", results=results, activities=activities, stats=stats,
        total_questions=total_questions, average=average,
    )


def analyze_password(password):
    checks = [
        (len(password) >= 12, "Use at least 12 characters."),
        (len(password) >= 16, "Longer passphrases are harder to guess."),
        (bool(re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)), "Mix uppercase and lowercase letters."),
        (bool(re.search(r"\d", password)), "Add a number."),
        (bool(re.search(r"[^A-Za-z0-9]", password)), "Add a symbol."),
        (not re.search(r"(.)\1{2,}", password), "Avoid repeating the same character."),
        (not re.search(r"password|qwerty|letmein|123456|admin", password, re.I), "Avoid common words and patterns."),
    ]
    score = round(sum(passed for passed, _tip in checks) * 100 / len(checks))
    recommendations = [tip for passed, tip in checks if not passed]
    if not recommendations:
        recommendations = ["Excellent foundation. Use it only for one account and store it safely."]
    label = "Strong" if score >= 86 else "Good" if score >= 58 else "Needs work"
    return {"score": score, "label": label, "recommendations": recommendations}


@app.route("/password", methods=["GET", "POST"])
@login_required
def password_checker():
    result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if not password:
            flash("Enter a password to analyze.", "error")
        else:
            result = analyze_password(password)
            # Never retain the supplied password in an activity log.
            log_activity("Checked password strength", f"Strength score: {result['score']}/100")
    return render_template("password.html", result=result)


def analyze_message(text):
    lowered = text.lower()
    signals = [
        ("urgent language", r"\b(urgent|immediately|act now|within 24 hours|final warning)\b"),
        ("credential request", r"\b(password|login|sign in|verify your account|credentials)\b"),
        ("payment or prize bait", r"\b(wire transfer|gift card|prize|lottery|payment overdue)\b"),
        ("threatening language", r"\b(suspended|locked|terminated|legal action)\b"),
        ("suspicious link wording", r"\b(click here|open attachment|confirm your account)\b"),
    ]
    matches = [name for name, pattern in signals if re.search(pattern, lowered)]
    for raw_url in re.findall(r"""(?:https?://|www\.)[^\s<>"']+""", text, flags=re.I):
        candidate = raw_url.rstrip(".,;:!?)]}")
        parsed = urlparse(candidate if candidate.startswith(("http://", "https://")) else "https://" + candidate)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme != "https":
            matches.append("link without HTTPS")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            matches.append("internationalized domain")
        if re.search(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
            matches.append("IP address used as a website")
        if "@" in parsed.netloc:
            matches.append("misleading link address")
        if len(hostname) > 45 or hostname.count("-") >= 3:
            matches.append("unusual domain structure")
    matches = list(dict.fromkeys(matches))
    score = min(100, len(matches) * 22)
    label = "High risk" if score >= 55 else "Caution" if score >= 22 else "Lower risk"
    return {"score": score, "label": label, "signals": matches}


@app.route("/phishing", methods=["GET", "POST"])
@login_required
def phishing_checker():
    result = None
    if request.method == "POST":
        text = request.form.get("content", "").strip()
        if not text or len(text) > 5000:
            flash("Enter text to analyze (up to 5,000 characters).", "error")
        else:
            result = analyze_message(text)
            log_activity("Analyzed suspicious message", f"Risk: {result['label']}")
    return render_template("phishing.html", result=result)


@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    database = get_db()
    questions = database.execute("SELECT * FROM quiz_questions ORDER BY id").fetchall()
    if request.method == "POST":
        if not questions:
            flash("There are no quiz questions available yet.", "error")
            return redirect(url_for("quiz"))
        correct = 0
        for question in questions:
            selected = request.form.get(f"q{question['id']}", "")
            if selected.isdigit() and int(selected) == question["answer"]:
                correct += 1
        cursor = database.execute(
            "INSERT INTO quiz_results (user_id, score, total) VALUES (?, ?, ?)",
            (g.user["id"], correct, len(questions)),
        )
        database.commit()
        log_activity("Completed security quiz", f"Score: {correct}/{len(questions)}")
        return redirect(url_for("certificate", result_id=cursor.lastrowid))
    history = database.execute(
        "SELECT * FROM quiz_results WHERE user_id = ? ORDER BY completed_at DESC LIMIT 5",
        (g.user["id"],),
    ).fetchall()
    return render_template("quiz.html", questions=questions, history=history)


@app.route("/certificate/<int:result_id>")
@login_required
def certificate(result_id):
    result = get_db().execute(
        "SELECT r.*, u.username FROM quiz_results r JOIN users u ON u.id = r.user_id "
        "WHERE r.id = ? AND r.user_id = ?", (result_id, g.user["id"])
    ).fetchone()
    if not result:
        abort(404)
    return render_template("certificate.html", result=result)


@app.route("/awareness")
@login_required
def awareness():
    return render_template("awareness.html")


@app.route("/profile")
@login_required
def profile():
    database = get_db()
    results = database.execute(
        "SELECT * FROM quiz_results WHERE user_id = ? ORDER BY completed_at DESC",
        (g.user["id"],),
    ).fetchall()
    activities = database.execute(
        "SELECT * FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
        (g.user["id"],),
    ).fetchall()
    return render_template("profile.html", results=results, activities=activities)


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    database = get_db()
    if request.method == "POST":
        question = request.form.get("question", "").strip()
        options = [item.strip() for item in request.form.getlist("options") if item.strip()]
        answer = request.form.get("answer", "")
        explanation = request.form.get("explanation", "").strip()
        if not question or len(options) != 4 or not answer.isdigit() or int(answer) not in range(4):
            flash("Add a question, exactly four answer options, and select the correct option.", "error")
        else:
            database.execute(
                "INSERT INTO quiz_questions (question, options, answer, explanation) VALUES (?, ?, ?, ?)",
                (question, "\n".join(options), int(answer), explanation or "Review the correct answer and keep learning."),
            )
            database.commit()
            log_activity("Added quiz question", question[:120])
            flash("Quiz question added.", "success")
            return redirect(url_for("admin"))
    users = database.execute(
        "SELECT u.id, u.username, u.email, u.role, u.created_at, "
        "COUNT(r.id) AS attempts FROM users u LEFT JOIN quiz_results r ON r.user_id = u.id "
        "GROUP BY u.id ORDER BY u.created_at DESC"
    ).fetchall()
    stats = {
        "users": database.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "attempts": database.execute("SELECT COUNT(*) FROM quiz_results").fetchone()[0],
        "questions": database.execute("SELECT COUNT(*) FROM quiz_questions").fetchone()[0],
        "average": database.execute(
            "SELECT COALESCE(ROUND(AVG(score * 100.0 / total)), 0) FROM quiz_results"
        ).fetchone()[0],
    }
    return render_template("admin.html", users=users, stats=stats)


@app.post("/admin/users/<int:user_id>/role")
@admin_required
def change_user_role(user_id):
    if user_id == g.user["id"]:
        flash("You cannot change your own administrator role.", "error")
    else:
        database = get_db()
        user = database.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            abort(404)
        new_role = "admin" if user["role"] == "user" else "user"
        database.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        database.commit()
        log_activity("Changed user role", f"User ID {user_id}: {new_role}")
        flash(f"User role updated to {new_role}.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def handle_http_error(error):
    return render_template("error.html", error=error), error.code


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
