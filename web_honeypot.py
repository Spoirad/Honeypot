# web_honeypot.py
# ----- Librerias -----
import logging
import os
import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from functools import wraps

# ----- Logging -----
logging_format = logging.Formatter('%(asctime)s %(message)s')

# ----- Decoradores -----

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session or 'role' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def employee_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "employee":
            http_logger.info(f"FORBIDDEN_EMPLOYEE_ACCESS ip={request.remote_addr} path={request.path}")
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            http_logger.info(f"FORBIDDEN_ADMIN_ACCESS ip={request.remote_addr} path={request.path}")
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return wrapper


# ----- HTTP Logger -----
http_logger = logging.getLogger('FunnelLogger')
http_logger.setLevel(logging.INFO)
# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

http_handler = RotatingFileHandler('logs/http_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

# ----- Honeypot Web (Flask) -----
def web_honeypot(input_username="admin", input_password="password"):
    app = Flask(__name__)
    app.secret_key = 'supersecretkey'  # Needed for flash messages

    # Configure upload folder
    UPLOAD_FOLDER = 'logs/web_uploads'
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    # ----- Routes -----

    @app.route("/")
    def index():
        # Si ya hay sesión, redirigir según rol
        if "role" in session:
            if session["role"] == "admin":
                return redirect(url_for("admin_panel"))
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    # -----  login -----
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            # Role is now determined by the username for this honeypot demo, 
            # or we can trust the form if we want to be flexible.
            # Let's use a simple hardcoded dict for demo purposes.
            
            # Demo credentials
            valid_users = {
                "admin": {"password": "password", "role": "admin"},
                "employee": {"password": "password", "role": "employee"},
                "j.perez": {"password": "password", "role": "employee"}
            }

            ip_address = request.remote_addr
            http_logger.info(f'LOGIN_ATTEMPT ip={ip_address} user="{username}"')

            if username in valid_users and valid_users[username]["password"] == password:
                role = valid_users[username]["role"]
                session['username'] = username
                session['role'] = role

                http_logger.info(f'LOGIN_SUCCESS ip={ip_address} user="{username}" role="{role}"')

                if role == "admin":
                    return redirect(url_for("admin_panel"))
                return redirect(url_for("dashboard"))
            else:
                http_logger.info(f'LOGIN_FAILURE ip={ip_address} user="{username}"')
                return render_template("login.html", error="Credenciales incorrectas"), 401

        return render_template("login.html")

    # -----  logout -----
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # -----  dashboard -----
    @app.route("/dashboard")
    @login_required
    @employee_required
    def dashboard():
        return render_template("dashboard_employee.html")

    # -----  upload -----
    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    @employee_required
    def upload():
        if request.method == "POST":
            if 'file' not in request.files:
                flash("No file part")
                return redirect(request.url)

            file = request.files['file']

            if file.filename == "":
                flash("No selected file")
                return redirect(request.url)

            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            file_size = os.path.getsize(save_path)
            ip = request.remote_addr

            http_logger.info(f'FILE_UPLOAD ip={ip} user="{session["username"]}" filename="{filename}" size={file_size}')

            flash("Archivo subido correctamente.")
            return redirect(url_for("upload"))

        return render_template("upload.html")

    @app.route("/profile")
    @login_required
    @employee_required
    def profile():
        return render_template("profile.html")

    @app.route("/documentation")
    @login_required
    @employee_required
    def documentation():
        return render_template("documentation.html")

    @app.route("/tickets")
    @login_required
    @employee_required
    def tickets():
        return render_template("tickets.html")
    

    # -----  admin ----- 

    @app.route("/admin_panel")
    @login_required
    @admin_required
    def admin_panel():
        return render_template("admin_panel.html")

    @app.route("/admin_users")
    @login_required
    @admin_required
    def admin_users():
        return render_template("admin_users.html")

    @app.route("/admin_documents")
    @login_required
    @admin_required
    def admin_documents():
        return render_template("admin_documents.html")

    @app.route("/admin_logs")
    @login_required
    @admin_required
    def admin_logs():
        return render_template("admin_logs.html")

    return app

def run_web_honeypot(port=5000, input_username="admin", input_password="password", host="0.0.0.0", debug=False):
    app = web_honeypot(input_username, input_password)
    app.run(host=host, port=port, debug=debug)

# añadido para pruebas (evita arranque automatico al importar)
if __name__ == "__main__":
    run_web_honeypot(port=5000, input_username="admin", input_password="admin", debug=True)
