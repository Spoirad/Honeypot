# web_honeypot.py
# ----- Librerias -----
import logging
import os
import json
import datetime
import uuid
import secrets
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from functools import wraps

# ----- Logging -----
logging_format = logging.Formatter('%(asctime)s %(message)s')

# ----- HTTP Logger -----
http_logger = logging.getLogger('HTTPFunnelLogger')
http_logger.setLevel(logging.INFO)
# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

http_handler = RotatingFileHandler('logs/http_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

# ----- Decoradores -----

def login_required(f):
    """Decorador que requiere sesión activa con username y role"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session or 'role' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def employee_required(f):
    """Decorador que requiere rol employee, loggea accesos prohibidos"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "employee":
            user = session.get("username", "anonymous")
            http_logger.info(f'forbidden_access ip={request.remote_addr} user="{user}" path="{request.path}" required_role="employee"')
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    """Decorador que requiere rol admin, loggea accesos prohibidos"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            user = session.get("username", "anonymous")
            http_logger.info(f'forbidden_access ip={request.remote_addr} user="{user}" path="{request.path}" required_role="admin"')
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return wrapper


# ----- Utilidades para archivos de datos -----

UPLOAD_METADATA_FILE = 'logs/upload_metadata.json'
TICKETS_FILE = 'logs/tickets.log'

def load_upload_metadata():
    """Carga metadatos de uploads desde JSON"""
    if os.path.exists(UPLOAD_METADATA_FILE):
        try:
            with open(UPLOAD_METADATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def save_upload_metadata(metadata_list):
    """Guarda metadatos de uploads en JSON"""
    with open(UPLOAD_METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata_list, f, indent=2, ensure_ascii=False)

def load_tickets():
    """Carga tickets desde archivo de log"""
    tickets = []
    if os.path.exists(TICKETS_FILE):
        try:
            with open(TICKETS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            tickets.append(json.loads(line))
                        except:
                            pass
        except:
            pass
    return tickets

def save_ticket(ticket):
    """Guarda un ticket en archivo de log (formato JSON lines)"""
    with open(TICKETS_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(ticket, ensure_ascii=False) + '\n')

def get_recent_log_entries(log_file, n=50):
    """Lee las últimas N entradas de un archivo de log"""
    entries = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                entries = [line.strip() for line in lines[-n:] if line.strip()]
                entries.reverse()  # Más recientes primero
        except:
            pass
    return entries


def generate_fake_siem_entries():
    """
    Genera entradas simuladas de un SIEM corporativo.
    Para mantener el realismo narrativo del honeypot - 
    el admin ve un SIEM "limitado", no los logs reales del honeypot.
    """
    import random
    
    # Timestamps variados (últimas horas/días)
    base_time = datetime.datetime.now()
    
    # Tipos de eventos SIEM corporativos
    siem_events = [
        # WAF Events
        {"type": "WAF", "severity": "MEDIUM", "msg": "SQL Injection attempt blocked", "src": "203.0.113.45", "dst": "10.0.1.50", "rule": "WAF-SQL-001"},
        {"type": "WAF", "severity": "HIGH", "msg": "XSS attack pattern detected", "src": "198.51.100.23", "dst": "10.0.1.50", "rule": "WAF-XSS-003"},
        {"type": "WAF", "severity": "LOW", "msg": "Rate limit exceeded", "src": "192.0.2.100", "dst": "10.0.1.50", "rule": "WAF-RATE-010"},
        {"type": "WAF", "severity": "MEDIUM", "msg": "Directory traversal attempt", "src": "203.0.113.88", "dst": "10.0.1.51", "rule": "WAF-PATH-002"},
        
        # EDR Events
        {"type": "EDR", "severity": "HIGH", "msg": "Suspicious PowerShell execution", "host": "WS-PC042", "user": "j.martinez", "process": "powershell.exe"},
        {"type": "EDR", "severity": "CRITICAL", "msg": "Mimikatz signature detected", "host": "SRV-DC01", "user": "SYSTEM", "process": "lsass.exe"},
        {"type": "EDR", "severity": "MEDIUM", "msg": "Unusual network connection", "host": "WS-PC117", "user": "a.gonzalez", "process": "chrome.exe"},
        {"type": "EDR", "severity": "LOW", "msg": "USB device connected", "host": "WS-PC089", "user": "m.rodriguez", "device": "Kingston USB"},
        
        # IAM Events  
        {"type": "IAM", "severity": "INFO", "msg": "User login successful", "user": "c.fernandez", "src": "10.0.5.22", "method": "SSO"},
        {"type": "IAM", "severity": "MEDIUM", "msg": "Multiple failed login attempts", "user": "admin", "src": "192.168.1.100", "attempts": "5"},
        {"type": "IAM", "severity": "HIGH", "msg": "Privilege escalation detected", "user": "temp_contractor", "action": "sudo", "target": "root"},
        {"type": "IAM", "severity": "INFO", "msg": "Password change completed", "user": "l.sanchez", "src": "10.0.3.45"},
        {"type": "IAM", "severity": "MEDIUM", "msg": "Account locked after failures", "user": "r.torres", "src": "external"},
        
        # VPN Events
        {"type": "VPN", "severity": "INFO", "msg": "VPN connection established", "user": "p.navarro", "src": "83.54.21.100", "location": "Madrid, ES"},
        {"type": "VPN", "severity": "MEDIUM", "msg": "VPN connection from unusual location", "user": "j.perez", "src": "45.67.89.12", "location": "Unknown"},
        {"type": "VPN", "severity": "HIGH", "msg": "VPN brute force attempt detected", "src": "185.220.101.33", "attempts": "127"},
        {"type": "VPN", "severity": "INFO", "msg": "VPN session terminated", "user": "m.garcia", "duration": "4h 23m"},
        
        # Firewall Events
        {"type": "FW", "severity": "LOW", "msg": "Outbound connection blocked", "src": "10.0.2.55", "dst": "45.33.32.156:4444", "rule": "FW-OUT-BLOCK"},
        {"type": "FW", "severity": "MEDIUM", "msg": "Port scan detected", "src": "203.0.113.200", "dst": "10.0.0.0/24", "ports": "22,23,80,443,3389"},
        {"type": "FW", "severity": "HIGH", "msg": "C2 communication attempt", "src": "10.0.2.88", "dst": "evil.example.com", "rule": "FW-THREAT-C2"},
        
        # SIEM Correlation
        {"type": "SIEM", "severity": "CRITICAL", "msg": "APT activity pattern detected", "correlation_id": "CORR-2024-0892", "events": "15"},
        {"type": "SIEM", "severity": "HIGH", "msg": "Data exfiltration suspected", "host": "SRV-FILE01", "volume": "2.3GB", "dst": "external"},
        {"type": "SIEM", "severity": "MEDIUM", "msg": "Anomalous user behavior", "user": "service_account_01", "score": "87/100"},
    ]
    
    entries = []
    for i, event in enumerate(siem_events):
        # Generar timestamp con variación
        delta = datetime.timedelta(minutes=random.randint(5, 1440))  # Últimas 24h
        ts = (base_time - delta).strftime("%Y-%m-%d %H:%M:%S")
        
        # Formatear entrada según tipo
        event_type = event["type"]
        severity = event["severity"]
        msg = event["msg"]
        
        # Construir línea de log según el tipo
        if event_type == "WAF":
            line = f"{ts} [{severity}] WAF: {msg} | src={event['src']} dst={event['dst']} rule={event['rule']}"
        elif event_type == "EDR":
            line = f"{ts} [{severity}] EDR: {msg} | host={event['host']} user={event.get('user', 'N/A')} process={event.get('process', 'N/A')}"
        elif event_type == "IAM":
            line = f"{ts} [{severity}] IAM: {msg} | user={event['user']} src={event.get('src', 'N/A')}"
        elif event_type == "VPN":
            line = f"{ts} [{severity}] VPN: {msg} | user={event.get('user', 'N/A')} src={event.get('src', 'N/A')}"
        elif event_type == "FW":
            line = f"{ts} [{severity}] FIREWALL: {msg} | src={event.get('src', 'N/A')} dst={event.get('dst', 'N/A')}"
        elif event_type == "SIEM":
            line = f"{ts} [{severity}] SIEM-CORRELATION: {msg} | id={event.get('correlation_id', 'N/A')}"
        else:
            line = f"{ts} [{severity}] {event_type}: {msg}"
        
        entries.append(line)
    
    # Ordenar por timestamp (más recientes primero) y añadir variabilidad
    random.shuffle(entries)  # Mezclar para que no se vean patrones
    entries.sort(reverse=True)  # Ordenar por timestamp
    
    return entries

def get_stats_from_logs():
    """Calcula estadísticas básicas desde http_audits.log para admin panel"""
    stats = {
        'active_users': 0,
        'failed_attempts': 0,
        'uploads_count': 0,
        'forbidden_count': 0,
        'recent_activity': []
    }
    
    log_file = 'logs/http_audits.log'
    if not os.path.exists(log_file):
        return stats
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        unique_users = set()
        for line in lines:
            if 'login_success' in line:
                stats['active_users'] += 1
                # Extraer usuario
                if 'user="' in line:
                    start = line.find('user="') + 6
                    end = line.find('"', start)
                    if end > start:
                        unique_users.add(line[start:end])
            if 'login_failure' in line:
                stats['failed_attempts'] += 1
            if 'file_upload' in line:
                stats['uploads_count'] += 1
            if 'forbidden_access' in line:
                stats['forbidden_count'] += 1
        
        stats['active_users'] = len(unique_users)
        
        # Últimas 10 entradas para actividad reciente
        recent_lines = lines[-10:]
        for line in reversed(recent_lines):
            line = line.strip()
            if line:
                stats['recent_activity'].append(line)
    except:
        pass
    
    return stats


# ----- Honeypot Web (Flask) -----
def web_honeypot(input_username="admin", input_password="password"):
    app = Flask(__name__)
    app.secret_key = 'supersecretkey'  # Needed for flash messages

    # Configure upload folder
    UPLOAD_FOLDER = 'logs/web_uploads'
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    # ----- Credenciales fake (honeypot - múltiples usuarios) -----
    # NO endurecer seguridad, es un honeypot para capturar atacantes
    valid_users = {
        "admin": {"password": "password", "role": "admin", "name": "Admin System", "dept": "IT / Seguridad"},
        "employee": {"password": "password", "role": "employee", "name": "Empleado Demo", "dept": "General"},
        "j.perez": {"password": "password", "role": "employee", "name": "Juan Pérez", "dept": "Finanzas"},
        "m.garcia": {"password": "password", "role": "employee", "name": "María García", "dept": "RRHH"},
        "c.ruiz": {"password": "password", "role": "employee", "name": "Carlos Ruiz", "dept": "IT"},
        "a.lopez": {"password": "password", "role": "admin", "name": "Ana López", "dept": "IT / Seguridad"},
        "root": {"password": "toor", "role": "admin", "name": "Root Admin", "dept": "Sistema"},
        "test": {"password": "test", "role": "employee", "name": "Test User", "dept": "QA"},
    }

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

            ip_address = request.remote_addr
            ua = request.user_agent.string
            
            # Log SIEMPRE el intento de login (captura todas las credenciales probadas)
            http_logger.info(f'login_attempt ip={ip_address} user="{username}" pass="{password}" ua="{ua}"')

            if username in valid_users and valid_users[username]["password"] == password:
                role = valid_users[username]["role"]
                session['username'] = username
                session['role'] = role
                session['name'] = valid_users[username].get('name', username)
                session['dept'] = valid_users[username].get('dept', 'General')

                http_logger.info(f'login_success ip={ip_address} user="{username}" role="{role}"')

                if role == "admin":
                    return redirect(url_for("admin_panel"))
                return redirect(url_for("dashboard"))
            else:
                http_logger.info(f'login_failure ip={ip_address} user="{username}"')
                return render_template("login.html", error="Credenciales incorrectas"), 401

        return render_template("login.html")

    # -----  logout -----
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # -----  dashboard (employee) -----
    @app.route("/dashboard")
    @login_required
    @employee_required
    def dashboard():
        # Obtener uploads recientes del usuario actual
        metadata = load_upload_metadata()
        user_uploads = [m for m in metadata if m.get('user') == session.get('username')][-5:]
        
        return render_template("dashboard_employee.html", recent_uploads=user_uploads)

    # -----  upload (employee) -----
    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    @employee_required
    def upload():
        if request.method == "POST":
            if 'file' not in request.files:
                flash("No se seleccionó archivo", "error")
                return redirect(request.url)

            file = request.files['file']

            if file.filename == "":
                flash("No se seleccionó archivo", "error")
                return redirect(request.url)

            # Nombre seguro con timestamp + token aleatorio para evitar overwrite
            original_filename = secure_filename(file.filename)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            token = secrets.token_hex(4)
            
            # Separar nombre y extensión
            name_parts = original_filename.rsplit('.', 1)
            if len(name_parts) == 2:
                safe_filename = f"{name_parts[0]}_{timestamp}_{token}.{name_parts[1]}"
            else:
                safe_filename = f"{original_filename}_{timestamp}_{token}"
            
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)
            file.save(save_path)

            file_size = os.path.getsize(save_path)
            ip = request.remote_addr
            username = session.get("username", "anonymous")
            
            # Obtener metadatos del formulario
            doc_type = request.form.get('doc_type', 'other')
            priority = request.form.get('priority', 'normal')
            description = request.form.get('description', '')
            
            # Guardar metadatos en JSON
            metadata = load_upload_metadata()
            upload_meta = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.datetime.now().isoformat(),
                'ip': ip,
                'user': username,
                'original_filename': original_filename,
                'saved_filename': safe_filename,
                'size': file_size,
                'mimetype': file.content_type or 'application/octet-stream',
                'doc_type': doc_type,
                'priority': priority,
                'description': description
            }
            metadata.append(upload_meta)
            save_upload_metadata(metadata)

            # Log del evento de upload
            http_logger.info(f'file_upload ip={ip} user="{username}" filename="{original_filename}" size={file_size} doc_type="{doc_type}"')

            flash("Archivo subido correctamente.", "success")
            return redirect(url_for("upload"))

        return render_template("upload.html")

    # -----  profile (employee) -----
    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    @employee_required
    def profile():
        if request.method == "POST":
            # Simular intento de edición de perfil (no persistir - es honeypot)
            ip = request.remote_addr
            username = session.get("username", "anonymous")
            
            # Capturar todos los datos enviados
            form_data = {k: v for k, v in request.form.items()}
            
            # Log del intento de modificación (muy útil para análisis forense)
            http_logger.info(f'profile_update_attempt ip={ip} user="{username}" fields="{",".join(form_data.keys())}"')
            
            flash("Perfil actualizado correctamente.", "success")
            return redirect(url_for("profile"))
        
        return render_template("profile.html")

    # -----  documentation (employee) -----
    @app.route("/documentation")
    @login_required
    @employee_required
    def documentation():
        ip = request.remote_addr
        username = session.get("username", "anonymous")
        
        # Capturar qué documento se solicita (si hay parámetro)
        doc_requested = request.args.get('doc', 'index')
        category = request.args.get('category', 'all')
        
        # Log de acceso a documentación (útil para detectar reconocimiento)
        http_logger.info(f'document_access ip={ip} user="{username}" doc="{doc_requested}" category="{category}"')
        
        return render_template("documentation.html")

    # -----  tickets (employee) -----
    @app.route("/tickets", methods=["GET", "POST"])
    @login_required
    @employee_required
    def tickets():
        username = session.get("username", "anonymous")
        
        if request.method == "POST":
            ip = request.remote_addr
            
            # Crear nuevo ticket
            subject = request.form.get('subject', '')
            department = request.form.get('department', 'IT Support')
            description = request.form.get('description', '')
            priority = request.form.get('priority', 'normal')
            
            ticket = {
                'id': f"TK-{secrets.token_hex(2).upper()}",
                'timestamp': datetime.datetime.now().isoformat(),
                'user': username,
                'ip': ip,
                'subject': subject,
                'department': department,
                'description': description,
                'priority': priority,
                'status': 'Abierto'
            }
            
            save_ticket(ticket)
            
            # Log de creación de ticket
            http_logger.info(f'ticket_creation ip={ip} user="{username}" ticket_id="{ticket["id"]}" subject="{subject[:50]}"')
            
            flash(f"Ticket {ticket['id']} creado correctamente.", "success")
            return redirect(url_for("tickets"))
        
        # GET: Listar tickets del usuario
        all_tickets = load_tickets()
        user_tickets = [t for t in all_tickets if t.get('user') == username]
        
        return render_template("tickets.html", tickets=user_tickets)
    

    # -----  ADMIN ROUTES ----- 

    @app.route("/admin_panel")
    @login_required
    @admin_required
    def admin_panel():
        # Obtener estadísticas reales de los logs
        stats = get_stats_from_logs()
        
        # También contar uploads desde metadatos
        metadata = load_upload_metadata()
        stats['uploads_total'] = len(metadata)
        
        return render_template("admin_panel.html", stats=stats)

    @app.route("/admin_users", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_users():
        ip = request.remote_addr
        admin_user = session.get("username", "admin")
        
        if request.method == "POST":
            action = request.form.get('action', '')
            target_user = request.form.get('target_user', '')
            
            # Simular acciones de admin (no persistir - es honeypot)
            http_logger.info(f'admin_user_action ip={ip} admin="{admin_user}" action="{action}" target="{target_user}"')
            
            if action == 'create':
                flash(f"Usuario '{target_user}' creado correctamente.", "success")
            elif action == 'block':
                flash(f"Usuario '{target_user}' bloqueado.", "warning")
            elif action == 'unblock':
                flash(f"Usuario '{target_user}' desbloqueado.", "success")
            elif action == 'delete':
                flash(f"Usuario '{target_user}' eliminado.", "danger")
            else:
                flash(f"Acción '{action}' realizada sobre '{target_user}'.", "info")
            
            return redirect(url_for("admin_users"))
        
        # Lista fake de usuarios para mostrar
        fake_users = [
            {"username": "j.perez", "name": "Juan Pérez", "role": "employee", "dept": "Finanzas", "status": "Activo"},
            {"username": "m.garcia", "name": "María García", "role": "employee", "dept": "RRHH", "status": "Activo"},
            {"username": "c.ruiz", "name": "Carlos Ruiz", "role": "employee", "dept": "IT", "status": "Pendiente"},
            {"username": "admin", "name": "Admin System", "role": "admin", "dept": "IT / Seguridad", "status": "Activo"},
        ]
        
        return render_template("admin_users.html", users=fake_users)

    @app.route("/admin_documents")
    @login_required
    @admin_required
    def admin_documents():
        # Obtener metadatos reales de uploads
        metadata = load_upload_metadata()
        
        # Ordenar por timestamp más reciente
        metadata.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return render_template("admin_documents.html", uploads=metadata)

    @app.route("/admin_logs")
    @login_required
    @admin_required
    def admin_logs():
        # Log real de esta acción de admin (para análisis forense real)
        ip = request.remote_addr
        username = session.get("username", "admin")
        ua = request.user_agent.string
        http_logger.info(f'event=admin_action ip={ip} user="{username}" role=admin action=view_siem_limited ua="{ua}"')
        
        # Generar vista SIEM simulada (no mostrar logs reales del honeypot)
        siem_entries = generate_fake_siem_entries()
        
        return render_template("admin_logs.html", log_entries=siem_entries, is_siem_limited=True)

    return app

def run_web_honeypot(port=5000, input_username="admin", input_password="password", host="0.0.0.0", debug=False):
    app = web_honeypot(input_username, input_password)
    app.run(host=host, port=port, debug=debug)

# añadido para pruebas (evita arranque automatico al importar)
if __name__ == "__main__":
    run_web_honeypot(port=5000, input_username="admin", input_password="admin", debug=True)
