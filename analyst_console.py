#!/usr/bin/env python3
"""
Analyst Console - Dashboard Real de Análisis de Logs del Honeypot
App Flask independiente para el analista de seguridad.

Por seguridad operativa, escucha solo en 127.0.0.1:9090 por defecto.
"""
import os
import json
import csv
from io import StringIO
from flask import Flask, render_template, request, Response, send_file

# Importar funciones del módulo de parsing
from log_parser import (
    LOG_DIR, load_all_logs, summarize,
    group_events_by_hour, group_events_by_day
)

app = Flask(__name__)
app.secret_key = 'analyst_console_secret_key'

# Configuración
UPLOAD_METADATA_FILE = 'logs/upload_metadata.json'
UPLOAD_DIR = 'logs/web_uploads'


# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================

def load_upload_metadata():
    """Carga metadatos de uploads desde JSON"""
    if os.path.exists(UPLOAD_METADATA_FILE):
        try:
            with open(UPLOAD_METADATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []


def get_data_and_summary():
    """Carga datos y genera resumen - caché simple"""
    data = load_all_logs()
    summary = summarize(data)
    return data, summary


def counter_to_list(counter, limit=10):
    """Convierte Counter a lista de dicts para JSON/templates"""
    return [{"item": item, "count": count} for item, count in counter.most_common(limit) if item]


def make_csv_response(data, filename, fields):
    """Genera respuesta CSV para descarga"""
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in data:
        writer.writerow({k: row.get(k, "") for k in fields})
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response


# =============================================================================
# RUTAS
# =============================================================================

@app.route("/")
def overview():
    """Página principal - Overview con KPIs y Top 10"""
    data, summary = get_data_and_summary()
    
    # KPIs
    kpis = {
        "ssh_attempts": summary.get("ssh_attempts_total", 0),
        "ssh_commands": summary.get("ssh_cmd_total", 0),
        "http_logins": summary.get("http_attempts_total", 0),
        "http_forbidden": summary.get("http_forbidden_total", 0),
        "http_uploads": summary.get("http_uploads_total", 0),
        "ftp_logins": summary.get("ftp_total_logins", 0),
        "ftp_commands": summary.get("ftp_total_cmds", 0),
        "ftp_downloads": summary.get("ftp_downloads_total", 0),
    }
    
    # Top 10 listas
    tops = {
        "http_ips": counter_to_list(summary.get("http_attempts_ips", {})),
        "http_users": counter_to_list(summary.get("http_users_tried", {})),
        "http_passwords": counter_to_list(summary.get("http_pw", {})),
        "ssh_ips": counter_to_list(summary.get("ssh_attempts_ips", {})),
        "ssh_users": counter_to_list(summary.get("ssh_attempts_users", {})),
        "ftp_ips": counter_to_list(summary.get("ftp_ips", {})),
        "ftp_users": counter_to_list(summary.get("ftp_users", {})),
    }
    
    # Eventos recientes (últimos 10)
    recent_http = summary.get("http_events", [])[-10:][::-1]
    
    return render_template("analyst/overview.html", kpis=kpis, tops=tops, recent_events=recent_http)


@app.route("/web")
def web_events():
    """Página de eventos HTTP/Web"""
    data, summary = get_data_and_summary()
    
    http_events = summary.get("http_events", [])
    
    # Agrupar por hora para gráfica
    hourly = group_events_by_hour(http_events)
    
    # Top datos
    tops = {
        "ips": counter_to_list(summary.get("http_attempts_ips", {})),
        "users": counter_to_list(summary.get("http_users_tried", {})),
        "passwords": counter_to_list(summary.get("http_pw", {})),
        "forbidden_paths": counter_to_list(summary.get("http_forbidden_paths", {})),
    }
    
    # Estadísticas
    stats = {
        "total_attempts": summary.get("http_attempts_total", 0),
        "total_success": summary.get("http_success_total", 0),
        "total_forbidden": summary.get("http_forbidden_total", 0),
        "total_uploads": summary.get("http_uploads_total", 0),
    }
    
    # Últimos 50 eventos
    recent = http_events[-50:][::-1]
    
    return render_template("analyst/web.html", 
                         events=recent, 
                         hourly=hourly,
                         tops=tops,
                         stats=stats)


@app.route("/ssh")
def ssh_events():
    """Página de eventos SSH"""
    data, summary = get_data_and_summary()
    
    # Top datos
    tops = {
        "ips": counter_to_list(summary.get("ssh_attempts_ips", {})),
        "users": counter_to_list(summary.get("ssh_attempts_users", {})),
        "passwords": counter_to_list(summary.get("ssh_attempts_pw", {})),
        "commands": counter_to_list(summary.get("ssh_cmd_names", {})),
    }
    
    # Estadísticas
    stats = {
        "total_attempts": summary.get("ssh_attempts_total", 0),
        "total_commands": summary.get("ssh_cmd_total", 0),
    }
    
    # Eventos
    ssh_attempts = data.get("ssh_attempts", [])[-50:][::-1]
    ssh_cmds = data.get("ssh_cmd", [])[-50:][::-1]
    
    # Agrupar por hora
    all_ssh = data.get("ssh_attempts", []) + data.get("ssh_cmd", [])
    hourly = group_events_by_hour(all_ssh)
    
    return render_template("analyst/ssh.html",
                         attempts=ssh_attempts,
                         commands=ssh_cmds,
                         tops=tops,
                         stats=stats,
                         hourly=hourly)


@app.route("/ftp")
def ftp_events():
    """Página de eventos FTP"""
    data, summary = get_data_and_summary()
    
    ftp = data.get("ftp", [])
    
    # Top datos
    tops = {
        "ips": counter_to_list(summary.get("ftp_ips", {})),
        "users": counter_to_list(summary.get("ftp_users", {})),
        "passwords": counter_to_list(summary.get("ftp_pw", {})),
        "commands": counter_to_list(summary.get("ftp_cmd_names", {})),
        "downloads": counter_to_list(summary.get("ftp_downloaded_files", {})),
    }
    
    # Estadísticas
    stats = {
        "total_logins": summary.get("ftp_total_logins", 0),
        "total_success": summary.get("ftp_success_total", 0),
        "total_commands": summary.get("ftp_total_cmds", 0),
        "total_downloads": summary.get("ftp_downloads_total", 0),
    }
    
    # Agrupar por hora
    hourly = group_events_by_hour(ftp)
    
    # Últimos eventos
    recent = ftp[-50:][::-1]
    
    return render_template("analyst/ftp.html",
                         events=recent,
                         tops=tops,
                         stats=stats,
                         hourly=hourly)


@app.route("/uploads")
def uploads():
    """Página de archivos subidos"""
    metadata = load_upload_metadata()
    
    # Ordenar por timestamp más reciente
    metadata.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Verificar qué archivos existen
    for upload in metadata:
        saved_filename = upload.get('saved_filename', '')
        file_path = os.path.join(UPLOAD_DIR, saved_filename)
        upload['file_exists'] = os.path.exists(file_path)
        if upload['file_exists']:
            upload['file_size_actual'] = os.path.getsize(file_path)
    
    return render_template("analyst/uploads.html", uploads=metadata)


# =============================================================================
# EXPORTACIÓN CSV
# =============================================================================

@app.route("/export/<export_type>")
def export_csv_route(export_type):
    """Exporta datos a CSV"""
    data, summary = get_data_and_summary()
    
    if export_type == "ssh_attempts":
        return make_csv_response(
            data.get("ssh_attempts", []),
            "ssh_attempts.csv",
            ["ts", "ip", "user", "pw"]
        )
    
    elif export_type == "ssh_commands":
        return make_csv_response(
            data.get("ssh_cmd", []),
            "ssh_commands.csv",
            ["ts", "ip", "user", "cmd"]
        )
    
    elif export_type == "http_logins":
        http = data.get("http", [])
        attempts = [d for d in http if "pw" in d and "ua" in d]
        return make_csv_response(
            attempts,
            "http_login_attempts.csv",
            ["ts", "ip", "user", "pw", "ua"]
        )
    
    elif export_type == "http_uploads":
        http = data.get("http", [])
        uploads = [d for d in http if "filename" in d]
        return make_csv_response(
            uploads,
            "http_uploads.csv",
            ["ts", "ip", "user", "filename", "size"]
        )
    
    elif export_type == "http_forbidden":
        http = data.get("http", [])
        forbidden = [d for d in http if "path" in d]
        return make_csv_response(
            forbidden,
            "http_forbidden.csv",
            ["ts", "ip", "user", "path"]
        )
    
    elif export_type == "ftp_logins":
        ftp = data.get("ftp", [])
        logins = [d for d in ftp if "user" in d and "pw" in d]
        return make_csv_response(
            logins,
            "ftp_logins.csv",
            ["ts", "ip", "user", "pw"]
        )
    
    elif export_type == "ftp_commands":
        ftp = data.get("ftp", [])
        cmds = [d for d in ftp if "raw" in d]
        return make_csv_response(
            cmds,
            "ftp_commands.csv",
            ["ts", "ip", "user", "raw"]
        )
    
    elif export_type == "uploads_metadata":
        metadata = load_upload_metadata()
        return make_csv_response(
            metadata,
            "uploads_metadata.csv",
            ["timestamp", "ip", "user", "original_filename", "saved_filename", "size", "mimetype"]
        )
    
    else:
        return "Export type not found", 404


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  ANALYST CONSOLE - Honeypot Log Analysis Dashboard")
    print("=" * 60)
    print(f"  Listening on: http://127.0.0.1:9090")
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    
    # Solo localhost por seguridad operativa
    app.run(host="127.0.0.1", port=9090, debug=True)
