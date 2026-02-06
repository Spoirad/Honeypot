#!/usr/bin/env python3
"""
log_parser.py - Módulo de parsing de logs del honeypot.
Extrae y analiza logs de SSH, FTP y HTTP.
Reutilizable por dashboard.py (CLI) y analyst_console.py (Web).
"""
import os
import re
from collections import Counter, defaultdict

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

LOG_DIR = "logs"
OUT_DIR = "out"

# =============================================================================
# REGEX PARA PARSEAR LOGS
# =============================================================================

# ----- SSH -----
RE_SSH_ATTEMPT = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+Client\s+(?P<ip>\S+)\s+attempted connection with username:\s*(?P<user>.*?),\s+password:\s*(?P<pw>.*)$'
)

RE_SSH_CMD_AUTH = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+(?P<ip>\S+),\s+(?P<user>[^,]+),\s*(?P<pw>.*)$'
)

RE_SSH_CMD_EXEC = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+Command\s+b\'(?P<cmd>.*)\'\s+executed by\s+(?P<ip>\S+)$'
)

# ----- HTTP - Login -----
RE_HTTP_LOGIN_ATTEMPT = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+login_attempt\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+pass="(?P<pw>[^"]*)"\s+ua="(?P<ua>.*)"$'
)

RE_HTTP_LOGIN_SUCCESS = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+login_success\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+role="(?P<role>[^"]*)"$'
)

RE_HTTP_LOGIN_FAILURE = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+login_failure\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"$'
)

# ----- HTTP - Acciones -----
RE_HTTP_UPLOAD = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+file_upload\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+filename="(?P<filename>[^"]*)"\s+size=(?P<size>\d+).*$',
    re.IGNORECASE  # Soporta FILE_UPLOAD y file_upload
)

RE_HTTP_FORBIDDEN = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+forbidden_access\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+path="(?P<path>[^"]*)".*$'
)

RE_HTTP_TICKET = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+ticket_creation\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+ticket_id="(?P<ticket_id>[^"]*)".*$'
)

RE_HTTP_DOC_ACCESS = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+document_access\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+doc="(?P<doc>[^"]*)".*$'
)

RE_HTTP_PROFILE_UPDATE = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+profile_update_attempt\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)".*$'
)

RE_HTTP_ADMIN_ACTION = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+admin_user_action\s+ip=(?P<ip>\S+)\s+admin="(?P<admin>[^"]*)"\s+action="(?P<action>[^"]*)"\s+target="(?P<target>[^"]*)"$'
)

RE_HTTP_ADMIN_SIEM = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+event=admin_action\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+role=(?P<role>\S+)\s+action=(?P<action>\S+).*$'
)

# ----- FTP -----
RE_FTP_LOGIN_SUCCESS = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+login_success\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+pass="(?P<pw>[^"]*)"$'
)

RE_FTP_LOGIN_FAILURE = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+login_failure\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+pass="(?P<pw>[^"]*)"$'
)

RE_FTP_CMD = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+command\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+raw="(?P<raw>.*)"$'
)

RE_FTP_NEW_CONN = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+new_connection\s+ip=(?P<ip>\S+)$'
)

RE_FTP_FILE_DOWNLOAD = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+file_download\s+ip=(?P<ip>\S+)\s+file="(?P<file>[^"]*)"$'
)


# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================

def clean_backspaces(s: str) -> str:
    """Elimina secuencias \\x7f (retroceso) y el carácter anterior"""
    result = []
    i = 0
    while i < len(s):
        if s[i:i+4] == '\\x7f':
            if result:
                result.pop()
            i += 4
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def parse_file(path, regexes):
    """Parsea un archivo de log usando una lista de regex"""
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            for rex in regexes:
                m = rex.match(line)
                if m:
                    d = m.groupdict()
                    d['_pattern'] = rex.pattern[:30]  # Guardar qué patrón matcheó
                    d['_raw'] = line  # Línea original para referencia
                    entries.append(d)
                    break
    return entries


def load_all_logs(log_dir=None):
    """Carga todos los logs del honeypot"""
    if log_dir is None:
        log_dir = LOG_DIR
    
    data = {}
    
    # SSH
    data["ssh_attempts"] = parse_file(
        os.path.join(log_dir, "ssh_audits.log"), 
        [RE_SSH_ATTEMPT]
    )
    data["ssh_cmd"] = parse_file(
        os.path.join(log_dir, "ssh_cmd_audits.log"), 
        [RE_SSH_CMD_AUTH, RE_SSH_CMD_EXEC]
    )
    
    # HTTP - todos los eventos
    http_regexes = [
        RE_HTTP_LOGIN_ATTEMPT,
        RE_HTTP_LOGIN_SUCCESS,
        RE_HTTP_LOGIN_FAILURE,
        RE_HTTP_UPLOAD,
        RE_HTTP_FORBIDDEN,
        RE_HTTP_TICKET,
        RE_HTTP_DOC_ACCESS,
        RE_HTTP_PROFILE_UPDATE,
        RE_HTTP_ADMIN_ACTION,
        RE_HTTP_ADMIN_SIEM,
    ]
    data["http"] = parse_file(os.path.join(log_dir, "http_audits.log"), http_regexes)
    
    # FTP
    ftp_regexes = [
        RE_FTP_LOGIN_SUCCESS,
        RE_FTP_LOGIN_FAILURE,
        RE_FTP_CMD,
        RE_FTP_NEW_CONN,
        RE_FTP_FILE_DOWNLOAD,
    ]
    data["ftp"] = parse_file(os.path.join(log_dir, "ftp_audits.log"), ftp_regexes)
    
    return data


# =============================================================================
# ESTADÍSTICAS
# =============================================================================

def summarize(data):
    """Genera estadísticas de todos los logs"""
    summary = {}
    
    # ----- SSH -----
    ssh_attempts = data.get("ssh_attempts", [])
    summary["ssh_attempts_total"] = len(ssh_attempts)
    summary["ssh_attempts_ips"] = Counter(d.get("ip") for d in ssh_attempts)
    summary["ssh_attempts_users"] = Counter(d.get("user") for d in ssh_attempts)
    summary["ssh_attempts_pw"] = Counter(d.get("pw") for d in ssh_attempts)

    ssh_cmds = data.get("ssh_cmd", [])
    commands = []
    for d in ssh_cmds:
        if "cmd" in d:
            commands.append(clean_backspaces(d["cmd"]))
    summary["ssh_cmd_total"] = len(commands)
    summary["ssh_cmd_ips"] = Counter(d.get("ip") for d in ssh_cmds if "ip" in d)
    summary["ssh_cmd_names"] = Counter(commands)

    # ----- HTTP -----
    http = data.get("http", [])
    
    # Separar por tipo de evento
    http_attempts = [d for d in http if "pw" in d and "ua" in d]  # login_attempt tiene pw y ua
    http_success = [d for d in http if "role" in d and "action" not in d]  # login_success tiene role
    http_failures = [d for d in http if "user" in d and "pw" not in d and "role" not in d and "filename" not in d and "path" not in d and "ticket_id" not in d and "doc" not in d and "action" not in d]
    http_uploads = [d for d in http if "filename" in d]
    http_forbidden = [d for d in http if "path" in d]
    http_tickets = [d for d in http if "ticket_id" in d]
    http_doc_access = [d for d in http if "doc" in d]
    http_profile_updates = [d for d in http if d.get("_pattern", "").startswith("^(?P<ts>[\\d\\-:\\s,]+)\\s+profile")]
    http_admin_actions = [d for d in http if "action" in d and ("admin" in d or "user" in d)]
    
    # Estadísticas HTTP
    summary["http_attempts_total"] = len(http_attempts)
    summary["http_success_total"] = len(http_success)
    summary["http_failures_total"] = len(http_failures)
    summary["http_uploads_total"] = len(http_uploads)
    summary["http_forbidden_total"] = len(http_forbidden)
    summary["http_tickets_total"] = len(http_tickets)
    summary["http_doc_access_total"] = len(http_doc_access)
    summary["http_admin_actions_total"] = len(http_admin_actions)
    
    # IPs por evento HTTP
    summary["http_attempts_ips"] = Counter(d.get("ip") for d in http_attempts)
    summary["http_success_ips"] = Counter(d.get("ip") for d in http_success)
    summary["http_forbidden_ips"] = Counter(d.get("ip") for d in http_forbidden)
    
    # Usuarios más activos
    summary["http_success_users"] = Counter(d.get("user") for d in http_success)
    summary["http_upload_users"] = Counter(d.get("user") for d in http_uploads)
    
    # Credenciales probadas
    summary["http_pw"] = Counter(d.get("pw") for d in http_attempts)
    summary["http_users_tried"] = Counter(d.get("user") for d in http_attempts)
    
    # Rutas prohibidas más accedidas
    summary["http_forbidden_paths"] = Counter(d.get("path") for d in http_forbidden)
    
    # Archivos subidos
    summary["http_uploaded_files"] = Counter(d.get("filename") for d in http_uploads)
    
    # Guardar listas para uso en web
    summary["http_events"] = http
    summary["http_uploads_list"] = http_uploads

    # ----- FTP -----
    ftp_entries = data.get("ftp", [])
    ftp_logins = [d for d in ftp_entries if "user" in d and "pw" in d]
    ftp_success = [d for d in ftp_logins if "login_success" in str(d.get("_pattern", ""))]
    ftp_failures = [d for d in ftp_logins if "login_failure" in str(d.get("_pattern", ""))]
    ftp_cmds = [d for d in ftp_entries if "raw" in d]
    ftp_downloads = [d for d in ftp_entries if "file" in d]

    summary["ftp_total_logins"] = len(ftp_logins)
    summary["ftp_success_total"] = len(ftp_success)
    summary["ftp_failures_total"] = len(ftp_failures)
    summary["ftp_total_cmds"] = len(ftp_cmds)
    summary["ftp_downloads_total"] = len(ftp_downloads)

    summary["ftp_ips"] = Counter(d.get("ip") for d in ftp_entries if "ip" in d)
    summary["ftp_users"] = Counter(d.get("user") for d in ftp_logins)
    summary["ftp_pw"] = Counter(d.get("pw") for d in ftp_logins)
    summary["ftp_downloaded_files"] = Counter(d.get("file") for d in ftp_downloads)

    summary["ftp_cmd_names"] = Counter()
    for d in ftp_cmds:
        raw = d.get("raw", "")
        cmd = raw.split(" ", 1)[0].upper() if raw else ""
        if cmd:
            summary["ftp_cmd_names"][cmd] += 1
    
    # Guardar listas para uso en web
    summary["ftp_events"] = ftp_entries
    summary["ftp_cmds_list"] = ftp_cmds

    return summary


def get_recent_events(data, event_type="http", n=50):
    """Obtiene los N eventos más recientes de un tipo"""
    events = data.get(event_type, [])
    return events[-n:][::-1]  # Últimos N, más recientes primero


# =============================================================================
# FUNCIONES DE AGRUPACIÓN TEMPORAL
# =============================================================================

def group_events_by_hour(events):
    """Agrupa eventos por hora para gráficas temporales"""
    hourly = defaultdict(int)
    for e in events:
        ts = e.get("ts", "")
        if ts:
            # Formato: "2025-12-07 17:50:22,539"
            hour_key = ts[:13]  # "2025-12-07 17"
            hourly[hour_key] += 1
    return dict(sorted(hourly.items()))


def group_events_by_day(events):
    """Agrupa eventos por día para gráficas temporales"""
    daily = defaultdict(int)
    for e in events:
        ts = e.get("ts", "")
        if ts:
            day_key = ts[:10]  # "2025-12-07"
            daily[day_key] += 1
    return dict(sorted(daily.items()))
