#!/usr/bin/env python3
import os
import re
import csv
from collections import Counter, defaultdict

LOG_DIR = "logs"
OUT_DIR = "out"
os.makedirs(OUT_DIR, exist_ok=True)

# --- Regex para parsear tus logs ---

#No entiendo exactamente el funcionamiento pero basicamente parsea y separa los componentes de los logs
RE_SSH_ATTEMPT = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+Client\s+(?P<ip>\S+)\s+attempted connection with username:\s*(?P<user>.*?),\s+password:\s*(?P<pw>.*)$'
)

RE_SSH_CMD_AUTH = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+(?P<ip>\S+),\s+(?P<user>[^,]+),\s*(?P<pw>.*)$'
)

RE_SSH_CMD_EXEC = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+Command\s+b\'(?P<cmd>.*)\'\s+executed by\s+(?P<ip>\S+)$'
)

RE_HTTP_LOGIN = re.compile(
    r'^(?P<ts>[\d\-:\s,]+)\s+login_attempt\s+ip=(?P<ip>\S+)\s+user="(?P<user>[^"]*)"\s+pass="(?P<pw>[^"]*)"\s+ua="(?P<ua>.*)"$'
)


# --- Funciones de carga y parsing ---

def clean_backspaces(s: str) -> str:
    #elimina secuencias \x7f (retroceso) y el carácter anterior
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
                    entries.append(d)
                    break
    return entries


# --- Cargar los tres logs ---

def load_all_logs():
    data = {}
    data["ssh_attempts"] = parse_file(os.path.join(LOG_DIR, "ssh_audits.log"), [RE_SSH_ATTEMPT])
    data["ssh_cmd"] = parse_file(os.path.join(LOG_DIR, "ssh_cmd_audits.log"), [RE_SSH_CMD_AUTH, RE_SSH_CMD_EXEC])
    data["http"] = parse_file(os.path.join(LOG_DIR, "http_audits.log"), [RE_HTTP_LOGIN])
    return data


# --- Generar estadísticas ---

def summarize(data):
    summary = {}
    # SSH attempts
    ssh_attempts = data["ssh_attempts"]
    summary["ssh_attempts_total"] = len(ssh_attempts)
    summary["ssh_attempts_ips"] = Counter(d.get("ip") for d in ssh_attempts)
    summary["ssh_attempts_users"] = Counter(d.get("user") for d in ssh_attempts)
    summary["ssh_attempts_pw"] = Counter(d.get("pw") for d in ssh_attempts)

    # SSH commands
    ssh_cmds = data["ssh_cmd"]
    commands = []
    for d in ssh_cmds:
        if "cmd" in d:
            commands.append(clean_backspaces(d["cmd"]))
    summary["ssh_cmd_total"] = len(commands)
    summary["ssh_cmd_ips"] = Counter(d.get("ip") for d in ssh_cmds if "ip" in d)
    summary["ssh_cmd_names"] = Counter(commands)

    # HTTP
    http = data["http"]
    summary["http_total"] = len(http)
    summary["http_ips"] = Counter(d.get("ip") for d in http)
    summary["http_users"] = Counter(d.get("user") for d in http)
    summary["http_pw"] = Counter(d.get("pw") for d in http)

    return summary


# --- Exportar a CSV ---

def export_csv(name, entries, fields):
    path = os.path.join(OUT_DIR, f"{name}.csv")
    with open(path, "w", newline='', encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in entries:
            w.writerow({k: e.get(k, "") for k in fields})
    print(f"[+] Exportado: {path}")


# --- Mostrar resultados ---

def show_top(counter, title, n=5):
    print(f"\nTop {n} {title}:")
    for item, count in counter.most_common(n):
        if item:
            print(f"  {item:<30} {count}")


def print_summary(summary):
    print("\n=================== HONEYPOT DASHBOARD ===================")
    print(f"Total SSH attempts: {summary['ssh_attempts_total']}")
    print(f"Total SSH commands: {summary['ssh_cmd_total']}")
    print(f"Total HTTP logins : {summary['http_total']}")
    show_top(summary["ssh_attempts_ips"], "IPs (SSH attempts)")
    show_top(summary["ssh_attempts_users"], "Usuarios (SSH)")
    show_top(summary["ssh_cmd_names"], "Comandos SSH ejecutados")
    show_top(summary["http_ips"], "IPs (HTTP)")
    show_top(summary["http_users"], "Usuarios (HTTP)")
    show_top(summary["http_pw"], "Passwords (HTTP)")


# --- MAIN ---

if __name__ == "__main__":
    logs = load_all_logs()
    summary = summarize(logs)
    print_summary(summary)

    # Exporta CSVs básicos
    export_csv("ssh_attempts", logs["ssh_attempts"], ["ts", "ip", "user", "pw"])
    export_csv("ssh_cmd", logs["ssh_cmd"], ["ts", "ip", "user", "pw", "cmd"])
    export_csv("http_logins", logs["http"], ["ts", "ip", "user", "pw", "ua"])
