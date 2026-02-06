#!/usr/bin/env python3
"""
Dashboard de análisis de logs del honeypot corporativo.
Parsea logs de SSH, FTP y HTTP para generar estadísticas y exportar CSVs.

Utiliza log_parser.py para el parsing de logs.
"""
import os
import csv

# Importar funciones del módulo de parsing
from log_parser import (
    LOG_DIR, OUT_DIR,
    load_all_logs, summarize, clean_backspaces
)

# Asegurar directorio de salida
os.makedirs(OUT_DIR, exist_ok=True)


# =============================================================================
# EXPORTAR CSV
# =============================================================================

def export_csv(name, entries, fields):
    """Exporta una lista de entradas a CSV"""
    path = os.path.join(OUT_DIR, f"{name}.csv")
    with open(path, "w", newline='', encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in entries:
            w.writerow({k: e.get(k, "") for k in fields})
    print(f"[+] Exportado: {path}")


# =============================================================================
# MOSTRAR RESULTADOS
# =============================================================================

def show_top(counter, title, n=5):
    """Muestra los N elementos más comunes de un Counter"""
    print(f"\nTop {n} {title}:")
    for item, count in counter.most_common(n):
        if item:
            print(f"  {str(item):<40} {count}")


def print_summary(summary):
    """Imprime resumen completo del análisis"""
    print("\n" + "="*60)
    print("           HONEYPOT DASHBOARD - ANÁLISIS DE LOGS")
    print("="*60)
    
    # ----- SSH -----
    print("\n[SSH]")
    print(f"  Intentos de conexión : {summary['ssh_attempts_total']}")
    print(f"  Comandos ejecutados  : {summary['ssh_cmd_total']}")
    
    show_top(summary["ssh_attempts_ips"], "IPs (SSH intentos)", 5)
    show_top(summary["ssh_attempts_users"], "Usuarios (SSH)", 5)
    show_top(summary["ssh_cmd_names"], "Comandos SSH", 5)

    # ----- HTTP -----
    print("\n" + "-"*60)
    print("[HTTP - WEB HONEYPOT]")
    print(f"  Intentos de login    : {summary['http_attempts_total']}")
    print(f"  Logins exitosos      : {summary['http_success_total']}")
    print(f"  Logins fallidos      : {summary['http_failures_total']}")
    print(f"  Archivos subidos     : {summary['http_uploads_total']}")
    print(f"  Accesos prohibidos   : {summary['http_forbidden_total']}")
    print(f"  Tickets creados      : {summary['http_tickets_total']}")
    print(f"  Accesos a docs       : {summary['http_doc_access_total']}")
    print(f"  Acciones de admin    : {summary['http_admin_actions_total']}")
    
    show_top(summary["http_attempts_ips"], "IPs (HTTP intentos)", 5)
    show_top(summary["http_success_users"], "Usuarios activos (login exitoso)", 5)
    show_top(summary["http_users_tried"], "Usuarios probados (login)", 5)
    show_top(summary["http_pw"], "Passwords probadas (HTTP)", 5)
    show_top(summary["http_forbidden_ips"], "IPs con accesos prohibidos", 5)
    show_top(summary["http_forbidden_paths"], "Rutas prohibidas más accedidas", 5)
    show_top(summary["http_uploaded_files"], "Archivos subidos", 5)

    # ----- FTP -----
    print("\n" + "-"*60)
    print("[FTP]")
    print(f"  Intentos de login    : {summary['ftp_total_logins']}")
    print(f"  Comandos ejecutados  : {summary['ftp_total_cmds']}")
    print(f"  Archivos descargados : {summary['ftp_downloads_total']}")
    
    show_top(summary["ftp_ips"], "IPs (FTP)", 5)
    show_top(summary["ftp_users"], "Usuarios (FTP)", 5)
    show_top(summary["ftp_pw"], "Passwords (FTP)", 5)
    show_top(summary["ftp_cmd_names"], "Comandos FTP", 5)
    show_top(summary["ftp_downloaded_files"], "Archivos descargados", 5)
    
    print("\n" + "="*60)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("Cargando logs del honeypot...")
    logs = load_all_logs()
    
    print("Generando estadísticas...")
    summary = summarize(logs)
    print_summary(summary)

    # ----- Exportar CSVs -----
    print("\n[*] Exportando CSVs...")

    # SSH
    export_csv("ssh_attempts", logs["ssh_attempts"], ["ts", "ip", "user", "pw"])
    export_csv("ssh_cmd", logs["ssh_cmd"], ["ts", "ip", "user", "pw", "cmd"])

    # HTTP - separar por tipo
    http = logs["http"]
    http_attempts = [d for d in http if "pw" in d and "ua" in d]
    http_uploads = [d for d in http if "filename" in d]
    http_forbidden = [d for d in http if "path" in d]
    http_tickets = [d for d in http if "ticket_id" in d]
    
    export_csv("http_login_attempts", http_attempts, ["ts", "ip", "user", "pw", "ua"])
    export_csv("http_uploads", http_uploads, ["ts", "ip", "user", "filename", "size"])
    export_csv("http_forbidden", http_forbidden, ["ts", "ip", "user", "path"])
    if http_tickets:
        export_csv("http_tickets", http_tickets, ["ts", "ip", "user", "ticket_id"])

    # FTP
    ftp = logs["ftp"]
    ftp_logins = [d for d in ftp if "user" in d and "pw" in d]
    ftp_cmds = [d for d in ftp if "raw" in d]
    ftp_downloads = [d for d in ftp if "file" in d]
    
    export_csv("ftp_logins", ftp_logins, ["ts", "ip", "user", "pw"])
    export_csv("ftp_cmds", ftp_cmds, ["ts", "ip", "user", "raw"])
    if ftp_downloads:
        export_csv("ftp_downloads", ftp_downloads, ["ts", "ip", "file"])

    print("\n[OK] Dashboard completado.")