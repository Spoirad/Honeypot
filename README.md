📘 README.md — Honeypot SSH, HTTP y FTP en Python
# 🛡️ Honeypot SSH, HTTP & FTP en Python

**Autor:** Ángel López Paparella  
**Universidad:** U-tad

---

## 🧠 Introducción

Este proyecto consiste en el desarrollo de un **Honeypot de baja interacción** implementado en **Python**, capaz de simular servicios **SSH**, **HTTP** (Intranet Corporativa) y **FTP**, registrar los intentos de acceso y almacenar los eventos generados para su posterior análisis.

El objetivo principal es **detectar y registrar intentos de intrusión**, sin ofrecer acceso real a ningún sistema.  
El proyecto se ha diseñado con fines educativos y de investigación en ciberseguridad, priorizando la seguridad y el aislamiento del entorno.

---

## ⚙️ Funcionalidades principales

### 🔐 Honeypot SSH (`ssh_honeypot.py`)
- Simula un servidor SSH utilizando la librería `paramiko`.
- Registra intentos de autenticación (usuario, contraseña, IP).
- Simula una shell mínima para capturar comandos ejecutados.
- Almacena los eventos en:
  - `logs/ssh_audits.log` → intentos de conexión.
  - `logs/ssh_cmd_audits.log` → comandos introducidos por el atacante.

### 🏢 Honeypot HTTP - Intranet Corporativa (`web_honeypot.py`)
- Simula una **Intranet Corporativa** realista con roles de usuario (**Admin** y **Empleado**).
- Sistema de login con redirección basada en roles:
  - **Admin**: Acceso a paneles de gestión de usuarios, documentos, logs y vista SIEM simulada.
  - **Empleado**: Acceso a dashboard, perfil, documentación, subida de ficheros y tickets.
- **Funcionalidad de subida de archivos**: Permite a los atacantes "subir" ficheros (se guardan de forma segura para análisis).
- **Sistema de tickets**: Los empleados pueden crear tickets de soporte (registrados en `logs/tickets.log`).
- **Vista SIEM simulada**: El panel admin incluye una vista SIEM con eventos falsos generados para realismo.
- Captura intentos de autenticación (usuario, contraseña, IP, User-Agent) y actividad de navegación.
- Registra accesos prohibidos (intentos de acceder a secciones sin permisos).
- Registra los eventos en:
  - `logs/http_audits.log`
  - `logs/tickets.log` → tickets de soporte creados.
  - `logs/web_uploads/` → archivos subidos por atacantes.

### 📂 Honeypot FTP (`ftp_honeypot.py`)
- Simula un servidor FTP corporativo ("ProFTPD").
- Sistema de archivos virtual (fake filesystem) navegable:
  - Directorios simulados: `backups`, `public`, `private`.
  - Archivos señuelo: `readme.txt`, `db_dump.sql`, `passwords.txt`.
- Soporta comandos comunes: `USER`, `PASS`, `LIST`, `CWD`, `PWD`, `RETR` (descarga simulada), `STOR`, `PASV`, etc.
- Registra todas las interacciones (intentos de login, comandos, descargas).
- Almacena los eventos en:
  - `logs/ftp_audits.log`

### 🧩 Controlador de servicios (`honeypotController.py`)
- Interfaz centralizada CLI para lanzar y gestionar los honeypots (SSH, HTTP, FTP).
- Permite ejecución concurrente de múltiples servicios mediante hilos (threading).
- Modo interactivo para monitorizar estado (`status`) y detener servicios.
- Argumentos de línea de comandos para facilitar la configuración (IP, puerto, usuarios).

### 📊 Dashboard CLI & Exportación (`dashboard.py`)
- Analiza los logs generados por todos los servicios (SSH, HTTP, FTP).
- Utiliza el módulo `log_parser.py` para el parsing de logs.
- **Muestra estadísticas en consola**:
  - Totales de ataques/intentos por servicio.
  - Top IPs atacantes, usuarios y contraseñas más probados.
  - Comandos SSH y FTP más ejecutados.
  - Archivos subidos y descargados.
  - Accesos prohibidos (rutas e IPs).
  - Tickets creados, accesos a documentación y acciones de admin.
- **Exportación a CSV**: Genera reportes estructurados en la carpeta `out/`:
  - `ssh_attempts.csv`, `ssh_cmd.csv`
  - `http_login_attempts.csv`, `http_uploads.csv`, `http_forbidden.csv`, `http_tickets.csv`
  - `ftp_logins.csv`, `ftp_cmds.csv`, `ftp_downloads.csv`
- Limpieza automática de caracteres de control en logs de comandos.

### 🔍 Módulo de Parsing (`log_parser.py`)
- Módulo reutilizable de parsing de logs del honeypot.
- Define expresiones regulares para todos los tipos de evento (SSH, HTTP, FTP).
- Funciones principales:
  - `load_all_logs()` → Carga y parsea todos los logs del honeypot.
  - `summarize()` → Genera estadísticas agregadas (Counters, totales).
  - `get_recent_events()` → Obtiene los N eventos más recientes por tipo.
  - `group_events_by_hour()` / `group_events_by_day()` → Agrupación temporal para gráficas.
- Utilizado por `dashboard.py` (CLI) y `analyst_console.py` (Web).

### 🖥️ Consola del Analista (`analyst_console.py`)
- **Aplicación Flask independiente** para visualización y análisis avanzado de logs.
- Escucha en `127.0.0.1:9090` por seguridad operativa (solo acceso local).
- **Vistas disponibles**:
  - **Overview**: KPIs globales y Top 10 de IPs, usuarios y comandos.
  - **Web Events**: Eventos HTTP/Web detallados.
  - **SSH Events**: Eventos SSH detallados.
  - **FTP Events**: Eventos FTP detallados.
  - **Uploads**: Listado de archivos subidos por atacantes con metadatos.
- **Exportación CSV** directa desde la interfaz web.
- Utiliza `log_parser.py` para el parsing y `templates/analyst/` para las vistas.

---

## 📂 Estructura del proyecto

```text
Honeypot/
├── ssh_honeypot.py          # Honeypot SSH (Paramiko)
├── web_honeypot.py          # Honeypot HTTP (Flask - Intranet Corporativa)
├── ftp_honeypot.py          # Honeypot FTP (Sockets - Fake Filesystem)
├── honeypotController.py    # Controlador central multihilo
├── dashboard.py             # Análisis de logs y exportación a CSV (CLI)
├── log_parser.py            # Módulo reutilizable de parsing de logs
├── analyst_console.py       # Consola web del analista (Flask, puerto 9090)
│
├── templates/               # Plantillas HTML para el entorno Web
│   ├── base.html            # Plantilla base (layout, navbar, estilos)
│   ├── login.html           # Página de login
│   ├── index.html           # Página de inicio
│   ├── login_success.html   # Confirmación de login
│   ├── 403.html             # Error de acceso prohibido
│   ├── 404.html             # Error de página no encontrada
│   ├── dashboard_employee.html  # Dashboard del empleado
│   ├── profile.html         # Perfil de usuario
│   ├── upload.html          # Página de subida de archivos
│   ├── tickets.html         # Sistema de tickets de soporte
│   ├── documentation.html   # Documentación interna simulada
│   ├── dashboard.html       # Dashboard general
│   ├── admin_panel.html     # Panel de administración principal
│   ├── admin_users.html     # Gestión de usuarios (Admin)
│   ├── admin_documents.html # Gestión de documentos (Admin)
│   ├── admin_logs.html      # Visor de logs (Admin)
│   ├── admin.html           # Vista SIEM simulada (Admin)
│   │
│   └── analyst/             # Plantillas de la Consola del Analista
│       ├── base.html        # Layout base del analista
│       ├── overview.html    # Vista general con KPIs
│       ├── web.html         # Eventos HTTP/Web
│       ├── ssh.html         # Eventos SSH
│       ├── ftp.html         # Eventos FTP
│       └── uploads.html     # Archivos subidos
│
├── static/                  # Archivos estáticos
│   ├── css/
│   │   └── styles.css       # Estilos CSS personalizados
│   └── js/
│       └── main.js          # JavaScript principal
│
├── out/                     # Reportes CSV generados
│   ├── ssh_attempts.csv
│   ├── ssh_cmd.csv
│   ├── http_login_attempts.csv
│   ├── http_uploads.csv
│   ├── http_forbidden.csv
│   ├── http_tickets.csv
│   ├── ftp_logins.csv
│   ├── ftp_cmds.csv
│   └── ftp_downloads.csv
│
├── logs/                    # Registros de actividad
│   ├── ssh_audits.log
│   ├── ssh_cmd_audits.log
│   ├── http_audits.log
│   ├── ftp_audits.log
│   ├── tickets.log          # Tickets de soporte (JSON lines)
│   └── web_uploads/         # Archivos subidos por atacantes via HTTP
│
├── tests/                   # Scripts de pruebas
│   ├── test_honeypot.sh     # Tests de integración (bash)
│   └── verify_backend.py   # Verificación del backend
│
├── server.key               # Clave privada server SSH
├── server.key.pub           # Clave pública server SSH
├── .gitignore
├── requirements.txt
└── README.md
```

## 🔧 Instalación

### 1️⃣ Clonar el repositorio
```bash
git clone https://github.com/Spoirad/Honeypot.git
cd Honeypot
```

### 2️⃣ Crear y activar entorno virtual
```bash
python -m venv venv
# En Windows
venv\Scripts\activate
# En Linux/Mac
source venv/bin/activate
```

### 3️⃣ Instalar dependencias
```bash
pip install -r requirements.txt
```

### 4️⃣ Generar claves SSH (para el honeypot SSH)
```bash
ssh-keygen -t rsa -b 2048 -f server.key
```

---

## 🚀 Uso

El controlador permite lanzar uno o varios honeypots simultáneamente.

### 🔹 Sintaxis General
```bash
python honeypotController.py [OPCIONES]
```

### 🔹 Ejemplos de ejecución

**1. Iniciar todo (SSH + Web + FTP):**
```bash
python honeypotController.py -s -w --web-port 8080 -f --ftp-port 2121
```

**2. Iniciar solo SSH (puerto 2223 user/pass admin/admin):**
```bash
python honeypotController.py -s -p 2223 -u admin -pw admin
```

**3. Iniciar solo Web (Corporate Intranet):**
```bash
python honeypotController.py -w --web-port 5000
```
*Credenciales Web Demo:* `admin:password` (Rol Admin), `employee:password` (Rol Empleado).

**4. Iniciar solo FTP:**
```bash
python honeypotController.py -f --ftp-port 21
```

### 🔹 Argumentos disponibles

| Argumento | Descripción | Valor por defecto |
|---|---|---|
| `-a`, `--address` | IP donde escuchar (SSH) | `0.0.0.0` |
| `-p`, `--port` | Puerto SSH | `2223` |
| `-u`, `--username` | Usuario SSH/Web | `None` (admin para Web) |
| `-pw`, `--password` | Contraseña SSH/Web | `None` (password para Web) |
| `-s`, `--ssh` | Arrancar honeypot SSH | `False` |
| `-w`, `--web` | Arrancar honeypot Web | `False` |
| `-f`, `--ftp` | Arrancar honeypot FTP | `False` |
| `--web-port` | Puerto para el honeypot Web | `8080` |
| `--ftp-port` | Puerto para el honeypot FTP | `21` |

### 🔹 Comandos en tiempo de ejecución
Una vez iniciado el controlador, puedes usar la consola interactiva:
- `status`: Ver estado de los servicios.
- `stop <ssh|web|ftp|all>`: Detener servicios (nota: detiene el proceso principal).
- `exit`: Salir.

### 🔹 Ejecutar el Dashboard CLI (Análisis)
Para ver estadísticas y generar los CSVs:
```bash
python dashboard.py
```

### 🔹 Ejecutar la Consola del Analista (Web)
Para acceder al dashboard web de análisis avanzado:
```bash
python analyst_console.py
```
Acceder en el navegador: `http://127.0.0.1:9090`

---

## 🧾 Salida esperada (Dashboard CLI)

```text
============================================================
           HONEYPOT DASHBOARD - ANÁLISIS DE LOGS
============================================================

[SSH]
  Intentos de conexión : 12
  Comandos ejecutados  : 5

Top 5 IPs (SSH intentos):
  192.168.1.50                             12

Top 5 Comandos SSH:
  whoami                                   3
  ls -la                                   2

------------------------------------------------------------
[HTTP - WEB HONEYPOT]
  Intentos de login    : 8
  Logins exitosos      : 3
  Logins fallidos      : 5
  Archivos subidos     : 2
  Accesos prohibidos   : 1
  Tickets creados      : 1
  Accesos a docs       : 0
  Acciones de admin    : 0

------------------------------------------------------------
[FTP]
  Intentos de login    : 4
  Comandos ejecutados  : 15
  Archivos descargados : 1

[+] Exportado: out/ssh_attempts.csv
[+] Exportado: out/http_login_attempts.csv
[+] Exportado: out/ftp_logins.csv
...
```

---

## 📁 Ejemplo de logs

### 🧩 SSH — `logs/ssh_audits.log`
```text
2025-10-23 12:41:57,528 Client 127.0.0.1 attempted connection with username: admin, password: 1234
```

### 🌐 HTTP — `logs/http_audits.log`
```text
2025-10-23 12:22:17,332 login_attempt ip=127.0.0.1 user="admin" pass="password" ua="Mozilla/5.0 ..."
2025-10-23 12:22:18,100 FILE_UPLOAD ip=127.0.0.1 user="employee" filename="malware.exe" size=10240
2025-10-23 12:22:19,200 forbidden ip=127.0.0.1 user="employee" role=employee path="/admin/panel"
2025-10-23 12:22:20,300 ticket_created ip=127.0.0.1 user="employee" ticket_id="abc123"
```

### 📂 FTP — `logs/ftp_audits.log`
```text
2025-10-23 14:00:01,123 new_connection ip=192.168.1.20
2025-10-23 14:00:05,456 login_success ip=192.168.1.20 user="admin" pass="password"
2025-10-23 14:00:10,789 command ip=192.168.1.20 user="admin" raw="RETR passwords.txt"
```

---

## 🔒 Seguridad

- El honeypot debe ejecutarse **en entorno controlado** (máquina virtual o contenedor).  
- No debe exponerse directamente a Internet sin un proxy o cortafuegos intermedio.  
- Los servicios no ejecutan ningún comando real en la máquina anfitriona, solo simulan respuestas.  
- La **Consola del Analista** escucha únicamente en `127.0.0.1` (localhost) para evitar exposición accidental.
- **Advertencia**: Los archivos subidos vía Web se guardan en `logs/web_uploads`. No ejecutarlos en la máquina local.
- Los logs **no deben compartirse públicamente**, ya que pueden contener credenciales o direcciones IP sensibles.

---

## 🏗️ Arquitectura

```text
┌──────────────────────────────────────────────────────────┐
│                 honeypotController.py                     │
│           (Controlador central multihilo)                │
├──────────┬──────────────┬────────────────────────────────┤
│          │              │                                │
│  SSH     │  HTTP        │  FTP                           │
│ Honeypot │  Honeypot    │  Honeypot                      │
│ :2223    │  :8080       │  :21                           │
│          │              │                                │
├──────────┴──────────────┴────────────────────────────────┤
│                      logs/                               │
│  ssh_audits.log  http_audits.log  ftp_audits.log  ...    │
├──────────────────────────────────────────────────────────┤
│                   log_parser.py                          │
│            (Módulo compartido de parsing)                │
├─────────────────────┬────────────────────────────────────┤
│   dashboard.py      │      analyst_console.py            │
│   (CLI - CSV)       │      (Web - :9090)                 │
└─────────────────────┴────────────────────────────────────┘
```

---

## 🧰 Dependencias principales

- [Python 3.10+](https://www.python.org/)  
- [Paramiko](https://pypi.org/project/paramiko/)  
- [Flask](https://pypi.org/project/Flask/)

**Contenido de `requirements.txt`:**
```text
paramiko==4.0.0
flask==3.1.2
```

---

## 🧑‍💻 Autor

**Ángel López Paparella**  
Grado en Ingeniería de Software — Mención en Ciberseguridad  

---

## ⚠️ Descargo de responsabilidad

Este software se ha desarrollado con fines educativos y de investigación.  
No debe utilizarse para actividades maliciosas o fuera de entornos controlados.  
El autor no se responsabiliza de los daños derivados de un uso inadecuado del código.
