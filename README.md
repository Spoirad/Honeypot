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
  - **Admin**: Acceso a paneles de gestión de usuarios, documentos y logs.
  - **Empleado**: Acceso a dashboard, perfil, subida de ficheros y tickets.
- **Funcionalidad de subida de archivos**: Permite a los atacantes "subir" ficheros (se guardan de forma segura para análisis).
- Captura intentos de autenticación (usuario, contraseña, IP, User-Agent) y actividad de navegación.
- Registra los eventos en:
  - `logs/http_audits.log`
  - Archivos subidos en: `logs/web_uploads/`

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
- **Muestra estadísticas en consola**:
  - Totales de ataques/intentos por servicio.
  - Top IPs atacantes, usuarios y contraseñas más probados.
  - Comandos SSH y FTP más ejecutados.
- **Exportación a CSV**: Genera reportes estructurados en la carpeta `out/`:
  - `ssh_attempts.csv`, `ssh_cmd.csv`
  - `http_logins.csv`
  - `ftp_logins.csv`, `ftp_cmds.csv`
- Limpieza automática de caracteres de control en logs de comandos.

---

## 📂 Estructura del proyecto

```text
Honeypot/
├── ssh_honeypot.py          # Honeypot SSH (Paramiko)
├── web_honeypot.py          # Honeypot HTTP (Flask - Intranet Corporativa)
├── ftp_honeypot.py          # Honeypot FTP (Sockets - Fake Filesystem)
├── honeypotController.py    # Controlador central multihilo
├── dashboard.py             # Análisis de logs y exportación a CSV
│
├── templates/               # Plantillas HTML para el entorno Web
│   ├── login.html           # Login
│   ├── dashboard_employee.html  # Panel de empleado
│   ├── admin_panel.html     # Panel de administración
│   ├── upload.html          # Página de subida de archivos
│   └── ... (otros templates)
│
├── static/                  # Archivos estáticos (CSS, JS, imágenes)
│
├── out/                     # Reportes CSV generados
│   ├── http_logins.csv
│   ├── ssh_attempts.csv
│   ├── ssh_cmd.csv
│   ├── ftp_logins.csv
│   └── ftp_cmds.csv
│
├── logs/                    # Registros de actividad
│   ├── ssh_audits.log
│   ├── ssh_cmd_audits.log
│   ├── http_audits.log
│   ├── ftp_audits.log
│   └── web_uploads/         # Archivos subidos por atacantes via HTTP
│
├── server.key               # Clave privada server ssh
├── server.key.pub           # Clave publica server ssh
├── .gitignore
├── requirements.txt
└── README.md
```

## 🔧 Instalación

### 1️⃣ Clonar el repositorio
```bash
git clone https://github.com/Spoirad/Honeypot.git
cd honeypot
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

### 🔹 Comandos en tiempo de ejecución
Una vez iniciado el controlador, puedes usar la consola interactiva:
- `status`: Ver estado de los servicios.
- `stop <ssh|web|ftp|all>`: Detener servicios (nota: detiene el proceso principal).
- `exit`: Salir.

### 🔹 Ejecutar el Dashboard (Análisis)
Para ver estadísticas y generar los CSVs:
```bash
python dashboard.py
```

---

## 🧾 Salida esperada (Dashboard)

```text
=================== HONEYPOT DASHBOARD ===================
Total SSH attempts      : 12
Total SSH commands      : 5
Total HTTP logins       : 8
Total FTP logins        : 4
Total FTP commands      : 15

Top 5 IPs (SSH attempts):
  192.168.1.50                 12

Top 5 Comandos SSH ejecutados:
  whoami                       3
  ls -la                       2

Top 5 Usuarios (FTP):
  admin                        3
  anonymous                    1

[+] Exportado: out/ssh_attempts.csv
[+] Exportado: out/http_logins.csv
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
- **Advertencia**: Los archivos subidos vía Web se guardan en `logs/web_uploads`. No ejecutarlos en la máquina local.
- Los logs **no deben compartirse públicamente**, ya que pueden contener credenciales o direcciones IP sensibles.

---

## 📈 Expansión futura (TFG)

El proyecto está preparado para evolucionar hacia un **honeypot modular** y un **dashboard avanzado**, con:

- Panel de control web local para gestionar múltiples honeypots.  
- Visualización de logs en tiempo real (gráficas, geolocalización de IPs).  
- Sistema de alertas automáticas (correo o Telegram).  
- Almacenamiento en base de datos (SQLite o MongoDB).  
- Integración con herramientas de análisis (ELK Stack o Splunk).

---

## 🧰 Dependencias principales

- [Python 3.10+](https://www.python.org/)  
- [Paramiko](https://pypi.org/project/paramiko/)  
- [Flask](https://pypi.org/project/Flask/)

**Contenido de `requirements.txt`:**
```text
paramiko==3.4.0
flask==3.0.0
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
