📘 README.md — Honeypot SSH & HTTP en Python
# 🛡️ Honeypot SSH & HTTP en Python

**Autor:** Ángel López Paparella  
**Asignatura:** Proyectos (3 créditos)  
**Universidad:** [Añadir aquí nombre del centro o grado]  
**Fecha:** [Mes/Año de entrega]

---

## 🧠 Introducción

Este proyecto consiste en el desarrollo de un **Honeypot de baja interacción** implementado en **Python**, capaz de simular servicios **SSH** y **HTTP**, registrar los intentos de acceso y almacenar los eventos generados para su posterior análisis.

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

### 🌐 Honeypot HTTP (`web_honeypot.py`)
- Simula un portal web con formulario de login (Flask + HTML).
- Captura intentos de autenticación (usuario, contraseña, IP, User-Agent).
- Registra los intentos en:
  - `logs/http_audits.log`
- Página utilizada: `templates/login.html` (login minimalista y realista).

### 🧩 Controlador de servicios (`honeypotController.py`)
- Permite lanzar el honeypot SSH o HTTP desde una misma interfaz.
- Controla parámetros como dirección, puerto, usuario y contraseña.
- Soporta ejecución de un honeypot a la vez.
- Muestra mensajes de estado y permite detener el servicio con `Ctrl+C`.

### 📊 Dashboard CLI (`dashboard.py`)
- Analiza los logs generados por ambos honeypots.
- Muestra estadísticas en consola:
  - Total de eventos por servicio.
  - IPs con más actividad.
  - Usuarios y contraseñas más utilizados.
  - Comandos SSH más ejecutados.
- Limpia los comandos con caracteres de retroceso (`\x7f`).
- No requiere conexión web ni dependencias adicionales.

---

## 📂 Estructura del proyecto



Honeypot/
│
├── ssh_honeypot.py # Honeypot SSH (Paramiko)
├── web_honeypot.py # Honeypot HTTP (Flask)
├── honeypotController.py # Controlador central
├── dashboard.py # Análisis de logs en consola
│
├── templates/
│ └── login.html # Página de login señuelo
│
├── logs/ # Carpeta de registros
│ ├── ssh_audits.log
│ ├── ssh_cmd_audits.log
│ └── http_audits.log
│
├── .gitignore
├── requirements.txt
└── README.md


---

## 🔧 Instalación

### 1️⃣ Clonar el repositorio
```bash
git clone https://github.com/<tu_usuario>/honeypot.git
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

### 🔹 Iniciar el Honeypot SSH
```bash
python honeypotController.py -a 0.0.0.0 -p 2223 --ssh -u admin -pw admin
```

### 🔹 Iniciar el Honeypot HTTP
```bash
python honeypotController.py -w --web -p 8080
```

### 🔹 Ejecutar el Dashboard
```bash
python dashboard.py
```

---

### 🧾 Salida esperada
```text
=================== HONEYPOT DASHBOARD ===================
Total SSH attempts: 3
Total SSH commands: 6
Total HTTP logins : 4

Top 5 IPs (SSH attempts):
  127.0.0.1                      3

Top 5 Usuarios (SSH):
  username                       3

Top 5 Comandos SSH ejecutados:
  whoami                         2
  uname -a                       1

Top 5 IPs (HTTP):
  127.0.0.1                      4

Top 5 Usuarios (HTTP):
  admin                          4
```

---

## 📁 Ejemplo de logs

### 🧩 SSH — `logs/ssh_audits.log`
```text
2025-10-23 12:41:57,528 Client 127.0.0.1 attempted connection with username: admin, password: 1234
```

### ⚙️ SSH Comandos — `logs/ssh_cmd_audits.log`
```text
2025-10-23 12:42:02,249 Command b'whoami' executed by 127.0.0.1
```

### 🌐 HTTP — `logs/http_audits.log`
```text
2025-10-23 12:22:17,332 login_attempt ip=127.0.0.1 user="admin" pass="admin" ua="Mozilla/5.0 ..."
```

---

## 🔒 Seguridad

- El honeypot debe ejecutarse **en entorno controlado** (máquina virtual o contenedor).  
- No debe exponerse directamente a Internet sin un proxy o cortafuegos intermedio.  
- Los servicios no ejecutan ningún comando real, solo simulan respuestas.  
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
