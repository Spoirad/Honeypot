# ------ Librerias ------

import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import random
import time
import os

# ------ Constantes / Logging ------

logging_format = logging.Formatter('%(asctime)s %(message)s')

ftp_logger = logging.getLogger('FtpLogger')
ftp_logger.setLevel(logging.INFO)

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

ftp_handler = RotatingFileHandler('logs/ftp_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5)
ftp_handler.setFormatter(logging_format)
ftp_logger.addHandler(ftp_handler)

# ------ Configuración de Honeypot ------

VALID_USERS = {
    "admin": "password",
    "employee": "1234",
    "user": "12345"
}

# Sistema de ficheros falso
# Estructura: Diccionario anidado. Keys son nombres, Values son dicts (dirs) o strings (contenido fichero)
FAKE_FILESYSTEM = {
    "root": {
        "readme.txt": "Welcome to the corporate FTP server.\nUnauthorized access is prohibited.",
        "backups": {
            "db_dump.sql": "CREATE TABLE users...",
            "config.xml": "<config><user>admin</user></config>"
        },
        "public": {
            "logo.png": "[BINARY_DATA_FAKE]",
            "newsletter.pdf": "[BINARY_DATA_FAKE]"
        },
        "private": {
            "passwords.txt": "admin:supersecret\njohn:123456"
        }
    }
}

# ------ Clase para manejar sesión FTP ------

class FTPHoneypotSession:
    def __init__(self, client_socket, addr):
        self.client = client_socket
        self.client_ip = addr[0]
        self.buffer = b""
        self.authenticated = False
        self.username = None
        
        # Filesystem state
        self.cwd = ["root"] # Path como lista de directorios
        
        # Data connection state
        self.pasv_socket = None
        self.data_mode = 'I' # ASCII (A) or Image/Binary (I)

    def send(self, msg):
        try:
            if not msg.endswith("\r\n"):
                msg += "\r\n"
            self.client.sendall(msg.encode("utf-8"))
        except Exception as e:
            print(f"Error sending to {self.client_ip}: {e}")

    def get_cwd_path(self):
        # Convierte lista ["root", "backups"] a "/backups" (ocultamos 'root')
        if len(self.cwd) == 1:
            return "/"
        return "/" + "/".join(self.cwd[1:])

    def get_current_dir_node(self):
        # Navega el FAKE_FILESYSTEM hasta el directorio actual
        node = FAKE_FILESYSTEM["root"]
        for d in self.cwd[1:]:
            if d in node and isinstance(node[d], dict):
                node = node[d]
            else:
                return None # Error estado corrupto/borrado
        return node

    def handle_command(self, raw_cmd):
        ftp_logger.info(f'command ip={self.client_ip} user="{self.username}" raw="{raw_cmd}"')
        
        parts = raw_cmd.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "USER":
            self.username = arg
            ftp_logger.info(f'login_user ip={self.client_ip} user="{self.username}"')
            self.send(f"331 Password required for {self.username}")

        elif cmd == "PASS":
            password = arg
            if self.username in VALID_USERS and VALID_USERS[self.username] == password:
                self.authenticated = True
                ftp_logger.info(f'login_success ip={self.client_ip} user="{self.username}" pass="{password}"')
                self.send("230 Login successful.")
            else:
                ftp_logger.info(f'login_failure ip={self.client_ip} user="{self.username}" pass="{password}"')
                self.send("530 Login incorrect.")

        elif cmd == "SYST":
            self.send("215 UNIX Type: L8")

        elif cmd == "QUIT":
            self.send("221 Goodbye.")
            return True # Close connection

        elif cmd == "FEAT":
            self.send("211-Features:\r\n PASV\r\n TYPE\r\n211 End")

        elif cmd == "TYPE":
            if arg.upper() == "A":
                self.data_mode = 'A'
                self.send("200 Switching to ASCII mode.")
            elif arg.upper() == "I":
                self.data_mode = 'I'
                self.send("200 Switching to Binary mode.")
            else:
                self.send("500 Unrecognised TYPE command.")

        # --- Comandos que requieren autenticacion ---
        
        elif not self.authenticated:
            self.send("530 Please login with USER and PASS.")

        elif cmd == "PWD" or cmd == "XPWD":
            path = self.get_cwd_path()
            self.send(f'257 "{path}" is the current directory')

        elif cmd == "CWD":
            target = arg
            current_node = self.get_current_dir_node()
            
            if target == "..":
                if len(self.cwd) > 1:
                    self.cwd.pop()
                    self.send("250 Directory successfully changed.")
                    ftp_logger.info(f'cwd ip={self.client_ip} path="{self.get_cwd_path()}"')
                else:
                    self.send("550 Failed to change directory.")
            
            elif target == "/" or target == "\\":
                self.cwd = ["root"]
                self.send("250 Directory successfully changed.")
            
            elif target in current_node and isinstance(current_node[target], dict):
                self.cwd.append(target)
                self.send("250 Directory successfully changed.")
                ftp_logger.info(f'cwd ip={self.client_ip} path="{self.get_cwd_path()}"')
            else:
                self.send("550 Failed to change directory.")

        elif cmd == "PASV":
            # Crear socket pasivo
            try:
                self.pasv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.pasv_socket.bind(('0.0.0.0', 0)) # Puerto aleatorio
                self.pasv_socket.listen(1)
                port = self.pasv_socket.getsockname()[1]
                
                # Calcular formato IP,p1,p2
                # Asumimos que el cliente conecta a la IP donde recibimos la conexion (self.client.getsockname())
                # En local 127.0.0.1
                host_ip = self.client.getsockname()[0] 
                ip_parts = host_ip.split('.')
                p1 = port // 256
                p2 = port % 256
                
                resp_arg = f"{ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1},{p2}"
                self.send(f"227 Entering Passive Mode ({resp_arg}).")
                ftp_logger.info(f'pasv_mode ip={self.client_ip} port={port}')

            except Exception as e:
                print(f"Error PASV: {e}")
                self.send("425 Can't open data connection.")

        elif cmd == "LIST" or cmd == "NLST":
            self.send("150 Here comes the directory listing.")
            
            content = ""
            current_node = self.get_current_dir_node()
            
            # Formato 'ls -l'
            # drwxr-xr-x 2 ftp ftp 4096 Jan 1 00:00 directory
            # -rw-r--r-- 1 ftp ftp  123 Jan 1 00:00 file.txt
            
            date_str = "Jan 01  2023"
            
            if current_node:
                for name, item in current_node.items():
                    if isinstance(item, dict):
                        line = f"drwxr-xr-x 1 ftp ftp 4096 {date_str} {name}\r\n"
                    else:
                        size = len(item)
                        line = f"-rw-r--r-- 1 ftp ftp {size} {date_str} {name}\r\n"
                    content += line
            
            self.send_data(content.encode('utf-8'))
            self.send("226 Directory send OK.")

        elif cmd == "RETR":
            filename = arg
            current_node = self.get_current_dir_node()
            
            if filename in current_node and not isinstance(current_node[filename], dict):
                self.send(f"150 Opening data connection for {filename}")
                data = current_node[filename].encode('utf-8') # Simplificado, solo texto/fake
                self.send_data(data)
                self.send("226 Transfer complete.")
                ftp_logger.info(f'file_download ip={self.client_ip} file="{filename}"')
            else:
                self.send("550 File not found.")

        elif cmd == "MKD":
            # Fake create
            self.send(f'257 "{arg}" created')
            ftp_logger.info(f'mkd_attempt ip={self.client_ip} dir="{arg}"')
            
        elif cmd == "DELE":
            # Fake delete
            self.send("250 Delete operation successful.")
            ftp_logger.info(f'dele_attempt ip={self.client_ip} file="{arg}"')
            
        elif cmd == "HELP":
             self.send("214-The following commands are recognized:\r\n USER PASS OPTS TYPE CWD PWD XPWD PASV LIST NLST RETR STOR MKD DELE HELP QUIT SYST FEAT\r\n214 Help OK.")

        else:
            self.send("502 Command not implemented.")
            
        return False

    def send_data(self, data_bytes):
        # Enviar datos por el canal de datos (PASV)
        if not self.pasv_socket:
            return # No hay canal
        
        try:
            # Esperar conexion del cliente
            self.pasv_socket.settimeout(10) # 10 seg timeout
            conn, addr = self.pasv_socket.accept()
            conn.sendall(data_bytes)
            conn.close()
        except Exception as e:
            print(f"Data transfer error: {e}")
        finally:
            self.pasv_socket.close()
            self.pasv_socket = None


# ------ Manejo de cliente FTP ------

def handle_ftp_client(client, addr):
    session = FTPHoneypotSession(client, addr)
    client_ip = addr[0]

    try:
        # Banner
        session.send("220 ProFTPD 1.3.5a Server (Debian) [Managers Only]")
        ftp_logger.info(f'new_connection ip={client_ip}')

        while True:
            data = client.recv(1024)
            if not data:
                break
            
            session.buffer += data
            
            while b"\r\n" in session.buffer:
                line, session.buffer = session.buffer.split(b"\r\n", 1)
                try:
                    decoded = line.decode("utf-8", errors="ignore")
                except:
                    continue
                
                if not decoded: continue
                
                should_exit = session.handle_command(decoded.strip())
                if should_exit:
                    return

    except Exception as error:
        print(f"Connection Error {client_ip}: {error}")
    finally:
        client.close()
        if session.pasv_socket:
            try: session.pasv_socket.close()
            except: pass


# ------ Provisioning FTP Honeypot ------

def run_ftp_honeypot(address="0.0.0.0", port=21):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((address, port))
    except Exception as e:
        print(f"Error binding FTP port {port}: {e}")
        return

    sock.listen(50)
    print(f"FTP server is listening on {address}:{port}.")

    while True:
        try:
            client, addr = sock.accept()
            ftp_thread = threading.Thread(target=handle_ftp_client, args=(client, addr))
            ftp_thread.start()
        except Exception as error:
            print(error)


if __name__ == "__main__":
    run_ftp_honeypot(address="127.0.0.1", port=2121)
