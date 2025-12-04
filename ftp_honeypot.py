# ------ Librerias ------

import logging
from logging.handlers import RotatingFileHandler
import socket
import threading

# ------ Constantes / Logging ------

logging_format = logging.Formatter('%(asctime)s %(message)s')

ftp_logger = logging.getLogger('FtpLogger')
ftp_logger.setLevel(logging.INFO)

ftp_handler = RotatingFileHandler('logs/ftp_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5)
ftp_handler.setFormatter(logging_format)
ftp_logger.addHandler(ftp_handler)


# ------ Manejo de cliente FTP ------


# funcion que simula una conexion al honeypot , con ftp basico, registra todo
def handle_ftp_client(client, addr):

    client_ip = addr[0]
    current_user = None

    try: #Intentar conexion

        # en el banner se puede poner cualquier cosa , este es un ejemplo de servidor FTP
        banner = "220 ProFTPD 1.3.5a Server (Debian)\r\n"
        client.sendall(banner.encode("utf-8"))
        ftp_logger.info(f'new_connection ip={client_ip}')

        buffer = b"" # baciar buffer

        while True:

            # recibimos lo que envía el cliente  
            # si está vacío ( el cliente ha cerrado la conexión ) salimos del bucle
            # sino acumulamos los datos en 'buffer' para procesarlos línea a línea cuando encontremos "\r\n".    
            # esto puede ser necesario porque el atacante puede enviar por ejemplo, "USER admin\r\n" puede llegar dividido en dos paquetes
            data = client.recv(1024)
            if not data:
                break
            buffer += data

            # procesar línea a línea (comandos terminados en \r\n)
            while b"\r\n" in buffer:
                line, buffer = buffer.split(b"\r\n", 1)
                try:
                    decoded = line.decode("utf-8", errors="ignore")
                except Exception:
                    decoded = ""

                if not decoded:
                    continue
        
                # guardar comando completo para logs
                raw_cmd = decoded.strip()
                ftp_logger.info(f'command ip={client_ip} raw="{raw_cmd}"')

                # separar comando y argumentos
                parts = raw_cmd.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ""


                # aqui vendrían un conjunto de comandos simulados 
                if cmd == "USER":
                    current_user = arg
                    ftp_logger.info(f'login_user ip={client_ip} user="{current_user}"')
                    response = f"331 Password required for {current_user}\r\n"
                    client.sendall(response.encode("utf-8"))

                elif cmd == "PASS":
                    password = arg
                    # registrar intento de credenciales (no se concede acceso real)
                    ftp_logger.info(
                        f'login_attempt ip={client_ip} user="{current_user if current_user else ""}" pass="{password}"'
                    )
                    # siempre rechazamos el login, es un honeypot
                    response = "530 Login incorrect.\r\n"
                    client.sendall(response.encode("utf-8"))

                elif cmd == "SYST":
                    response = "215 UNIX Type: L8\r\n"
                    client.sendall(response.encode("utf-8"))

                elif cmd in ("PWD", "XPWD"):
                    # directorio actual simulado
                    response = '257 "/" is the current directory\r\n'
                    client.sendall(response.encode("utf-8"))

                elif cmd == "TYPE":
                    # aceptar cambio de tipo sin hacer nada real
                    response = "200 Type set to I.\r\n"
                    client.sendall(response.encode("utf-8"))

                elif cmd == "PASV":
                    # no implementamos canal de datos real; devolvemos error genérico
                    response = "502 Passive mode not implemented.\r\n"
                    client.sendall(response.encode("utf-8"))

                elif cmd == "LIST":
                    # simulamos una respuesta de listado
                    client.sendall(b"150 Opening ASCII mode data connection for file list\r\n")
                    # no se establece canal de datos real, solo un listado ficticio
                    fake_list = (
                        "-rw-r--r-- 1 ftp ftp     532 Jan 12  2023 readme.txt\r\n"
                        "drwxr-xr-x 2 ftp ftp    4096 Jan 12  2023 backups\r\n"
                        "drwxr-xr-x 2 ftp ftp    4096 Jan 12  2023 configs\r\n"
                    )
                    client.sendall(fake_list.encode("utf-8"))
                    client.sendall(b"226 Transfer complete.\r\n")

                elif cmd == "QUIT":
                    response = "221 Goodbye.\r\n"
                    client.sendall(response.encode("utf-8"))
                    return

                else:
                    # comando no soportado
                    response = "502 Command not implemented.\r\n"
                    client.sendall(response.encode("utf-8"))

    # TRY INICIAL
    except Exception as error:
        print(error)
    finally:
        try:
            client.close()
        except Exception as error:
            print(error)


# ------ Provisioning FTP Honeypot ------

def run_ftp_honeypot(address="0.0.0.0", port=21):

    # inicia el honeypot FTP escuchando en la dirección y puerto indicados
    # usa sockets y threads para manejar múltiples clientes
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind((address, port))
    sock.listen(50)

    print(f"FTP server is listening on {address}:{port}.")


    while True:
        try:
            client, addr = sock.accept()
            ftp_thread = threading.Thread(target=handle_ftp_client, args=(client, addr))
            ftp_thread.start()
        except Exception as error:
            print(error)


# añadido para pruebas locales
if __name__ == "__main__":
    # ejemplo: honeypot FTP escuchando en 2121 para pruebas
    run_ftp_honeypot(address="127.0.0.1", port=2121)


