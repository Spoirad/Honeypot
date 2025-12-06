# ------Librerias------

import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko #pure python implement de SSHv2 (server y client)
import threading #manejo de threads para poner manejar varios client con el server

# ------Contantes------ 
logging_format = logging.Formatter('%(asctime)s %(message)s')
SSH_BANNER = "SSH-2.0-SSHServer_1.0"

#host_key = 'server.key' # private key  [Debe mantenerse secreto o en local]
host_key = paramiko.RSAKey(filename='server.key')

# ------Loggers & Logging Files------


#Este primero es para capturar IP adress, username , pass
#datos de logger en documentaciond e python python-logging
funnel_logger = logging.getLogger('SSHFunnelLogger')
funnel_logger.setLevel(logging.INFO)

#handler --> provides options so it sets the format. where we are going to log
funnel_handler = RotatingFileHandler('logs/ssh_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5)  #setting para el funnel logger, tb crea el audits
funnel_handler.setFormatter(logging_format)

# se las ponemos al logger 
funnel_logger.addHandler(funnel_handler)

# creamos otro para capturar la shell emulada, es lo mismo pero para capturar los datos de otro sitio.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('logs/ssh_cmd_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5) 
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# ------Emulated shell------

#se crearan funciones para hacerlo mas modular


#channel es basicamente la forma de comunicarse o enviar dialogos en la conexion SSH
def emulated_shell(channel, client_ip):
    # simula prompt "corporate-jumpbox$"--> host que representa un jumpbox/bastion, el $ indica usuario no root.
    # Un jumpbox es un punto de salto endurecido usado para administración remota, suele ser objetivo valioso.
    channel.send(b'corporate-jumpbox3$ ') # b de binario

    #recibir comandos
    #Se dasarrolla un loop en el que se simula la terminal hasta que se inserte exit(simulando asi la terminal)
    command = b""
    while True:
        char = channel.recv(1) #escuchar el input del usuario
        channel.send(char)
        if not char: # si no recibimos un char cerramos el channel
            channel.close()

        command += char #convinar todos los caracteres en una única string

        if char == b'\r':  # significa el return en binario basicamente
            if command.strip() == b'exit': # el strip es una funcion de python que elimina espacios en blanco/saltos de linea al principio y final pero si se escribio pwd\n por ejemplo
                response = b'\n Goodbye!\n'
                channel.close()
            elif command.strip() == b'pwd': # mostrar dierctorio actual
                response = b"\n" + b'\\usr\\local' + b'\r\n' # \\ = \ dentro de string de python || esto simula terminal mostrando ese directorio 
            elif command.strip() == b'whoami':
                response = b"\n" + b"corpuser3" + b'\r\n' #user de ejemplo
            elif command.strip() == b'ls': #listar 
                response = b"\n" + b'jumpbox.conf' + b'\r\n' #archivo ficticio para indicar que la máquina es un bastion/jumpbox (lo cual se supondría por el user).
            elif command.strip() == b'cat jumpbox.conf': # cat del contenido del archivo
                response = b"\n" + b"Incluir archivo de configuracion " + b'\r\n'
            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n" # si escriben algo no soportado simplemente se lo devuelve

            # logs
            creds_logger.info(f'Command {command.strip()}' + ' executed by ' + f'{client_ip}')
            # enviamos respuesta y simulacion de user y reseteamos a valores por defecto
            channel.send(response)
            channel.send(b'corporate-jumpbox3$ ')
            command = b""


# ------SSH Server + Sockets------


#funcion necesaria para funcionamiento de paramiko
class Server(paramiko.ServerInterface):  # clase que implementa los callbacks que paramiko usará para el servidor SSH
     
    def __init__(self, client_ip, input_username=None, input_password=None): #inicializacion
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED # acepta solicitudes de canal tipo "session" (abrir shell)

    #autentication
    def get_allowed_auths(self, username):  #aqui no debería ser necesario el username , pero me veo obligado a ponerlo [cambio de versiones quiza???]
        return "password" # Indica que el servidor permite autenticación por contraseña

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with ' + f'username: {username}, ' + f'password: {password} ')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        # autenticación por contraseña, compara con valores previstos si existen
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL # aceptar
            else:
                return paramiko.AUTH_FAILED # rechazar
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set() # señala que la petición de shell ha sido aceptada
        return True  # permite la shell interactiva
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True # acepta  petición pseudo-TTY (permite interacción tipo terminal)
    
    #handle de los comandos que se reciben
    def check_channel_exec_request(self, channel, command):
        command = str(command)   # Convierte/normaliza el comando a string
        return True  #indica que se acepta la petición de ejecutar un comando

    
# función que maneja la conexión de un cliente al honeypot
def client_handle(client, addr, username , password):

    client_ip = addr[0]
    print(f"{client_ip} has connected to the server. ")

    try:
        #inicializar un nuevo objeto de transporte 
        #lo que hace en paramiko es manejar la sesion SSH en bajo nivel
        transport = paramiko.Transport(client) # pasar el socket del cliente
        transport.local_version = SSH_BANNER  # Banner que se mostrará al cliente al conectarse

        #inicializar el server
        server = Server(client_ip=client_ip, input_username = username, input_password = password) # creamos instancia del server


        #para este paso se necesita general un par de claves public-private , lo generamos via SSH key gen
        #ssh-keygen -t rsa -b 2048 -f server.key - este comando genera 2 documentos 1 privado y ptrp publico son sus respectivas claves.

        # añade la clave privada del servidor para la autenticación SSH
        transport.add_server_key(host_key)

        # Inicia el servidor SSH en el transport, usando nuestra clase Server
        transport.start_server(server = server)

        channel = transport.accept(100) # espera a que el cliente abra un canal (shell) hasta 100 ms
        if channel is None:
            print("No channel was opened. ")
        # banner que se muestra al cliente al conectarse a la shell (simula un servidor Ubuntu)
        standart_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)! \r\n\r\n" 
        channel.send(standart_banner)

        # inicia la shell
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error: # Captura errores de la conexión o del transporte
        print(error)

    finally:
        # Cierre seguro del transporte y del socket del cliente
        try:
            transport.close()
        except Exception as error:
            print(error)
        client.close()


# ------Provisioning SSH-Based Hoheypot------

def run_ssh_honeypot(address, port, username, password):

    # creamos un socket
    # AF_INET--> define que va ser ipv4, SOCK_STREAM--> define que usaremos TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #conf add , SO_REUSEADDR --> permite reusar addr, el 1 basicamente es para decirle que esten enable
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind((address, port))  
    #soprta hasta 100 conexiones
    sock.listen(100)

    print(f"SSH server is listening on port {port}. ")

    while True:
        try:
            client, addr = sock.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)



#run_ssh_honeypot('127.0.0.1', 2223, "username", "password")
#run_ssh_honeypot('127.0.0.1', 2223, username=None, password=None)