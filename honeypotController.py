#archivo para centralizar el control y despliegue de los distintos tipos de honeypots.

# ----- Librerias -----
import argparse
import threading
import time
from ssh_honeypot import *   # importa solo la función pública que inicia el honeypot

# ----- Argumentos -----

#def run_ssh(address, port, username, password):
#    # wrapper que llama a tu función honeypot (bloqueante)
#    honeypot(address, port, username, password)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Controlador de honeypots")
    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str, default=None)
    parser.add_argument('-pw', '--password', type=str, default=None)
    parser.add_argument('-s', '--ssh', action="store_true", help="Arrancar honeypot SSH")
    parser.add_argument('-w', '--web', action="store_true", help="Arrancar honeypot web")

    args = parser.parse_args()

    try:
        if args.ssh:
            print("SSH Honeypot activado")
            # arrancar el honeypot en un hilo daemon para no bloquear la terminal principal
            honeypot(args.address, args.port, args.username, args.password)

            #thread_ssh = threading.Thread(target=run_ssh,args=(args.address, args.port, args.username, args.password), daemon=True)
            #thread_ssh.start()

            #print("Honeypot SSH arrancado en hilo. Usa Ctrl+C para parar.")

        elif args.web:
            print("WEB Honeypot activado")
            # Aquí pondrías la llamada al honeypot web

            print("Funcionalidad web no implementada aún.")
        else:
            # evita el uso de backslash sin escape en cadenas
            print("Tipo de Honeypot no especificado (-s/--ssh o -w/--web).")

    except KeyboardInterrupt:
        print("\nDetención solicitada por usuario. Cerrando...")
    except Exception as e:
        print("Error inesperado:", e)
    finally:
        print("Proceso finalizado.")
