#archivo para centralizar el control y despliegue de los distintos tipos de honeypots.

# ----- Librerias -----
import argparse
import threading
import time
import sys
from ssh_honeypot import run_ssh_honeypot   # importa solo la función pública que inicia el honeypot
from web_honeypot import run_web_honeypot 
# ----- Argumentos -----

def start_thread(target, *args, name=None):
    """Helper: lanzar target(...) en un hilo daemon y devolver el objeto Thread."""
    t = threading.Thread(target=target, args=args, daemon=True, name=name)
    t.start()
    return t


def main():

    parser = argparse.ArgumentParser(description="Controlador de honeypots")
    parser.add_argument('-a', '--address', type=str, default="0.0.0.0", help="IP donde escuchar (SSH)")
    parser.add_argument('-p', '--port', type=int, default=2223, help="Puerto SSH o Web (según el servicio)")
    parser.add_argument('-u', '--username', type=str, default=None)
    parser.add_argument('-pw', '--password', type=str, default=None)
    parser.add_argument('-s', '--ssh', action="store_true", help="Arrancar honeypot SSH")
    parser.add_argument('-w', '--web', action="store_true", help="Arrancar honeypot web")
    parser.add_argument('--web-port', type=int, default=8080, help="Puerto para el honeypot web (si -w)")
    args = parser.parse_args()


    threads = {}

    try:
        if args.ssh:
            print("Arrancando SSH honeypot...")
            # Lanza la función blocking `ssh_honeypot(address, port, username, password)` en hilo
            t_ssh = start_thread(run_ssh_honeypot, args.address, args.port, args.username, args.password, name="SSH-Honeypot")
            threads['ssh'] = t_ssh
            print(f"SSH honeypot arrancado en hilo (escuchando en {args.address}:{args.port}).")

        if args.web:
            print("Arrancando Web honeypot...")
            # run_web_honeypot puede tener firma (port, user, pass, host). Ajusta si tu función difiere.
            t_web = start_thread(run_web_honeypot, args.web_port, args.username or "admin", args.password or "password", "0.0.0.0", name="WEB-Honeypot")
            threads['web'] = t_web
            print(f"Web honeypot arrancado en hilo (escuchando en 0.0.0.0:{args.web_port}).")

        if not threads:
            print("No se inició ningún honeypot. Usa -s/--ssh o -w/--web.")
            return

        # Bucle interactivo simple para controlar
        print("\nControl console: escribe 'status', 'stop <ssh|web|all>' o 'exit'")
        while True:
            cmd = input("> ").strip().lower()
            if cmd in ("exit", "quit"):
                print("Saliendo y deteniendo honeypots (los hilos daemon se cerrarán con el proceso)...")
                break
            if cmd == "status":
                for k, th in threads.items():
                    alive = "alive" if th.is_alive() else "stopped"
                    print(f"- {k}: {alive}")
                continue
            if cmd.startswith("stop"):
                parts = cmd.split()
                if len(parts) == 1 or parts[1] == "all":
                    print("Parando todos (termina el proceso principal)...")
                    break
                target = parts[1]
                if target in threads:
                    # Los hilos son daemon; no hay 'stop' inmediato. Informar al usuario.
                    print(f"Nota: los hilos son daemon; para detener {target} puedes salir del controlador (exit).")
                else:
                    print("Nombre de servicio desconocido. Opciones: " + ", ".join(threads.keys()))
                continue

            print("Comando no reconocido. Usa 'status', 'stop <ssh|web|all>' o 'exit'.")

    except KeyboardInterrupt:
        print("\nCtrl+C detectado. Terminando...")
    finally:
        # Salida limpia: como los hilos son daemon, el proceso terminará y los hilos se cerrarán.
        print("Controlador finalizado.")
        sys.exit(0)

if __name__ == "__main__":
    main()