# web_honeypot.py
# ----- Librerias -----
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request

# ----- Logging -----
logging_format = logging.Formatter('%(asctime)s %(message)s')

# ----- HTTP Logger -----
http_logger = logging.getLogger('FunnelLogger')
http_logger.setLevel(logging.INFO)
http_handler = RotatingFileHandler('logs/http_audits.log', maxBytes=10 * 1024 * 1024, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

# ----- Honeypot Web (Flask) -----
def web_honeypot(input_username="admin", input_password="password"):
    app = Flask(__name__)

    # pagina de login
    @app.route("/", methods=["GET"])
    def index():
        # flask buscara login.html en la carpeta templates/
        return render_template("login.html")

    # endpoint que recibe el POST del formulario de login
    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")

        # dejar en los logs el intento 
        http_logger.info(f'login_attempt ip={ip_address} user="{username}" pass="{password}" ua="{user_agent}"')

        # simular fallo si no coincide
        if username == input_username and password == input_password:
            # exito
            return render_template("login_success.html"), 200
        else:
            # fallo (código 401 para simular autenticación fallida)
            return render_template("login.html", error="Usuario o contraseña incorrectos"), 401

    return app

def run_web_honeypot(port=5000, input_username="admin", input_password="password", host="0.0.0.0", debug=False):
    app = web_honeypot(input_username, input_password)
    app.run(host=host, port=port, debug=debug)

# añadido para pruebas (evita arranque automatico al importar)
if __name__ == "__main__":
    run_web_honeypot(port=5000, input_username="admin", input_password="admin", debug=False)
