# ----- Librerias -----
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for


# ----- Logging -----

logging_format = logging.Formatter('%(asctime)s %(message)s')

# ----- HTTP Logger -----

http_logger = logging.getLogger('FunnelLogger')
http_logger.setLevel(logging.INFO)
http_handler = RotatingFileHandler('http_audits.log', maxBytes=2000, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

# ----- Honeypot -----

def web_honeypot(input_username="admin", input_password="password"):
    app = Flask(__name__)

    @app.route('/')

    def index():
        return render_template('login.html')
    
    @app.route('/login.html', methods=['POST'])


    def login():
        username = request.form['username']
        password = request.form['password'] 

        ip_address = request.remote_addr

        http_logger.info(f'Cliente con IP:  {ip_address} accedio con credenciales: {username}, {password}')

        if username == input_username and password == input_password:
            # Respuesta simple de éxito (puedes personalizar)
            #return render_template("login_success.html"), 200
            return "Usuario o contraseña correctos"
        else:
            # volver al login con mensaje de fallo (código 401 para simular autenticación fallida)
            #return render_template("login.html", error="Usuario o contraseña incorrectos"), 401
            return "Usuario o contraseña incorrectos"

    return app
    
def run_henoypot(port = 5000,input_username="admin", input_password="password"):
    run_app = web_honeypot(input_username, input_password)
    run_app.run(debug=True, port=port, host='0.0.0.0')

    return run_app

#prueba
run_henoypot(port=5000, input_username='admin', input_password='admin')