from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import re

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import logging

import hmac
import hashlib

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'
# Ruta del archivo JSON donde se guardarán los registros
RUTA_JSON = 'usuarios.json'

# Cargar o crear el archivo JSON si no existe
if not os.path.exists(RUTA_JSON):
    with open(RUTA_JSON, 'w') as f:
        json.dump([], f)

# Función para leer los usuarios del archivo JSON
def leer_usuarios():
    try:
        with open(RUTA_JSON, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al leer el archivo JSON: {e}")
        return []

# Función para guardar usuarios en el archivo JSON
def guardar_usuario(nuevo_usuario):
    try:
        usuarios = leer_usuarios()

        # Verificar si el nombre de usuario o el correo ya existen
        for usuario in usuarios:
            if usuario['username'] == nuevo_usuario['username'] or usuario['email'] == nuevo_usuario['email']:
                return False

        usuarios.append(nuevo_usuario)
        with open(RUTA_JSON, 'w') as f:
            json.dump(usuarios, f)
        return True
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al escribir el archivo JSON: {e}")
        return False

# Función para validar el formato de correo electrónico
def validar_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# Función para validar la contraseña (mínimo 8 caracteres)
def validar_contraseña(password):
    return len(password) >= 8






# Configuración del log para mostrar mensajes
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()


# Función para cifrar un mensaje con AES-GCM
def cifrar_aes(texto_plano, clave):
    # Genera un nonce (vector de inicialización) aleatorio
    nonce = get_random_bytes(12)

    # Crea un objeto de cifrado AES en modo GCM
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)

    # Cifra el texto plano
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_plano.encode())

    # Devuelve el texto cifrado, el nonce y el tag (para autenticar el mensaje)
    return texto_cifrado, nonce, tag


# Función para descifrar un mensaje cifrado con AES-GCM
def descifrar_aes(texto_cifrado, nonce, tag, clave):
    # Crea un objeto de descifrado AES en modo GCM con el mismo nonce
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)

    # Descifra el texto cifrado y verifica la integridad con el tag
    try:
        texto_descifrado = cipher.decrypt_and_verify(texto_cifrado, tag)
        return texto_descifrado.decode()
    except ValueError:
        logger.error("Error: el mensaje ha sido alterado o la clave es incorrecta.")
        return None


# Generación de clave AES de 256 bits (32 bytes)
clave_aes = get_random_bytes(32)  # 256 bits

# Mensaje a cifrar
mensaje = "Aqui estara el mensaje que queramos cifrar luego"

# Cifrar el mensaje
texto_cifrado, nonce, tag = cifrar_aes(mensaje, clave_aes)
logger.info(f"Texto cifrado (base64): {base64.b64encode(texto_cifrado).decode()}")
logger.info(f"Nonce (base64): {base64.b64encode(nonce).decode()}")
logger.info(f"Tag (base64): {base64.b64encode(tag).decode()}")
logger.info(f"Algoritmo: AES-GCM, Longitud de clave: {len(clave_aes) * 8} bits")

# Descifrar el mensaje
texto_descifrado = descifrar_aes(texto_cifrado, nonce, tag, clave_aes)

if texto_descifrado:
    logger.info(f"Texto descifrado: {texto_descifrado}")









# Función para generar HMAC
def generar_hmac(mensaje, clave):
    # Crear un objeto HMAC con la clave secreta y el algoritmo SHA-256
    hmac_obj = hmac.new(clave, mensaje.encode(), hashlib.sha256)

    # Generar el HMAC
    hmac_digest = hmac_obj.digest()

    # Devolver el HMAC en formato base64 para que sea legible
    return base64.b64encode(hmac_digest).decode()


# Función para verificar HMAC
def verificar_hmac(mensaje, clave, hmac_proporcionado):
    # Volver a generar el HMAC con el mensaje y la clave secreta
    hmac_calculado = generar_hmac(mensaje, clave)

    # Comparar el HMAC calculado con el proporcionado
    if hmac.compare_digest(hmac_calculado, hmac_proporcionado):
        logger.info("HMAC válido. El mensaje no ha sido alterado.")
        return True
    else:
        logger.error("HMAC no válido. El mensaje ha sido alterado o la clave es incorrecta.")
        return False


# Clave secreta (debe ser compartida entre emisor y receptor)
clave_secreta = b'secret_key_very_secure'

# Mensaje a autenticar
mensaje = "Este es un mensaje importante."

# Generar el HMAC para el mensaje
hmac_generado = generar_hmac(mensaje, clave_secreta)
logger.info(f"HMAC generado (base64): {hmac_generado}")

# Verificar el HMAC generado (en una simulación de que es recibido correctamente)
es_valido = verificar_hmac(mensaje, clave_secreta, hmac_generado)











@app.route('/perfil')
def perfil():
    if 'usuario' in session:
        usuario = session['usuario']
        return render_template('perfil.html', usuario=usuario)
    else:
        return redirect(url_for('login'))


# Ruta para modificar el balance
@app.route('/modificar_balance', methods=["POST"])
def modificar_balance():
    if 'usuario' in session:
        action = request.form.get('accion')
        cantidad = float(request.form.get('cantidad'))

        # Leer usuarios desde el archivo JSON
        usuarios = leer_usuarios()
        usuario_email = session['usuario']['email']

        # Actualizar balance según la acción
        for usuario in usuarios:
            if usuario['email'] == usuario_email:
                if action == 'añadir':
                    usuario['balance'] += cantidad
                elif action == 'retirar' and usuario['balance'] >= cantidad:
                    usuario['balance'] -= cantidad
                break

        # Guardar cambios en el archivo JSON
        guardar_usuario(usuarios)

        # Actualizar balance en la sesión
        session['usuario']['balance'] = usuario['balance']
        return redirect(url_for('perfil'))  # Regresar a la página de perfil

    return redirect(url_for('login'))


# Ruta para actualizar los datos del usuario
@app.route('/actualizar_datos', methods=["POST"])
def actualizar_datos():
    if 'usuario' in session:
        nuevo_email = request.form.get('nuevo_email')
        nuevo_username = request.form.get('nuevo_username')

        # Leer usuarios desde el archivo JSON
        usuarios = leer_usuarios()
        usuario_email = session['usuario']['email']

        # Actualizar datos del usuario
        for usuario in usuarios:
            if usuario['email'] == usuario_email:
                usuario['email'] = nuevo_email
                usuario['username'] = nuevo_username
                break

        # Guardar cambios en el archivo JSON
        guardar_usuario(usuarios)

        # Actualizar datos en la sesión
        session['usuario']['email'] = nuevo_email
        session['usuario']['username'] = nuevo_username
        return redirect(url_for('perfil'))  # Regresar a la página de perfil

    return redirect(url_for('login'))

# Ruta para mostrar la página principal (index.html)
@app.route('/')
def index():

    usuario = session.get("usuario")
    return render_template('index.html', usuario=usuario)

# Ruta para mostrar la página de registro (register.html) y manejar el registro (POST)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Obtener los datos del formulario
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validación de campos obligatorios
        if not username or not email or not password:
            return jsonify({'message': 'Faltan campos obligatorios'}), 400

        # Validación del formato del correo electrónico
        if not validar_email(email):
            return jsonify({'message': 'El formato del correo electrónico es inválido'}), 400

        # Validación de la longitud de la contraseña
        if not validar_contraseña(password):
            return jsonify({'message': 'La contraseña debe tener al menos 8 caracteres'}), 400

        # Cifrar la contraseña
        hashed_password = generate_password_hash(password)

        nuevo_usuario = {
            'username': username,
            'email': email,
            'password': hashed_password,  # Guardar la contraseña cifrada
            'balance': 0
        }

        # Intentar guardar el nuevo usuario
        if guardar_usuario(nuevo_usuario):
            return redirect(url_for('index'))  # Redirigir a la página de inicio (index.html)
        else:
            return jsonify({'message': 'El nombre de usuario o el correo ya están en uso'}), 409

    return render_template('register.html')  # Si es GET, mostrar el formulario

# Ruta para mostrar la página de inicio de sesión (login.html)
@app.route('/login', methods=["GET", "POST"])
def login():

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return jsonify({'message': 'Faltan campos obligatorios'}), 400

        usuarios = leer_usuarios()
        usuario = next((u for u in usuarios if u['email'] == email), None)

        if usuario and check_password_hash(usuario['password'], password):
            session['usuario'] = {
                'username': usuario['username'],
                'email': usuario['email'],
                'balance': usuario['balance']  # Incluir el balance
            }
            return redirect(url_for('index'))
        else:
            return jsonify({'message': 'Credenciales incorrectas'}), 401

    return render_template('login.html')




@app.route('/futbol')
def futbol():
    usuario = session.get('usuario')  # Obtener al usuario de la sesión si está autenticado
    return render_template('futbol.html', usuario=usuario)


@app.route('/hipica')
def hipica():
    usuario = session.get('usuario')
    return render_template('hipica.html', usuario=usuario)

@app.route('/baloncesto')
def baloncesto():
    usuario = session.get('usuario')
    return render_template('baloncesto.html', usuario=usuario)

@app.route('/tenis')
def tenis():
    usuario = session.get('usuario')
    return render_template('tenis.html', usuario=usuario)

# Ruta para la verificación de usuario al iniciar sesión (POST)


@app.route('/logout')
def logout():
    session.pop('usuario', None)  # Cerrar sesión
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)




