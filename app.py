from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import re

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

import base64
import logging

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'
# Ruta del archivo JSON donde se guardarán los registros
RUTA_JSON = 'usuarios.json'

# Cargar o crear el archivo JSON si no existe
if not os.path.exists(RUTA_JSON):
    with open(RUTA_JSON, 'w') as f:
        json.dump([], f)


def leer_usuarios():
    try:
        with open(RUTA_JSON, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al leer el archivo JSON: {e}")
        return []


# Función para guardar un nuevo usuario en el archivo JSON
def guardar_usuario(nuevo_usuario):
    try:
        usuarios = leer_usuarios()

        # Verificar si el nombre de usuario o el correo ya existen
        for usuario in usuarios:
            if usuario['username'] == nuevo_usuario['username'] or usuario['email'] == nuevo_usuario['email']:
                return False

        usuarios.append(nuevo_usuario)

        # Guardar el nuevo arreglo de usuarios en formato JSON legible
        with open(RUTA_JSON, 'w') as f:
            json.dump(usuarios, f, indent=4)
        return True
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al escribir el archivo JSON: {e}")
        return False

# Función para validar el formato de correo electrónico
def validar_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# Función para validar la contraseña (mínimo 8 caracteres, una mayuscula y un caracter especial)
def validar_contraseña(password):
    # Verificar longitud
    if len(password) < 8:
        return False

    # Verificar que tenga al menos una mayúscula
    if not re.search(r'[A-Z]', password):
        return False

    # Verificar que tenga al menos un carácter especial (usamos \W para buscar no alfanuméricos)
    if not re.search(r'[\W_]', password):  # \W coincide con cualquier cosa que no sea letra, número o guión bajo
        return False

    # Si pasa todas las condiciones, la contraseña es válida
    return True


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





# Función para generar HMAC usando Crypto
def generar_hmac(mensaje, clave):
    # Crear un objeto HMAC con la clave secreta y el algoritmo SHA-256
    hmac_obj = HMAC.new(clave, digestmod=SHA256)
    hmac_obj.update(mensaje.encode())

    # Generar el HMAC
    hmac_digest = hmac_obj.digest()

    # Devolver el HMAC en formato base64 para que sea legible
    return base64.b64encode(hmac_digest).decode()

# Función para verificar HMAC usando Crypto
def verificar_hmac(mensaje, clave, hmac_proporcionado):
    try:
        # Crear el objeto HMAC nuevamente para verificar
        hmac_obj = HMAC.new(clave, digestmod=SHA256)
        hmac_obj.update(mensaje.encode())

        # Decodificar el HMAC proporcionado de base64
        hmac_proporcionado_bytes = base64.b64decode(hmac_proporcionado)

        # Verificar si el HMAC coincide
        hmac_obj.verify(hmac_proporcionado_bytes)

        logger.info("HMAC válido. El mensaje no ha sido alterado.")
        return True
    except ValueError:
        logger.error("HMAC no válido. El mensaje ha sido alterado o la clave es incorrecta.")
        return False





# Función para generar un par de claves RSA (privada y pública)
def generar_claves_rsa_firma():
    clave_privada = RSA.generate(2048)
    clave_publica = clave_privada.publickey()
    return clave_privada, clave_publica

# Función para firmar un mensaje con la clave privada
def firmar_mensaje(mensaje, clave_privada):
    # Crear un hash SHA-256 del mensaje
    hash_mensaje = SHA256.new(mensaje.encode())

    # Firmar el hash del mensaje con la clave privada
    firma = pkcs1_15.new(clave_privada).sign(hash_mensaje)

    # Devolver la firma en formato base64 para legibilidad
    return base64.b64encode(firma).decode()

# Función para verificar la firma con la clave pública
def verificar_firma(mensaje, firma_base64, clave_publica):
    # Crear un hash SHA-256 del mensaje
    hash_mensaje = SHA256.new(mensaje.encode())

    # Decodificar la firma desde base64
    firma = base64.b64decode(firma_base64)

    # Verificar la firma con la clave pública
    try:
        pkcs1_15.new(clave_publica).verify(hash_mensaje, firma)
        logger.info("La firma es válida. El mensaje no ha sido alterado.")
        return True
    except (ValueError, TypeError):
        logger.error("La firma no es válida. El mensaje ha sido alterado o la firma es incorrecta.")
        return False





# Función para generar un par de claves RSA
def generar_claves_rsa_certificado():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

# Función para crear un certificado autofirmado para la AC raíz
def crear_certificado_autofirmado(nombre_ac, clave_privada):
    nombre = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nombre_ac),
    ])

    # Obtener la clave pública de la clave privada
    clave_publica = clave_privada.public_key()

    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)  # Autofirmado, así que el sujeto es igual al emisor
        .public_key(clave_publica)  # Aquí usamos la clave pública
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Certificado válido por 1 año
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(clave_privada, hashes.SHA256(), default_backend())
    )

    return certificado

# Función para crear un certificado para un usuario firmado por la AC
def crear_certificado_usuario(nombre_usuario, clave_publica_usuario, clave_privada_ac, certificado_ac):
    nombre = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nombre_usuario),
    ])

    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(certificado_ac.subject)  # La AC es la que firma el certificado
        .public_key(clave_publica_usuario)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Certificado válido por 1 año
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(clave_privada_ac, hashes.SHA256(), default_backend())
    )

    return certificado

# Función para guardar certificados y claves en archivos PEM
def guardar_certificado_y_claves(nombre_archivo, certificado, clave_privada):
    # Guardar certificado
    with open(f"{nombre_archivo}_cert.pem", "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))

    # Guardar clave privada
    with open(f"{nombre_archivo}_key.pem", "wb") as f:
        f.write(
            clave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )



'''PRUEBAS DE LOS CIFRADOS'''


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





# Clave secreta (debe ser compartida entre emisor y receptor)
clave_secreta = b'secret_key_very_secure'

# Mensaje a autenticar
mensaje = "Este es un mensaje importante."

# Generar el HMAC para el mensaje
hmac_generado = generar_hmac(mensaje, clave_secreta)
logger.info(f"HMAC generado (base64): {hmac_generado}")

# Verificar el HMAC generado (en una simulación de que es recibido correctamente)
es_valido = verificar_hmac(mensaje, clave_secreta, hmac_generado)




# Generar un par de claves RSA
clave_privada, clave_publica = generar_claves_rsa_firma()

# Mensaje a firmar
mensaje = "Este es un mensaje confidencial."

# Firmar el mensaje
firma_digital = firmar_mensaje(mensaje, clave_privada)
logger.info(f"Firma digital generada (base64): {firma_digital}")

# Verificar la firma
es_valida = verificar_firma(mensaje, firma_digital, clave_publica)




# Crear la AC raíz y su certificado autofirmado
nombre_ac_raiz = "AC_Raiz_Segura"
clave_privada_ac, _ = generar_claves_rsa_certificado()
certificado_ac = crear_certificado_autofirmado(nombre_ac_raiz, clave_privada_ac)

logger.info(f"Certificado autofirmado de la AC raíz '{nombre_ac_raiz}' creado.")
guardar_certificado_y_claves("ac_raiz", certificado_ac, clave_privada_ac)

# Crear un certificado para un usuario firmado por la AC raíz
nombre_usuario = "Usuario_1"
clave_privada_usuario, clave_publica_usuario = generar_claves_rsa_certificado()
certificado_usuario = crear_certificado_usuario(nombre_usuario, clave_publica_usuario, clave_privada_ac, certificado_ac)

logger.info(f"Certificado del usuario '{nombre_usuario}' creado y firmado por la AC raíz.")
guardar_certificado_y_claves("usuario_1", certificado_usuario, clave_privada_usuario)






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




