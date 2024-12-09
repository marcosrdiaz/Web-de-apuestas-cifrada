from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import re

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import base64
import logging

# Crear una instancia de la aplicación Flask
app = Flask(__name__)
# Definir una clave secreta para la aplicación, utilizada para gestionar las sesiones y proteger los datos
app.secret_key = 'albondigas_yaya'

# Configuración del log para mostrar mensajes
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# Creamos las rutas de los archivos donde vamos a guardar información

# Ruta del archivo JSON donde se guardarán los registros
RUTA_JSON = 'usuarios.json'

# Cargar o crear el archivo JSON si no existe
if not os.path.exists(RUTA_JSON):
    with open(RUTA_JSON, 'w') as f:
        json.dump([], f)

# Ruta del archivo JSON donde se guardarán las apuestas de hipica
RUTA_JSON_HIPICA = 'apuestas_hipica.json'

# Crear o cargar el archivo JSON para las apuestas de hípica
if not os.path.exists(RUTA_JSON_HIPICA):
    with open(RUTA_JSON_HIPICA, 'w') as f:
        json.dump([], f)

# Ruta del archivo JSON donde se guardarán las apuestas de hipica
RUTA_JSON_FUTBOL = 'apuestas_futbol.json'

# Crear o cargar el archivo JSON para las apuestas de hípica
if not os.path.exists(RUTA_JSON_FUTBOL):
    with open(RUTA_JSON_FUTBOL, 'w') as f:
        json.dump([], f)


def leer_usuarios():
    try:
        with open(RUTA_JSON, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.info(f"Error al leer el archivo JSON: {e}")
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
        with open(RUTA_JSON, 'w') as f:
            json.dump(usuarios, f, indent=4)
        logger.info("Usuarios guardados correctamente en el archivo JSON.")
        return True
    except (IOError, TypeError) as e:
        logger.error(f"Error al guardar el archivo JSON: {e}")

# Función para validar el formato de correo electrónico
def validar_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# Función para validar la contraseña (mínimo 8 caracteres, una mayuscula y un caracter especial)
def validar_password(password):
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

def proteger_password(password):
    # creamos un salt aleatorio
    salt = os.urandom(16)
    # creamos un kdf para derivar la contraseña
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    password_token = kdf.derive(password.encode('utf-8'))
    return password_token, salt

# Función para cifrar un mensaje con AES-GCM
def cifrar_aes(texto_plano, clave):
    # Genera un nonce (vector de inicialización) aleatorio
    nonce = get_random_bytes(12)

    # Crea un objeto de cifrado AES en modo GCM
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)

    texto_cifrado, tag = cipher.encrypt_and_digest(texto_plano.encode())
    logger.info(f"Cifrando con AES-GCM. Tamaño de clave {len(clave) * 8} bits ({len(clave)} bytes). Texto_cifrado: "
                f"{texto_cifrado}, nonce: {nonce}, tag: {tag}")
    return texto_cifrado, nonce, tag

# Función para descifrar un mensaje cifrado con AES-GCM
def descifrar_aes(texto_cifrado, nonce, tag, clave):
    # Crea un objeto de descifrado AES en modo GCM con el mismo nonce
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)

    # Descifra el texto cifrado y verifica la integridad con el tag
    try:
        texto_descifrado = cipher.decrypt_and_verify(texto_cifrado, tag)
        logger.info(f"Autenticación exitosa con AES-GCM. Tamaño de clave: {len(clave) * 8} bits ({len(clave)} bytes), "
                    f"Algoritmo: AES-GCM, Texto descifrado: {texto_descifrado}")
        return texto_descifrado.decode()
    except ValueError:
        logger.error("Error: el mensaje ha sido alterado o la clave es incorrecta.")
        return None

def guardar_apuesta_hipica(apuesta):
    try:
        # Leer apuestas previas
        with open(RUTA_JSON_HIPICA, 'r') as f:
            apuestas_hipica = json.load(f)

        # Añadir la nueva apuesta
        apuestas_hipica.append(apuesta)

        # Guardar de vuelta en el archivo JSON
        with open(RUTA_JSON_HIPICA, 'w') as f:
            json.dump(apuestas_hipica, f, indent=4)

        logger.info("Apuesta de hípica guardada correctamente en el archivo JSON.")
        return True

    except (FileNotFoundError, json.JSONDecodeError):
        apuestas_hipica = []
        # Añadir la nueva apuesta
        apuestas_hipica.append(apuesta)

        # Guardar de vuelta en el archivo JSON
        with open(RUTA_JSON_HIPICA, 'w') as f:
            json.dump(apuestas_hipica, f, indent=4)

        logger.info("Apuesta de hípica guardada correctamente en el archivo JSON.")
        return True


def generar_claves():
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serializar las claves en formato PEM
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'pollo123')
   )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_bytes, private_key_bytes

def guardar_claves(email, private_key, public_key):
    # Ensure the 'claves' directory exists
    if not os.path.exists('claves'):
        os.makedirs('claves')

    try:
        # Save the private key
        with open(f'claves/private_key_{email}.pem', 'wb') as f:
            f.write(private_key)
        logger.info(f"Clave privada guardada correctamente para el usuario: {email}")

        # Save the public key
        with open(f'claves/public_key_{email}.pem', 'wb') as f:
            f.write(public_key)
        logger.info(f"Clave pública guardada correctamente para el usuario: {email}")

        return True
    except (IOError, TypeError) as e:
        logger.error(f"Error al guardar las claves: {e}")
        return False

def sign_data(data, email):
   #Deserializar la clave privada
   with open(f'claves/private_key_{email}.pem', "rb") as key_file:
       private_key = serialization.load_pem_private_key(
           key_file.read(),
           password=b'pollo123'
       )
    # Firmar los datos con la clave privada
   signature = private_key.sign(
       data.encode('utf-8'),
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA256()
   )
   guardar_firma(email, signature)
   return True


def guardar_firma(email, signature):
    # Ensure the 'firmas' directory exists
    if not os.path.exists('firmas'):
        os.makedirs('firmas')

    try:
        # Save the signature
        with open(f'firmas/firma_{email}.sig', 'wb') as f:
            f.write(signature)
        logger.info(f"Firma guardada correctamente para el usuario: {email}")
        return True
    except (IOError, TypeError) as e:
        logger.error(f"Error al guardar la firma: {e}")
        return False

def verify_signature(data, email, public_key):

    # Leer la firma
    with open(f'firmas/firma_{email}.sig', "rb") as f:
        signature = f.read()

    # Deserializar la clave pública
    public_key = serialization.load_pem_public_key(
        public_key,
    )
    # Verificar la firma con la clave pública
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logger.info("Firma verificada correctamente.")
        return True
    except:
        return False

def crear_csr(email):
    with open(f'claves/private_key_{email}.pem', "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'pollo123'
        )
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, email),
    ])).sign(key, hashes.SHA256())
    # Guardar el CSR en un archivo
    ruta_csr = f"AC1/solicitudes/{email}_csr_req.pem"
    if not os.path.exists(ruta_csr):
        with open(ruta_csr, 'w') as f:
            json.dump([], f)
    with open(ruta_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return True

def verificar_certificados(email):
    #Obtenemos el certificado del usuario
    try:
        with open(f'A/{email}_cert.pem', "rb") as f:
            certificado = f.read()

        certificado_usuario = x509.load_pem_x509_certificate(certificado)
    except FileNotFoundError as e:
        logger.error(f"Error al cargar el certificado del usuario: {e}")
        return False

    #Obtenemos el certificado de la AC a verificar (AC1)
    with open(f'A/ac1cert.pem', "rb") as f:
        certificado = f.read()

    certificado_ac_ver = x509.load_pem_x509_certificate(certificado)

    #Obtenemos el certificado de la AC (AC1)
    with open(f'AC1/ac1cert.pem', "rb") as f:
        certificado = f.read()

    certificado_ac = x509.load_pem_x509_certificate(certificado)

    #Obtenemos la clave pública de la AC (AC1)
    ac_public_key = certificado_ac.public_key()

    #Verificamos el certificado del usuario con la clave pública de la AC
    ac_public_key.verify(
        certificado_usuario.signature,
        certificado_usuario.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificado_usuario.signature_hash_algorithm,
    )

    #Verificamos el certificado de la AC con la clave pública de la AC
    ac_public_key.verify(
        certificado_ac_ver.signature,
        certificado_ac.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificado_ac.signature_hash_algorithm,
    )
    return True

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
        if not validar_password(password):
            return jsonify({'message': 'La contraseña debe tener al menos 8 caracteres'}), 400

        # Protegemos la contraseña
        password_token, salt = proteger_password(password)

        balance_inicial = "0"

        # Cifrar el balance usando AES-GCM con la clave única (estamos usando la contraseña como clave aes)
        balance_cifrado, nonce, tag = cifrar_aes(balance_inicial, password_token)

        #Generamos la clave publica y privada del usuario
        public_key_bytes, private_key_bytes = generar_claves()
        guardar_claves(email, private_key_bytes, public_key_bytes)

        # Crear el mensaje de política de privacidad y confirmación de edad
        mensaje = "I agree to the Privacy Policy and confirm that I am over 18 years old."

        # Firmar el mensaje con la clave privada del usuario
        sign_data(mensaje, email)

        # Crear un CSR con la firma
        crear_csr(email)

        #Verificamos la firma
        verify_signature(mensaje, email, public_key_bytes)

        # Guardamos en base 64 para mayor seguridad
        nuevo_usuario = {
            'username': username,
            'email': email,
            'password': base64.b64encode(password_token).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'balance': base64.b64encode(balance_cifrado).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
        }

        # Guardar el nuevo usuario en el archivo JSON
        if guardar_usuario(nuevo_usuario):
            logger.info(f"Nuevo usuario registrado: {username}, {email}")
            return redirect(url_for('login'))
        else:
            return jsonify({'message': 'El nombre de usuario o correo electrónico ya existen'}), 400

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
        usuario = None

        # Buscar al usuario en la lista utilizando un bucle for
        for usuario in usuarios:
            if usuario['email'] == email:
                usuario = usuario
                break

        if usuario:
            # Decodificar el salt almacenado desde Base64
            salt = base64.b64decode(usuario['salt'])

            # Derivar la clave usando la contraseña ingresada y el salt almacenado
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2 ** 14,
                r=8,
                p=1
            )
            password_token_intentada = kdf.derive(password.encode('utf-8'))

            # Convertir la clave derivada a Base64 para comparación
            password_token_b64 = base64.b64encode(password_token_intentada).decode('utf-8')

            # Comparar las claves derivadas
            if password_token_b64 == usuario['password']:
                session['usuario'] = {
                    'username': usuario['username'],
                    'email': usuario['email'],
                    'balance': usuario['balance']  # Incluir el balance
                }
                return redirect(url_for('index'))
            else:
                return jsonify({'message': 'Credenciales incorrectas'}), 401
        else:
            return jsonify({'message': 'Credenciales incorrectas'}), 401

    return render_template('login.html')
@app.route('/perfil')
def perfil():
    # Verificar si el usuario está en la sesión
    if 'usuario' in session:
        # Leer usuarios desde el archivo JSON
        usuarios = leer_usuarios()

        # Buscar el usuario en la lista de usuarios
        usuario_email = session['usuario']['email']
        for usuario in usuarios:
            if usuario['email'] == usuario_email:

                # Actualizar la sesión con el balance del usuario desde el archivo JSON
                # Como esta guardado en base 64 lo pasamos de vuelta a bytes
                session['usuario']['balance'] = descifrar_aes(base64.b64decode(usuario['balance']),
                                                              base64.b64decode(usuario['nonce']),
                                                              base64.b64decode(usuario['tag']),
                                                              base64.b64decode(usuario['password']))

                logger.info(f"Datos de la sesión que se pasan a la plantilla (descifrado solo en la sesion temporal "
                            f"porque imprime el balance en el perfil): {session['usuario']}")

                # Renderizar la plantilla con los datos del usuario
                return render_template('perfil.html', usuario=session['usuario'])

    # Si no hay usuario en la sesión, redirigir a la página de inicio de sesión
    return redirect(url_for('login'))

# Ruta para modificar el balance
@app.route('/modificar_balance', methods=["POST"])
def modificar_balance():
    if 'usuario' in session:
        accion = request.form.get('accion')  # Obtener la acción: 'añadir' o 'retirar'
        cantidad = float(request.form.get('cantidad'))  # Obtener la cantidad del formulario

        # Leer usuarios desde el archivo JSON
        usuarios = leer_usuarios()
        usuario_email = session['usuario']['email']  # Identificar al usuario en sesión

        # Actualizar el balance según la acción y el usuario en sesión
        for usuario in usuarios:

            if usuario['email'] == usuario_email:
                balance = descifrar_aes(base64.b64decode(usuario['balance']), base64.b64decode(usuario['nonce']),
                                        base64.b64decode(usuario['tag']), base64.b64decode(usuario['password']))
                balance = float(balance)
                if accion == 'añadir':  # Si la acción es añadir
                    balance += cantidad
                    balance = str(balance)
                    balance_cifrado, nonce, tag = cifrar_aes(balance, base64.b64decode(usuario['password']))
                    usuario['balance'] = base64.b64encode(balance_cifrado).decode('utf-8')
                    usuario['tag'] = base64.b64encode(tag).decode('utf-8')
                    usuario['nonce'] = base64.b64encode(nonce).decode('utf-8')
                elif accion == 'retirar':  # Si la acción es retirar
                    if balance >= cantidad:  # Verificar que haya suficiente saldo
                        balance -= cantidad
                        balance = str(balance)
                        balance_cifrado, nonce, tag = cifrar_aes(balance, base64.b64decode(usuario['password']))
                        usuario['balance'] = base64.b64encode(balance_cifrado).decode('utf-8')
                        usuario['tag'] = base64.b64encode(tag).decode('utf-8')
                        usuario['nonce'] = base64.b64encode(nonce).decode('utf-8')
                    else:
                        return jsonify({'message': 'Fondos insuficientes'}), 400
                session['usuario']['balance'] = balance
                break

        # Guardar cambios en el archivo JSON
        with open(RUTA_JSON, 'w') as f:
            json.dump(usuarios, f, indent=4)

        logger.info(f"Datos de la sesión que se pasan a la plantilla: {session['usuario']}")
        # Redirigir a la página de perfil con el balance actualizado
        return redirect(url_for('perfil'))

    return redirect(url_for('login'))

# Ruta para actualizar los datos del usuario
@app.route('/actualizar_datos', methods=["POST"])
def actualizar_datos():
    if 'usuario' in session:
        nuevo_email = request.form.get('nuevo_email')
        nuevo_username = request.form.get('nuevo_username')

        # Verificar que se han proporcionado datos
        if not nuevo_email or not nuevo_username:
            logger.error("Intento de actualización fallido: campos vacíos.")
            return redirect(url_for('perfil'))  # Regresar a la página de perfil

        # Leer usuarios desde el archivo JSON
        usuarios = leer_usuarios()
        usuario_email = session['usuario']['email']

        # Actualizar datos del usuario
        usuario_encontrado = False  # Variable para verificar si se encontró el usuario
        for usuario in usuarios:
            if usuario['email'] == usuario_email:
                usuario['email'] = nuevo_email
                usuario['username'] = nuevo_username
                usuario_encontrado = True
                logger.info(f"Datos actualizados para el usuario: {usuario['username']}, nuevo email: {nuevo_email}")
                break

        if usuario_encontrado:
            # Guardar cambios en el archivo JSON
            guardar_usuario(usuarios)

            # Actualizar datos en la sesión
            session['usuario']['email'] = nuevo_email
            session['usuario']['username'] = nuevo_username
            logger.info(f"Datos de usuario actualizados en la sesión. Usuario: {session['usuario']}")
        else:
            logger.error("No se pudo encontrar el usuario para actualizar.")

            # Guardar cambios en el archivo JSON
        with open(RUTA_JSON, 'w') as f:
            json.dump(usuarios, f, indent=4)

        return redirect(url_for('perfil'))  # Regresar a la página de perfil

    logger.warning("Intento de actualización de datos sin sesión de usuario.")
    return redirect(url_for('login'))

@app.route('/futbol')
def futbol():
    usuario = session.get('usuario')  # Obtener al usuario de la sesión si está autenticado
    #crear_perfil_usuario()
    return render_template('futbol.html', usuario=usuario)

# Ruta para guardar una apuesta cifrada
@app.route("/guardar_apuesta", methods=["POST"])
def guardar_apuesta():
    if 'usuario' not in session:
        return jsonify({"error": "Debes iniciar sesión para hacer una apuesta."}), 401

    data = request.get_json()

    partido = data.get("partido")
    apuesta = data.get("apuesta")
    valor_apuesta_str = data.get("valor_apuesta")

    if not partido or not apuesta or not valor_apuesta_str:
        return jsonify({"success": False, "error": "Datos incompletos"}), 400

    try:
        valor_apuesta = float(valor_apuesta_str)
        logger.info("Hecho")# Convertir el valor de la apuesta a float
    except ValueError:
        return jsonify({"success": False, "error": "Valor de apuesta inválido"}), 400

    # Leer usuarios desde el archivo JSON
    usuarios = leer_usuarios()
    usuario_email = session['usuario']['email']  # Identificar al usuario en sesión

    for usuario in usuarios:
        if usuario['email'] == usuario_email:
            # Descifrar el balance del usuario
            balance = descifrar_aes(base64.b64decode(usuario['balance']), base64.b64decode(usuario['nonce']),
                                    base64.b64decode(usuario['tag']), base64.b64decode(usuario['password']))
            balance = float(balance)
            logger.info(f"Balance del usuario: {balance}")

            # Verificar si el balance es suficiente para la apuesta
            if balance < valor_apuesta:
                return jsonify({"success": False, "error": "Fondos insuficientes. Por favor, añade más balance."}), 400

            # Preparar el texto de la apuesta para cifrarlo
            texto_apuesta = f"Partido: {partido} - Apuesta: {apuesta} - Valor: {valor_apuesta}"

            # Cifrar la apuesta
            apuesta_cifrada, nonce_apuesta, tag_apuesta = cifrar_aes(texto_apuesta, base64.b64decode(usuario['password']))

            # Guardar la apuesta cifrada en la sesión o base de datos
            if "apuestas" not in session:
                session["apuestas"] = []
            session["apuestas"].append(apuesta_cifrada)

            # Intentar leer el archivo JSON y manejar posibles errores
            try:
                with open(RUTA_JSON_FUTBOL, "r") as file:
                    apuestas_data = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError):
                apuestas_data = []

            # Agregar la nueva apuesta al archivo
            nueva_apuesta = {
                "email": usuario_email,
                "apuesta": base64.b64encode(apuesta_cifrada).decode('utf-8'),
                "nonce": base64.b64encode(nonce_apuesta).decode('utf-8'),
                "tag": base64.b64encode(tag_apuesta).decode('utf-8')
            }
            apuestas_data.append(nueva_apuesta)

            # Guardar las apuestas actualizadas en el archivo JSON
            with open(RUTA_JSON_FUTBOL, "w") as file:
                json.dump(apuestas_data, file, indent=4)

            # Modificar el balance del usuario
            balance -= valor_apuesta
            balance = str(balance)
            balance_cifrado, nonce, tag = cifrar_aes(balance, base64.b64decode(usuario['password']))
            usuario['balance'] = base64.b64encode(balance_cifrado).decode('utf-8')
            usuario['tag'] = base64.b64encode(tag).decode('utf-8')
            usuario['nonce'] = base64.b64encode(nonce).decode('utf-8')

            # Guardar cambios en el archivo JSON
            with open(RUTA_JSON, 'w') as f:
                json.dump(usuarios, f, indent=4)

            session['usuario']['balance'] = balance

            return jsonify({"success": True, "message": "Apuesta guardada exitosamente"})

    return jsonify({"success": False, "error": "Error al guardar la apuesta"}), 500
@app.route('/modificar_balance_apuesta', methods=["POST"])
def modificar_balance_apuesta():
    if 'usuario' in session:
        data = request.get_json()
        partido = data.get("partido")
        apuesta = data.get("apuesta")
        valor_apuesta = float(data.get("valor_apuesta"))  # Obtener el valor de la apuesta

        # Leer usuarios desde el archivo JSON
        usuarios = leer_usuarios()
        usuario_email = session['usuario']['email']  # Identificar al usuario en sesión

        # Actualizar el balance según la apuesta y el usuario en sesión
        for usuario in usuarios:
            if usuario['email'] == usuario_email:
                balance = descifrar_aes(base64.b64decode(usuario['balance']), base64.b64decode(usuario['nonce']),
                                        base64.b64decode(usuario['tag']), base64.b64decode(usuario['password']))
                balance = float(balance)

                # Restar el valor de la apuesta del balance
                if balance >= valor_apuesta:  # Verificar que haya suficiente saldo
                    balance -= valor_apuesta
                    balance = str(balance)
                    balance_cifrado, nonce, tag = cifrar_aes(balance, base64.b64decode(usuario['password']))
                    usuario['balance'] = base64.b64encode(balance_cifrado).decode('utf-8')
                    usuario['tag'] = base64.b64encode(tag).decode('utf-8')
                    usuario['nonce'] = base64.b64encode(nonce).decode('utf-8')
                else:
                    return jsonify({'message': 'Fondos insuficientes'}), 400

                session['usuario']['balance'] = balance
                break

        # Guardar cambios en el archivo JSON
        with open(RUTA_JSON, 'w') as f:
            json.dump(usuarios, f, indent=4)

        logger.info(f"Datos de la sesión que se pasan a la plantilla: {session['usuario']}")
        return jsonify({"success": True, "message": "Balance actualizado exitosamente"})

    return jsonify({"error": "Debes iniciar sesión para modificar el balance."}), 401

@app.route('/hipica')
def hipica():
    usuario = session.get('usuario')
    return render_template('hipica.html', usuario=usuario)

@app.route('/apostar_hipica', methods=["POST"])
def apostar_hipica():
    if 'usuario' in session:
        horse_number = request.form.get('horseNumber')  # Recoger el valor de horseNumber
        if not horse_number:
            return jsonify({'message': 'Número del caballo no proporcionado'}), 400
            # Leer usuarios desde el archivo JSON

        usuarios = leer_usuarios()
        usuario_email = session['usuario']['email']  # Identificar al usuario en sesión

        # Actualizar el balance según la acción y el usuario en sesión
        for usuario in usuarios:

            if usuario['email'] == usuario_email:
                try:
                    # Cifrar el número del caballo elegido
                    texto_cifrado, nonce, tag = cifrar_aes(horse_number, base64.b64decode(usuario['password']))
                except KeyError as e:
                    # Manejo del error si alguna clave falta
                    return jsonify({'message': f'Error en la clave de encriptación: {str(e)}'}), 500
                # Convertir datos a base64 para almacenarlos en JSON
                apuesta_cifrada = {
                    'email': session['usuario']['email'],
                    'horse_number_cifrado': base64.b64encode(texto_cifrado).decode('utf-8'),
                    'nonce': base64.b64encode(nonce).decode('utf-8'),
                    'tag': base64.b64encode(tag).decode('utf-8'),
                }

                # Guardar apuesta en el archivo JSON
                if guardar_apuesta_hipica(apuesta_cifrada):
                    logger.info(f"Apuesta de hípica realizada por el usuario: {session['usuario']['username']}")
                    return ('', 204)
                else:
                    return jsonify({'message': 'Error al registrar la apuesta'}), 500
    else:
        return redirect(url_for('login'))

@app.route('/baloncesto')
def baloncesto():
    usuario = session.get('usuario')
    return render_template('baloncesto.html', usuario=usuario)

@app.route('/tenis')
def tenis():
    usuario = session.get('usuario')
    return render_template('tenis.html', usuario=usuario)

@app.route('/logout')
def logout():
    session.pop('usuario', None)  # Cerrar sesión
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)