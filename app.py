from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import re


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




