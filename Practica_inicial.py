import tkinter
import os
import json
import hashlib
from pathlib import Path


JSON_USER_FILE = str(Path.home()) + "/PycharmProjects/Cryptography-project/user.json"
def sign_up():
    inicio.grid_remove()
    registro.grid_remove()
    register()
    
    return 0
def login():
    inicio.grid_remove()
    registro.grid_remove()
    logged()
def encode_password(password_to_encode):
    password_encoded = hashlib.sha256(password_to_encode.encode()).hexdigest()
    return password_encoded
    
    return 0
def guardar_datos(usuario, id_card, date, correo, contraseña):
    try:
        with open(JSON_USER_FILE, 'r', encoding='utf-8', newline="") as l:
            data = json.load(l)
    except FileNotFoundError:
        data = []

    data.append({"user": usuario, "ID": id_card, "birth date": date,"mail":correo, "password":encode_password(contraseña)})

    try:
        with open(JSON_USER_FILE, 'w', encoding='utf-8', newline="") as f:
            json.dump(data, f, indent=2)
    except FileNotFoundError as e:
        print("NO SE PUDO HACER")
        return 0






def prueba_contraseña(usuario, id_card, date, correo, repetir_contraseña, contraseña):
    if encode_password(contraseña) != encode_password(repetir_contraseña):
        print("error")
        return -1
    guardar_datos(usuario, id_card, date, correo, contraseña)
    return 0

def register():
    tkinter.Label(ventana_frame, text="REGISTRO").grid(row=0, column=150)
    tkinter.Label(ventana_frame, text="Nombre").grid(row=2, column=150)
    usuario = tkinter.Entry(ventana_frame, width=20)
    usuario.grid(row=4, column=150)
    tkinter.Label(ventana_frame, text="DNI").grid(row=6, column=150)
    id_card = tkinter.Entry(ventana_frame, width=20)
    id_card.grid(row=8, column=150)
    tkinter.Label(ventana_frame, text="Fecha de nacimiento").grid(row=10, column=150)
    date = tkinter.Entry(ventana_frame, width=20)
    date.grid(row=12, column=150)
    tkinter.Label(ventana_frame, text="Correo").grid(row=14, column=150)
    correo = tkinter.Entry(ventana_frame, width=20)
    correo.grid(row=16, column=150)
    tkinter.Label(ventana_frame, text="Contrseña").grid(row=18, column=150)
    contraseña = tkinter.Entry(ventana_frame, width=20, show="*")
    contraseña.grid(row=20, column=150)
    tkinter.Label(ventana_frame, text="Repita la contrseña").grid(row=22, column=150)
    repetir_contraseña = tkinter.Entry(ventana_frame, width=20, show="*")
    repetir_contraseña.grid(row=24, column=150)

    inicio = tkinter.Button(ventana_frame, text="Registrarse", command=lambda: prueba_contraseña(usuario.get(), id_card.get(), date.get(), correo.get(), repetir_contraseña.get(), contraseña.get()))
    inicio.grid(row=26, column=150)
def logged():
    tkinter.Label(ventana_frame, text="INICIO DE SESION").grid(row=0, column=150)
    tkinter.Label(ventana_frame, text="Correo").grid(row=2, column=150)
    correo = tkinter.Entry(ventana_frame, width=20)
    correo.grid(row=4, column=150)
    tkinter.Label(ventana_frame, text="Contrseña").grid(row=6, column=150)
    contraseña = tkinter.Entry(ventana_frame, width=20)
    contraseña.grid(row=8, column=150)
    
    inicio = tkinter.Button(ventana_frame, text="INICIAR SESION", command=lambda: prueba_inicio_sesion(correo.get()))
    inicio.grid(row=10, column=150)
    
def prueba_inicio_sesion(correo):
    file = get_json_file()
    found = False
    for item in file:
        if item["mail"] == correo:
            found = True
            print("MAIL FOUND")
            print("USER", item["user"], "IDCARD", item["ID"], "BIRTH DATE", item["birth date"], "MAIL", item["mail"])
            break
    if not found:
        print("USER IS NOT REGISTERED")
        register()


    entrada_interfaz()




def entrada_interfaz():

    print("FUNCIONA")
    return 0







def get_json_file():
    try:
        with open(JSON_USER_FILE, 'r', encoding='utf-8', newline="") as l:
            data = json.load(l)
    except FileNotFoundError:
        data = []
    return data





ventana = tkinter.Tk()
ventana.geometry("600x300")


ventana_frame = tkinter.Frame(ventana)
ventana_frame.grid()


registro = tkinter.Button(ventana_frame, text="Registrarse", command=sign_up)
registro.grid(row=0, column=0, padx=10)

inicio = tkinter.Button(ventana_frame, text="Iniciar sesión", command=login)
inicio.grid(row=0, column=1, padx=10)









ventana.mainloop()