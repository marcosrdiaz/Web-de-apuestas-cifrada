import tkinter

def sign_up():
    inicio.grid_remove()
    registro.grid_remove()
    register()
    
    return 0
def login():
    inicio.grid_remove()
    registro.grid_remove()
    logged()
    
    
    return 0

def prueba(pruebv):
    print(pruebv)
    return 0

def register():
    tkinter.Label(ventana_frame, text="REGISTRO").grid(row=0, column=150)
    tkinter.Label(ventana_frame, text="Correo").grid(row=2, column=150)
    usuario = tkinter.Entry(ventana_frame, width=20)
    usuario.grid(row=4, column=150)
    tkinter.Label(ventana_frame, text="Contrseña").grid(row=6, column=150)
    usuario = tkinter.Entry(ventana_frame, width=20)
    usuario.grid(row=8, column=150)
    
    inicio = tkinter.Button(ventana_frame, text="Registrarse", command=lambda: prueba(usuario.get()))
    inicio.grid(row=10, column=150)
def logged():
    tkinter.Label(ventana_frame, text="INICIO DE SESION").grid(row=0, column=150)
    tkinter.Label(ventana_frame, text="Correo").grid(row=2, column=150)
    usuario = tkinter.Entry(ventana_frame, width=20)
    usuario.grid(row=4, column=150)
    tkinter.Label(ventana_frame, text="Contrseña").grid(row=6, column=150)
    usuario = tkinter.Entry(ventana_frame, width=20)
    usuario.grid(row=8, column=150)
    
    inicio = tkinter.Button(ventana_frame, text="INICIAR SESION", command=lambda: prueba(usuario.get()))
    inicio.grid(row=10, column=150)
    
    

ventana = tkinter.Tk()
ventana.geometry("600x300")


ventana_frame = tkinter.Frame(ventana)
ventana_frame.grid()


registro = tkinter.Button(ventana_frame, text="Registrarse", command=sign_up)
registro.grid(row=0, column=0, padx=10)

inicio = tkinter.Button(ventana_frame, text="Iniciar sesión", command=login)
inicio.grid(row=0, column=1, padx=10)









ventana.mainloop()