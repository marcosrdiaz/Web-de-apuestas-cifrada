# Cryptography-project

***Breve descripción***

Plataforma web para apuestas deportivas que incluye registro seguro, gestión y protección de datos mediante técnicas criptográficas, firma digital y certificados.

***Qué hace el proyecto***

Permite a usuarios registrarse, modificar perfil, hacer apuestas en diversos deportes, y gestionar balance de forma segura. Implementa cifrado AES-GCM para datos sensibles y firma digital RSA para autenticación e integridad.

***Tecnologías usadas***

- Backend: Python Flask

- Criptografía: Scrypt para derivación de contraseñas, AES-GCM para cifrado, RSA para firma digital

- Gestión de claves y certificados con OpenSSL

- JSON para almacenamiento de usuarios y apuestas

***Cómo se ejecuta***
- Ejecutar servidor Flask en entorno Python

- Acceder a la plataforma web para registro e inicio de sesión

- Realizar apuestas y operaciones protegidas mediante firmas y certificados

***Ejemplo de salida o captura***
- Mensajes de confirmación o error en registro y apuestas

- Visualización de apuestas realizadas

- Logs de operaciones criptográficas y verificaciones exitosas de firmas
