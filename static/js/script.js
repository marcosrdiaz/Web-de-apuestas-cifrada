document.getElementById('registro-form').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevenir el comportamiento predeterminado del formulario

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    // Enviar datos al backend usando Fetch API
    fetch('/registrar_usuario', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: username,
            email: email,
            password: password
        }),
    })
    .then(response => response.json())
    .then(data => {
        // Mostrar el mensaje recibido en el frontend
        document.getElementById('resultado').textContent = data.message;
    })
    .catch(error => {
        console.error('Error:', error);
    });
});
