
const canvas = document.getElementById('raceCanvas');
const ctx = canvas.getContext('2d');

// Variables del juego
const horses = [
    { x: 0, color: 'red' },
    { x: 0, color: 'blue' },
    { x: 0, color: 'green' }
];

const raceDistance = canvas.width - 50; // Distancia de la carrera

// Función para dibujar los caballos
function drawHorses() {
    ctx.clearRect(0, 0, canvas.width, canvas.height); // Limpiar canvas
    horses.forEach((horse, index) => {
        ctx.fillStyle = horse.color;
        ctx.fillRect(horse.x, index * 80 + 30, 40, 40); // Dibujar caballo
    });
}

// Función para iniciar la carrera
function startRace() {
    const horseNumber = parseInt(document.getElementById('horseNumber').value);
    if (isNaN(horseNumber) || horseNumber < 1 || horseNumber > 3) {
        alert('Por favor, ingresa un número de caballo válido (1-3)');
        return;
    }

    horses.forEach(horse => horse.x = 0); // Reiniciar posición de los caballos
    drawHorses(); // Dibujar caballos al inicio

    const raceInterval = setInterval(() => {
        horses.forEach(horse => {
            // Mover cada caballo una distancia aleatoria
            horse.x += Math.random() * 10;
        });

        drawHorses(); // Redibujar caballos

        // Verificar si algún caballo ha llegado a la meta
        const winner = horses.findIndex(horse => horse.x >= raceDistance);
        if (winner !== -1) {
            clearInterval(raceInterval);
            alert(`¡Caballo ${winner + 1} ha ganado!`);
        }
    }, 100);
}

// Asignar el evento de click al botón
document.getElementById('startRace').addEventListener('click', startRace);


function login(user) {
            // Ocultar botones de inicio de sesión y registro
            document.getElementById('login-btn').style.display = 'none';
            document.getElementById('register-btn').style.display = 'none';

            // Mostrar información del usuario
            document.getElementById('user-info').style.display = 'block';
            document.getElementById('user-name').textContent = `Bienvenido, ${user}`;
        }

        function logout() {
            // Mostrar botones de inicio de sesión y registro
            document.getElementById('login-btn').style.display = 'inline';
            document.getElementById('register-btn').style.display = 'inline';

            // Ocultar información del usuario
            document.getElementById('user-info').style.display = 'none';
        }

        // Simulamos el inicio de sesión con un clic
        document.getElementById('login-btn').addEventListener('click', function(event) {
            event.preventDefault();
            login('Usuario123'); // Aquí se pondría el nombre del usuario
        });

        // Cerrar sesión
        document.getElementById('logout-btn').addEventListener('click', function(event) {
            event.preventDefault();
            logout();
        });






