

const canvas = document.getElementById('raceCanvas');
const ctx = canvas.getContext('2d');

// Obtenemos los elementos de las imágenes de los caballos
const horse1 = document.getElementById('horse1');
const horse2 = document.getElementById('horse2');
const horse3 = document.getElementById('horse3');

// Definimos las posiciones iniciales
const horses = [
    { x: 0, element: horse1 },
    { x: 0, element: horse2 },
    { x: 0, element: horse3 }
];

const raceDistance = canvas.width - 100; // Distancia de la carrera

// Función para iniciar la carrera
function startRace() {
    const horseNumber = parseInt(document.getElementById('horseNumber').value);
    if (isNaN(horseNumber) || horseNumber < 1 || horseNumber > 3) {
        alert('Por favor, ingresa un número de caballo válido (1-3)');
        return;
    }

    // Reiniciar la posición de los caballos
    horses.forEach(horse => horse.x = 0);
    updateHorsePositions(); // Actualizar las posiciones inmediatamente

    const raceInterval = setInterval(() => {
        horses.forEach(horse => {
            // Mover cada caballo una distancia aleatoria
            horse.x += Math.random() * 10;
        });

        updateHorsePositions(); // Actualizar las posiciones en cada iteración

        // Verificar si algún caballo ha llegado a la meta
        const winner = horses.findIndex(horse => horse.x >= raceDistance);
        if (winner !== -1) {
            clearInterval(raceInterval);
            alert(`¡Caballo ${winner + 1} ha ganado!`);
        }
    }, 100);
}

// Función para actualizar las posiciones de los caballos
function updateHorsePositions() {
    horses.forEach(horse => {
        horse.element.style.left = `${horse.x}px`; // Actualizar la posición horizontal (left) en píxeles
    });
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





// Variables para almacenar apuestas seleccionadas
const selectedBets = [];

// Función para manejar el clic en una opción de apuesta
function handleBetOptionClick(event) {
    const bet = event.target.getAttribute('data-bet');
    console.log("Opción de apuesta seleccionada:", bet);  // Log para verificar la apuesta seleccionada

    if (selectedBets.includes(bet)) {
        alert("Ya has seleccionado esta apuesta.");
        console.log("Apuesta duplicada: ya seleccionada antes.");  // Log para apuestas duplicadas
        return;
    }

    selectedBets.push(bet);
    console.log("Apuestas seleccionadas hasta ahora:", selectedBets);  // Log para mostrar las apuestas seleccionadas

    updateSelectedBetsDisplay();
}


// Función para actualizar la lista de apuestas seleccionadas en la interfaz
function updateSelectedBetsDisplay() {
    const selectedBetsList = document.getElementById('selectedBetsList');
    selectedBetsList.innerHTML = ''; // Limpiar la lista actual
    console.log("Actualizando visualización de apuestas seleccionadas");  // Log para seguimiento de actualización

    if (selectedBets.length === 0) {
        selectedBetsList.innerHTML = '<li>No has seleccionado ninguna apuesta aún.</li>';
        console.log("No hay apuestas seleccionadas para mostrar.");  // Log cuando no hay apuestas
    } else {
        selectedBets.forEach(bet => {
            const listItem = document.createElement('li');
            listItem.textContent = bet;
            selectedBetsList.appendChild(listItem);
        });
        console.log("Apuestas mostradas en la lista:", selectedBets);  // Log para verificar la lista actualizada
    }
}


// Agregar eventos a los botones de apuesta
document.querySelectorAll('.bet-option').forEach(button => {
    console.log("Asignando evento a botón:", button.getAttribute('data-bet'));  // Log para verificar qué botón está recibiendo el evento
    button.addEventListener('click', handleBetOptionClick);
});
