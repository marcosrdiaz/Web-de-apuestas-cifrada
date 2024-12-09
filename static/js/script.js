

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
// Function to start the race
function startRace() {
    // Reset the positions of the horses
    horses.forEach(horse => horse.x = 0);
    updateHorsePositions(); // Update positions immediately

    const raceInterval = setInterval(() => {
        horses.forEach(horse => {
            // Move each horse a random distance
            horse.x += Math.random() * 10;
        });

        updateHorsePositions(); // Update positions in each iteration

        // Check if any horse has reached the finish line
        const winner = horses.findIndex(horse => horse.x >= raceDistance);
        if (winner !== -1) {
            clearInterval(raceInterval);
            alert(`Horse ${winner + 1} has won!`);
        }
    }, 100);
}

// Function to update the positions of the horses
function updateHorsePositions() {
    horses.forEach(horse => {
        horse.element.style.left = `${horse.x}px`; // Update the horizontal position (left) in pixels
    });
}

// Assign the click event to the button
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

function enviarApuesta(partido, apuesta, valorApuesta) {
    if (!valorApuesta) {
        alert("Por favor, indica cuánto dinero vas a apostar.");
        return;
    }

    fetch("/guardar_apuesta", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ partido, apuesta, valor_apuesta: valorApuesta })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            mostrarApuestaEnSidebar(partido, apuesta, valorApuesta); // Muestra en la sidebar
        } else {
            alert(data.error || "Hubo un problema al guardar la apuesta.");
        }
    })
    .catch(error => console.error("Error al enviar la apuesta:", error));
}

// Function to display the bet in the sidebar without reloading the page
function mostrarApuestaEnSidebar(partido, apuesta, valorApuesta) {
    const listaApuestas = document.getElementById("selectedBetsList");
    const apuestaItem = document.createElement("li");
    apuestaItem.innerHTML = `${partido}<br>Apuesta: ${apuesta}<br>Valor: ${valorApuesta}€`;
    listaApuestas.appendChild(apuestaItem);
}