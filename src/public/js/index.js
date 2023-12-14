const socketClient = io();
const caja = document.getElementById('caja');
const contenido = document.getElementById('contenido');

let usuario = '';

socketClient.on("addedProduct", (data) => {
    const contenido = document.getElementById('contenido');
    let contenidoFinal = "";
    data.forEach(({title, description, price, code, stock, category, status}) => {
        contenidoFinal += `
            <div id=${code} style="border: 2px solid black; margin-block: 16px; padding-inline: 8px;">
                <p>Producto: ${title}</p>
                <p>Descripcion del producto: ${description}</p>
                <p>Precio: ${price}</p>
                <p>Codigo del producto: ${code}</p>
                <p>Stock: ${stock}</p>
                <p>Categoria: ${category}</p>
                <p>Estado: ${status}</p>
            </div>
        `
    });
    contenido.innerHTML = contenidoFinal;
});

socketClient.on("deletedProduct", (data) => {
    const divToBeEliminated = document.getElementById(data.code);
    divToBeEliminated.remove();
});


caja.addEventListener('change', (e) => {
    socketClient.emit('message', {
    user: usuario,
    message: e.target.value,
  });
});

// Swal.fire({
//   title: 'Ingresa tu correo',
//   input: 'text',
//   inputAttributes: {
//     autocapitalize: 'off',
//   },
//   confirmButtonText: 'Ingresar',
// }).then((result) => {
//   usuario = result.value;
// });

socketClient.on('new_message', (data) => {
  const mensajes = data.map(({ user, message }) => {
    return `<p>${user} dijo: ${message}</p>`;
  });

  contenido.innerHTML = mensajes.join('');
});