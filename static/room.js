document.addEventListener('DOMContentLoaded', function() {
    const socket = io(); // Use SocketIO client
    const messagesDiv = document.getElementById('messages');
    const messageInput = document.getElementById('message'); // Corrected ID
    const messageForm = document.getElementById('message-form');

    socket.on('connect', function() {
        console.log('SocketIO connection established');
    });

    socket.on('message', function(data) {
        const p = document.createElement('p');
        p.innerHTML = `<strong>${data.sender}:</strong> ${data.message}`;
        messagesDiv.appendChild(p);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    });

    socket.on('disconnect', function() {
        console.log('SocketIO connection closed');
    });

    socket.on('clear_messages', function() {
        messagesDiv.innerHTML = '';
    });

    // Handle room expiry redirect
    socket.on('room_expired_redirect', function(data) {
        window.location.href = data.redirect_url;
    });

    messageForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            socket.emit('message', { message: message }); // Emit message event
            messageInput.value = '';
        }
    });
});