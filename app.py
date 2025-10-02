import json
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import SocketIO, join_room, leave_room, send, disconnect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import functools

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change to a random secret
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERS_FILE = 'users.json'
ROOMS_FILE = 'rooms.json'

# Load users safely
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                data = f.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

# Load rooms safely
def load_rooms():
    if os.path.exists(ROOMS_FILE):
        try:
            with open(ROOMS_FILE, 'r') as f:
                data = f.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}

def save_rooms(rooms):
    with open(ROOMS_FILE, 'w') as f:
        json.dump(rooms, f, indent=2)

users = load_users()
rooms = load_rooms()

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None

def generate_room_code(length=6):
    while True:
        code = ''.join(random.choice(string.ascii_letters) for _ in range(length))
        if code not in rooms:
            return code

def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users:
            # Support old and new formats
            user_data = users[username]
            if isinstance(user_data, dict):
                hashed_pw = user_data.get('password')
            else:
                hashed_pw = user_data  # old string format
            if hashed_pw and check_password_hash(hashed_pw, password):
                login_user(User(username))
                return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users:
            flash('Username already exists')
            return redirect(url_for('signup'))
        users[username] = {'password': generate_password_hash(password)}
        save_users(users)
        login_user(User(username))
        return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room_code = generate_room_code()
    rooms[room_code] = {'members': {}, 'messages': []}  # store messages per user
    save_rooms(rooms)
    session['room'] = room_code
    return redirect(url_for('room'))

@app.route('/join_room', methods=['POST'])
@login_required
def join_room_route():
    room_code = request.form.get('room_code')
    if room_code not in rooms:
        flash('Invalid room code')
        return redirect(url_for('home'))
    session['room'] = room_code
    return redirect(url_for('room'))

@app.route('/room')
@login_required
def room():
    room_code = session.get('room')
    if not room_code or room_code not in rooms:
        return redirect(url_for('home'))
    user_messages = rooms[room_code]['members'].get(current_user.id, [])
    return render_template('room.html', room=room_code, messages=user_messages)

@app.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    room_code = session.get('room')
    if room_code and room_code in rooms:
        rooms[room_code]['members'][current_user.id] = []
        save_rooms(rooms)
    return redirect(url_for('room'))

@socketio.on('connect')
@authenticated_only
def handle_connect(auth=None):
    room = session.get('room')
    if not room or room not in rooms:
        disconnect()
        return
    join_room(room)
    rooms[room]['members'].setdefault(current_user.id, [])
    send({'sender': '', 'message': f"{current_user.id} has entered the chat"}, to=room)

@socketio.on('message')
@authenticated_only
def handle_message(data):
    room = session.get('room')
    if not room or room not in rooms:
        return
    message = {'sender': current_user.id, 'message': data['message']}
    rooms[room]['members'].setdefault(current_user.id, []).append(message)
    rooms[room]['messages'].append(message)  # global messages
    save_rooms(rooms)
    send(message, to=room)

@socketio.on('disconnect')
@authenticated_only
def handle_disconnect():
    room = session.get('room')
    if not room or room not in rooms:
        return
    send({'sender': '', 'message': f"{current_user.id} has left the chat"}, to=room)
    leave_room(room)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
