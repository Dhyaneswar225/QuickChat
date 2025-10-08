import os
import json
import time
import random
import string
import functools
import threading
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_socketio import SocketIO, join_room, leave_room, send, emit, disconnect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ------------------- Logging Setup -------------------
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ------------------- Load environment variables -------------------
load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
MESSAGE_KEY = os.environ.get("CHAT_SECRET_KEY")
if not MESSAGE_KEY:
    logger.error("CHAT_SECRET_KEY not set in .env")
    raise ValueError("Set CHAT_SECRET_KEY environment variable in .env")

# ------------------- App Setup -------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
# Configure necessary settings for URL generation outside request context
app.config['SERVER_NAME'] = 'localhost:5000'  # Match your development server
app.config['APPLICATION_ROOT'] = '/'
app.config['PREFERRED_URL_SCHEME'] = 'http'  # Use 'https' in production
socketio = SocketIO(app, async_mode="threading", logger=True, engineio_logger=True)

# ------------------- Rate Limiter -------------------
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

# ------------------- Login Manager -------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERS_FILE = 'users.json'
ROOMS_FILE = 'rooms.json'

fernet = Fernet(MESSAGE_KEY.encode())

# ------------------- Security Headers -------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws://localhost:5000;"
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# ------------------- Helper Functions -------------------
def load_users():
    logger.debug("Loading users from %s", USERS_FILE)
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                data = f.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except Exception as e:
            logger.error(f"Error loading users: {e}")
            return {}
    return {}

def save_users(users):
    logger.debug("Saving users to %s", USERS_FILE)
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving users: {e}")

def load_rooms():
    logger.debug("Loading rooms from %s", ROOMS_FILE)
    if os.path.exists(ROOMS_FILE):
        try:
            with open(ROOMS_FILE, 'r') as f:
                data = f.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except Exception as e:
            logger.error(f"Error loading rooms: {e}")
            return {}
    return {}

def save_rooms(rooms):
    logger.debug("Saving rooms to %s", ROOMS_FILE)
    try:
        with open(ROOMS_FILE, 'w') as f:
            json.dump(rooms, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving rooms: {e}")

users = load_users()
rooms = load_rooms()

def generate_room_code(length=6):
    code = ''.join(random.choice(string.ascii_letters) for _ in range(length))
    while code in rooms:
        code = ''.join(random.choice(string.ascii_letters) for _ in range(length))
    return code

def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            logger.debug("Disconnecting unauthenticated user")
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

def cleanup_expired_rooms():
    logger.debug("Starting cleanup_expired_rooms thread")
    with app.app_context():  # Ensure application context is available
        while True:
            try:
                now = datetime.now(timezone.utc)
                rooms_changed = False
                expired_rooms = []
                for room_code in list(rooms.keys()):
                    expiry_str = rooms[room_code].get('expiry')
                    if expiry_str:
                        expiry_time = datetime.fromisoformat(expiry_str)
                        if now >= expiry_time:
                            logger.debug(f"Clearing and expiring room: {room_code}")
                            rooms[room_code]['messages'] = []
                            rooms[room_code]['members'] = {}
                            rooms_changed = True
                            socketio.emit('clear_messages', to=room_code)
                            socketio.emit('room_expired_redirect', {'redirect_url': url_for('home')}, to=room_code)
                            expired_rooms.append(room_code)
                            del rooms[room_code]
                if rooms_changed:
                    save_rooms(rooms)
                    for room_code in expired_rooms:
                        logger.debug(f"Emitting room_expired for {room_code}")
                        socketio.emit('room_expired', {'room': room_code}, to=room_code)
            except Exception as e:
                logger.error(f"Error in cleanup_expired_rooms: {e}")
            time.sleep(60)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# ------------------- Routes -------------------
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/x-icon')

@app.route('/')
@login_required
def home():
    logger.debug("Accessing home page for user: %s", current_user.id)
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    logger.debug("Accessing login route, method: %s", request.method)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logger.debug("Login attempt for username: %s", username)
        if username in users:
            user_data = users[username]
            hashed_pw = user_data.get('password') if isinstance(user_data, dict) else user_data
            if hashed_pw and check_password_hash(hashed_pw, password):
                login_user(User(username))
                next_page = request.args.get('next')
                if not next_page or not is_safe_url(next_page):
                    next_page = url_for('home')
                logger.debug("Login successful, redirecting to: %s", next_page)
                return redirect(next_page)
        flash('Invalid username or password')
        logger.debug("Login failed for username: %s", username)
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    logger.debug("Accessing signup route, method: %s", request.method)
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        logger.debug("Signup attempt for username: %s, email: %s", username, email)

        if not email.endswith('@gmail.com'):
            flash('Please use a valid Gmail address')
            logger.debug("Signup failed: Invalid email")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match')
            logger.debug("Signup failed: Passwords do not match")
            return redirect(url_for('signup'))

        if (len(password) < 8 or
            not any(c.isupper() for c in password) or
            not any(c.islower() for c in password) or
            not any(c.isdigit() for c in password) or
            not any(not c.isalnum() for c in password)):
            flash('Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character')
            logger.debug("Signup failed: Weak password")
            return redirect(url_for('signup'))

        if username in users:
            flash('Username already exists')
            logger.debug("Signup failed: Username exists")
            return redirect(url_for('signup'))

        users[username] = {
            'password': generate_password_hash(password),
            'email': email
        }
        save_users(users)
        login_user(User(username))
        logger.debug("Signup successful, redirecting to home")
        return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logger.debug("Logging out user: %s", current_user.id)
    logout_user()
    return redirect(url_for('login'))

# ------------------- Room Routes -------------------
@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    logger.debug("Creating room for user: %s", current_user.id)
    room_code = generate_room_code()
    expiry_choice = request.form.get('expiry', '604800')
    try:
        expiry_seconds = int(expiry_choice)
    except ValueError:
        expiry_seconds = 604800
    expiry_time = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
    rooms[room_code] = {'members': {}, 'messages': [], 'expiry': expiry_time.isoformat()}
    save_rooms(rooms)
    session['room'] = room_code
    logger.debug("Room created: %s, expiry: %s", room_code, expiry_time)
    return redirect(url_for('room'))

@app.route('/join_room', methods=['POST'])
@login_required
def join_room_route():
    room_code = request.form.get('room_code')
    logger.debug("User %s attempting to join room: %s", current_user.id, room_code)
    if room_code not in rooms:
        flash('Invalid or expired room code')
        logger.debug("Join failed: Invalid room code %s", room_code)
        return redirect(url_for('home'))
    session['room'] = room_code
    return redirect(url_for('room'))

@app.route('/room')
@login_required
def room():
    logger.debug("Accessing room for user: %s", current_user.id)
    room_code = session.get('room')
    if not room_code or room_code not in rooms:
        flash('Room has expired or does not exist.')
        logger.debug("Room access failed: Room %s not found", room_code)
        return redirect(url_for('home'))
    encrypted_msgs = rooms[room_code]['members'].get(current_user.id, [])
    decrypted_msgs = []
    for msg in encrypted_msgs:
        try:
            decrypted_text = fernet.decrypt(msg['message'].encode()).decode()
            decrypted_msgs.append({'sender': msg['sender'], 'message': decrypted_text})
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            decrypted_msgs.append({'sender': msg['sender'], 'message': msg['message']})
    return render_template('room.html', room=room_code, messages=decrypted_msgs)

@app.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    room_code = session.get('room')
    logger.debug("Clearing chat for user %s in room %s", current_user.id, room_code)
    if room_code and room_code in rooms:
        rooms[room_code]['members'][current_user.id] = []
        save_rooms(rooms)
        socketio.emit('clear_messages', to=room_code)
    return redirect(url_for('room'))

# ------------------- User -------------------
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None

# ------------------- Socket.IO -------------------
@socketio.on('connect')
@authenticated_only
def handle_connect(auth=None):
    room = session.get('room')
    logger.debug("Socket.IO connect for user %s in room %s", current_user.id, room)
    if not room or room not in rooms:
        logger.debug("Disconnecting: Room %s not found", room)
        disconnect()
        return
    join_room(room)
    rooms[room]['members'].setdefault(current_user.id, [])
    send({'sender': '', 'message': f"{current_user.id} has entered the chat"}, to=room)

@socketio.on('message')
@authenticated_only
def handle_message(data):
    room = session.get('room')
    logger.debug("Message from %s in room %s: %s", current_user.id, room, data.get('message'))
    if not room or room not in rooms:
        return
    plaintext = data['message'].encode()
    encrypted_message = fernet.encrypt(plaintext).decode()
    message = {'sender': current_user.id, 'message': encrypted_message}
    rooms[room]['members'].setdefault(current_user.id, []).append(message)
    rooms[room]['messages'].append(message)
    save_rooms(rooms)
    send({'sender': current_user.id, 'message': data['message']}, to=room)

@socketio.on('disconnect')
@authenticated_only
def handle_disconnect():
    room = session.get('room')
    logger.debug("User %s disconnected from room %s", current_user.id, room)
    if not room or room not in rooms:
        return
    send({'sender': '', 'message': f"{current_user.id} has left the chat"}, to=room)
    leave_room(room)

# ------------------- Run -------------------
if __name__ == "__main__":
    cleanup_thread = threading.Thread(target=cleanup_expired_rooms, daemon=True)
    cleanup_thread.start()
    logger.debug("Starting Flask-SocketIO server")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=True,allow_unsafe_werkzeug=True)