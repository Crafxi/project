from flask import *
import sqlite3
import bcrypt
import os
import uuid

sqlite3_db = 'database.db'
conn = sqlite3.connect(sqlite3_db)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
c.execute('SELECT * FROM users WHERE username=?', ('admin',))
if not c.fetchone():
    c.execute('''INSERT INTO users (username, password) VALUES ('admin', 'password')''')
conn.commit()

app = Flask(__name__)
app.secret_key = os.urandom(12)


@app.context_processor
def inject_layout():
    def render_header(header_text):
        session_id = request.cookies.get('session_id')
        username = session.get(session_id)
        logout_button = ''
        user_info = ''
        if username:
            logout_button = f'''
            <button onclick="window.location.href='/logout'" 
                class="bg-red-500 text-white border-none px-4 py-2 cursor-pointer ml-4 mt-2 rounded hover:bg-red-600">
                Logout
            </button>
            '''
            user_info = f'<p class="text-white">Logged in as: {username} {logout_button}</p>'
        return f'''
        <header class="bg-gray-800 text-white p-4 text-center font-sans mb-4">
            <h1 class="text-2xl">{header_text}</h1>
            {user_info}
        </header>
        '''
    footer_html = '''
    <footer class="bg-gray-900 text-white p-4 fixed bottom-0 w-full text-center font-sans">
        <p>&copy; 2023 Meine Webseite. Alle Rechte vorbehalten.</p>
    </footer>
    '''
    return dict(render_header=render_header, footer=footer_html)


@app.route('/')
def index():
    session_id = request.cookies.get('session_id')
    if session_id:
        username = session.get(session_id)
        if username:
            return redirect(url_for('welcome'))
    title = request.args.get('title', 'Default Title')
    return render_template('index.html', title=title, header_text='Welcome to My Website')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Hash the password

        conn = sqlite3.connect(sqlite3_db)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        existing_user = c.fetchone()
        if existing_user:
            conn.close()
            return render_template('register.html', error='Username already exists')
        
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return render_template('index.html', message='User registered successfully', header_text='Registration Success')
    return render_template('register.html', header_text='Register New User')


@app.post('/login')
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()

    # Verify the hashed password
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        session_id = str(uuid.uuid4())
        session[session_id] = username
        response = redirect(url_for('welcome'))
        response.set_cookie('session_id', session_id, max_age=60*60*24)  # Set cookie for 1 day
        return response
    else:
        return render_template('index.html', error='Passwort oder Benutzername falsch', header_text='Login Page')


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id and session_id in session:
        session.pop(session_id)
    response = redirect(url_for('index'))
    response.delete_cookie('session_id')  # Remove the cookie
    return response


@app.route('/welcome')
def welcome():
    session_id = request.cookies.get('session_id')
    username = session.get(session_id)
    if not username:
        return redirect(url_for('index'))
    return render_template('welcome.html', header_text='Welcome Page')


@app.route('/user/<username>')
def user_profile(username):
    session_id = request.cookies.get('session_id')
    logged_in_user = session.get(session_id)
    if not logged_in_user:
        return redirect(url_for('index'))
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    if user:
        return render_template('users.html', user=user[1], header_text=f'Profile of {user[1]}')
    else:
        return render_template('users.html')


@app.get('/search_user')
def search_user():
    session_id = request.cookies.get('session_id')
    logged_in_user = session.get(session_id)
    if not logged_in_user:
        return redirect(url_for('index'))
    username = request.args.get('username', '')
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE username LIKE ?', (f'%{username}%',))
    results = c.fetchall()
    conn.close()
    users = [{'name': user[0]} for user in results]
    return render_template('welcome.html', users=users, header_text='Search Results')


# when py stops running, close the connection to the database
@app.teardown_appcontext
def close_connection(exception):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()
