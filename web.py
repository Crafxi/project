from flask import *
import sqlite3
import bcrypt
import os

sqlite3_db = 'database.db'
conn = sqlite3.connect(sqlite3_db)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
c.execute('SELECT * FROM users WHERE username=?', ('admin',))
if not c.fetchone():
    hashed_password = bcrypt.hashpw('password'.encode('utf-8'), bcrypt.gensalt())
    c.execute('''INSERT INTO users (username, password) VALUES ('admin', ?)''', (hashed_password,))
conn.commit()


app = Flask(__name__)
app.secret_key = os.urandom(12)


@app.context_processor
def inject_layout():
    def render_header(header_text):
        username = session.get('username')
        logout_button = ''
        user_info = ''
        admin_panel_link = ''
        if username:
            conn = sqlite3.connect(sqlite3_db)
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username=?', (username,))
            user = c.fetchone()
            conn.close()
            if user and user[3] == 'admin':  # Check if the user has the 'admin' role
                admin_panel_link = '''
                <a href="/adminpanel" 
                    class="bg-stone-700 text-stone-200 border-none px-4 py-2 cursor-pointer ml-4 mt-2 rounded hover:bg-stone-600">
                    Admin Panel
                </a>
                '''
            logout_button = f'''
            <button onclick="window.location.href='/logout'" 
                class="bg-stone-700 text-stone-200 border-none px-4 py-2 cursor-pointer ml-4 mt-2 rounded hover:bg-stone-600">
                Logout
            </button>
            '''
            user_info = f'<p class="text-stone-200">Logged in as: {username} {logout_button} {admin_panel_link}</p>'
        return f'''
        <header class="flex bg-stone-800 align-content-middle text-stone-200 p-4 text-center font-sans mb-4 justify-between items-center">
            <a class="text-2xl" href="/">{header_text}</a>
            {user_info}
        </header>
        '''
    footer_html = '''
    <footer class="bg-stone-900 text-stone-300 p-4 w-full text-center font-sans fixed bottom-0">
        <p>&copy; 2025 Meine Webseite. Alle Rechte vorbehalten.</p>
    </footer>
    '''
    return dict(render_header=render_header, footer=footer_html)


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('welcome'))
    title = request.args.get('title', 'Default Title')
    return render_template('index.html', title=title, header_text='Eigene Website Login Test')


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
        
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, 'user'))
        conn.commit()
        conn.close()
        return render_template('index.html', message='User registered successfully')
    return render_template('register.html', header_text='Regstrierung')


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
        session['username'] = username  # Store the username in the session
        return redirect(url_for('welcome'))
    else:
        return render_template('index.html', error='Passwort oder Benutzername falsch', header_text='Login')


@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the username from the session
    return redirect(url_for('index'))


@app.route('/welcome')
def welcome():
    username = session.get('username')
    if not username:
        return redirect(url_for('index'))
    return render_template('welcome.html', header_text='Hauptseite', username=username)


@app.route('/user/<int:user_id>')
def user_profile(user_id):
    logged_in_user = session.get('username')
    if not logged_in_user:
        return redirect(url_for('index'))
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id=?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return render_template('users.html', user=user[1], header_text=f'Profil von {user[1]}')
    else:
        return render_template('users.html', error='User not found')


@app.get('/search_user')
def search_user():
    logged_in_user = session.get('username')
    if not logged_in_user:
        return redirect(url_for('index'))
    username = request.args.get('username', '')
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT id, username FROM users WHERE username LIKE ?', (f'%{username}%',))
    results = c.fetchall()
    conn.close()
    users = [{'id': user[0], 'name': user[1]} for user in results]
    return render_template('welcome.html', users=users, header_text='Hauptseite')

@app.route('/adminpanel')
def admin_panel():
    logged_in_user = session.get('username')
    if not logged_in_user:
        return redirect(url_for('index'))
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (logged_in_user,))
    user = c.fetchone()
    if not user or user[3] != 'admin':  # Check if the user exists and has the 'admin' role
        conn.close()
        return redirect(url_for('index'))
    c.execute('SELECT * FROM users')
    users = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, header_text='Admin Panel')

@app.route('/add_user', methods=['POST'])
def add_user():
    logged_in_user = session.get('username')
    if not logged_in_user:
        return redirect(url_for('index'))
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (logged_in_user,))
    user = c.fetchone()
    if not user or user[3] != 'admin':  # Check if the user exists and has the 'admin' role
        conn.close()
        return redirect(url_for('index'))
    username = request.form['username']
    password = request.form['password']  # Get password from the form
    role = request.form['role']
    
    c.execute('SELECT * FROM users')
    users = c.fetchall()
    
    # Check if the username already exists
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    existing_user = c.fetchone()
    if existing_user:
        conn.close()
        return render_template('admin.html', error='Username already exists', header_text='Admin Panel', users=users)
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))


@app.route('/edit_user/<int:user_id>', methods=['POST', 'GET'])
def edit_user(user_id):
    logged_in_user = session.get('username')
    if not logged_in_user:
        return redirect(url_for('index'))
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (logged_in_user,))
    user = c.fetchone()
    if not user or user[3] != 'admin':  # Check if the user exists and has the 'admin' role
        conn.close()
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) if password else None
        if hashed_password:
            c.execute('UPDATE users SET username=?, password=?, role=? WHERE id=?', (username, hashed_password, role, user_id))
        else:
            c.execute('UPDATE users SET username=?, role=? WHERE id=?', (username, role, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_panel'))
    else:
        c.execute('SELECT * FROM users WHERE id=?', (user_id,))
        user_to_edit = c.fetchone()
        conn.close()
        if user_to_edit:
            return render_template('edit_user.html', user=user_to_edit, header_text='Edit User')
        else:
            return redirect(url_for('admin_panel'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    logged_in_user = session.get('username')
    if not logged_in_user:
        return redirect(url_for('index'))
    conn = sqlite3.connect(sqlite3_db)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (logged_in_user,))
    user = c.fetchone()
    if not user or user[3] != 'admin':  # Check if the user exists and has the 'admin' role
        conn.close()
        return redirect(url_for('index'))
    c.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))


# when py stops running, close the connection to the database
@app.teardown_appcontext
def close_connection(exception):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()