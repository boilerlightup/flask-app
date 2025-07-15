from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a random secret in production

# ---------- Database Setup ----------
def init_db():
    conn = sqlite3.connect('auth.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    
    # Tasks table
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    completed BOOLEAN NOT NULL DEFAULT 0,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )''')
    
    conn.commit()
    conn.close()

# ---------- Auth Routes ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        hashed = generate_password_hash(password)

        try:
            conn = sqlite3.connect('auth.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists."
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = sqlite3.connect('auth.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password."
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- Task Routes ----------
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('auth.db')
    c = conn.cursor()

    if request.method == 'POST':
        task = request.form['task'].strip()
        if task:
            c.execute('INSERT INTO tasks (content, user_id) VALUES (?, ?)', (task, session['user_id']))
            conn.commit()
    
    c.execute('SELECT id, content, completed FROM tasks WHERE user_id = ?', (session['user_id'],))
    tasks = c.fetchall()
    conn.close()
    return render_template('dashboard.html', user=session['username'], tasks=tasks)

@app.route('/delete/<int:task_id>')
def delete(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('auth.db')
    c = conn.cursor()
    c.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
def edit(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('auth.db')
    c = conn.cursor()

    if request.method == 'POST':
        new_content = request.form['content'].strip()
        if new_content:
            c.execute('UPDATE tasks SET content = ? WHERE id = ? AND user_id = ?', (new_content, task_id, session['user_id']))
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))

    c.execute('SELECT id, content FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
    task = c.fetchone()
    conn.close()
    return render_template('edit.html', task=task)

@app.route('/toggle/<int:task_id>')
def toggle(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('auth.db')
    c = conn.cursor()
    c.execute('SELECT completed FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
    current = c.fetchone()
    if current:
        new_status = 0 if current[0] else 1
        c.execute('UPDATE tasks SET completed = ? WHERE id = ? AND user_id = ?', (new_status, task_id, session['user_id']))
        conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# ---------- Run ----------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
