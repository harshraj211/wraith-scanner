"""
File: test_app/vulnerable_app.py

A deliberately vulnerable Flask application for testing the scanner.
WARNING: Never deploy this to production - it has intentional vulnerabilities!
"""

from flask import Flask, request, render_template_string, redirect, session, url_for
import sqlite3
import time

app = Flask(__name__)
app.secret_key = "test-app-secret-key"

# Initialize a simple database
def init_db():
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute('DELETE FROM users')  # Clear existing
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT INTO users VALUES (2, 'user', 'password')")
    conn.commit()
    conn.close()

init_db()

# Home page with links
@app.route('/')
def home():
    html = """
    <h1>Vulnerable Test App</h1>
    <ul>
        <li><a href="/search?q=test">Search (SQLi vulnerable)</a></li>
        <li><a href="/login">Login Form (SQLi vulnerable)</a></li>
        <li><a href="/comment">Comment (XSS vulnerable)</a></li>
        <li><a href="/profile?id=1">Profile (IDOR vulnerable)</a></li>
        <li><a href="/redirect?url=https://google.com">Redirect (Open redirect)</a></li>
        <li><a href="/auth/login">Protected Area Login</a></li>
    </ul>
    """
    return render_template_string(html)

# SQL Injection - GET parameter (error-based)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    try:
        # VULNERABLE: Direct string concatenation
        sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        c.execute(sql)
        results = c.fetchall()
        return f"<h2>Search Results:</h2><pre>{results}</pre><br><a href='/'>Home</a>"
    except Exception as e:
        return f"<h2>Database Error:</h2><pre>{str(e)}</pre><br><a href='/'>Home</a>"
    finally:
        conn.close()

# SQL Injection - POST form (time-based)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        html = """
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        <a href='/'>Home</a>
        """
        return render_template_string(html)
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    try:
        # VULNERABLE: SQL injection with timing
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        c.execute(sql)
        user = c.fetchone()
        if user:
            return f"<h2>Welcome {user[1]}!</h2><a href='/'>Home</a>"
        else:
            return "<h2>Invalid credentials</h2><a href='/login'>Try again</a>"
    except Exception as e:
        return f"<h2>Error:</h2><pre>{str(e)}</pre>"
    finally:
        conn.close()

# XSS - Reflected
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'GET':
        html = """
        <h2>Leave a Comment</h2>
        <form method="POST">
            Name: <input type="text" name="name"><br>
            Comment: <textarea name="comment"></textarea><br>
            <input type="submit" value="Submit">
        </form>
        <a href='/'>Home</a>
        """
        return render_template_string(html)
    
    name = request.form.get('name', '')
    comment = request.form.get('comment', '')
    
    # VULNERABLE: No escaping
    html = f"""
    <h2>Comment Submitted</h2>
    <p><strong>{name}</strong> said:</p>
    <p>{comment}</p>
    <a href='/comment'>Back</a> | <a href='/'>Home</a>
    """
    return render_template_string(html)

# IDOR - Insecure Direct Object Reference
@app.route('/profile')
def profile():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    # VULNERABLE: No authorization check
    c.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = c.fetchone()
    conn.close()
    
    if user:
        return f"<h2>Profile #{user[0]}</h2><p>Username: {user[1]}</p><a href='/'>Home</a>"
    return "<h2>User not found</h2><a href='/'>Home</a>"

# Open Redirect
@app.route('/redirect')
def redirect_page():
    url = request.args.get('url', '/')
    # VULNERABLE: No URL validation
    return f'<meta http-equiv="refresh" content="0;url={url}"><p>Redirecting to {url}...</p>'


@app.route('/auth/login', methods=['GET'])
def auth_login():
    csrf_token = "auth-csrf-token"
    session['auth_csrf'] = csrf_token
    html = """
    <h2>Protected Area Login</h2>
    <form method="POST" action="/auth/session">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        Username: <input type="text" name="user_name"><br>
        Password: <input type="password" name="user_pass"><br>
        <input type="submit" value="Login">
    </form>
    """
    return render_template_string(html, csrf_token=csrf_token)


@app.route('/auth/session', methods=['POST'])
def auth_session():
    username = request.form.get('user_name', '')
    password = request.form.get('user_pass', '')
    csrf_token = request.form.get('csrf_token', '')

    if csrf_token != session.get('auth_csrf'):
        return "<h2>Invalid CSRF token</h2>", 400

    if username == 'admin' and password == 'admin123':
        session['authenticated_user'] = username
        return redirect(url_for('auth_dashboard'))

    return "<h2>Invalid credentials</h2>", 401


@app.route('/auth/dashboard')
def auth_dashboard():
    if not session.get('authenticated_user'):
        return redirect(url_for('auth_login'))

    html = """
    <h2>Authenticated Dashboard</h2>
    <p>Welcome {{ user }}! <a href="/auth/logout">Logout</a></p>
    <ul>
        <li><a href="/auth/records?id=1">Private Record 1</a></li>
        <li><a href="/auth/report">Internal Report Form</a></li>
    </ul>
    """
    return render_template_string(html, user=session['authenticated_user'])


@app.route('/auth/records')
def auth_records():
    if not session.get('authenticated_user'):
        return redirect(url_for('auth_login'))

    record_id = request.args.get('id', '1')
    return (
        f"<h2>Private Record #{record_id}</h2>"
        f"<p>Owner: {session['authenticated_user']}</p>"
        "<a href='/auth/dashboard'>Dashboard</a>"
    )


@app.route('/auth/report', methods=['GET', 'POST'])
def auth_report():
    if not session.get('authenticated_user'):
        return redirect(url_for('auth_login'))

    if request.method == 'GET':
        html = """
        <h2>Internal Report</h2>
        <form method="POST">
            <input type="text" name="title" value="Quarterly report"><br>
            <textarea name="notes"></textarea><br>
            <input type="submit" value="Save">
        </form>
        """
        return render_template_string(html)

    title = request.form.get('title', '')
    notes = request.form.get('notes', '')
    return (
        f"<h2>Report Saved</h2><p>{title}</p><p>{notes}</p>"
        "<a href='/auth/dashboard'>Dashboard</a>"
    )


@app.route('/auth/logout')
def auth_logout():
    session.clear()
    return redirect(url_for('auth_login'))

if __name__ == '__main__':
    print("\n" + "="*60)
    print("⚠️  VULNERABLE TEST APPLICATION - DO NOT USE IN PRODUCTION")
    print("="*60)
    print("\nStarting server at http://127.0.0.1:5000")
    print("\nVulnerable endpoints:")
    print("  - http://127.0.0.1:5000/search?q=test")
    print("  - http://127.0.0.1:5000/login")
    print("  - http://127.0.0.1:5000/comment")
    print("  - http://127.0.0.1:5000/profile?id=1")
    print("  - http://127.0.0.1:5000/redirect?url=https://google.com")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
