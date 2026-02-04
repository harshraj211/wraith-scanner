"""
File: test_app/vulnerable_app.py

A deliberately vulnerable Flask application for testing the scanner.
WARNING: Never deploy this to production - it has intentional vulnerabilities!
"""

from flask import Flask, request, render_template_string
import sqlite3
import time

app = Flask(__name__)

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