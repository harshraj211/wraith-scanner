"""
File: test_app/vulnerable_app.py

A deliberately vulnerable Flask application for testing the scanner.
WARNING: Never deploy this to production - it has intentional vulnerabilities!
"""

from flask import Flask, jsonify, request, render_template_string, redirect, session, url_for
import re
import sqlite3
import time

app = Flask(__name__)
app.secret_key = "test-app-secret-key"
API_BEARER_TOKEN = "test-bearer-token"
API_HEADER_KEY = "header-key-123"
API_QUERY_KEY = "query-key-456"
API_SESSION_COOKIE = "secure-session-789"

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
        <li><a href="/dom?dom=test">DOM XSS</a></li>
        <li><a href="/graphql">GraphQL Endpoint</a></li>
        <li><a href="/openapi.json">OpenAPI Spec</a></li>
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


@app.route('/dom')
def dom_page():
    return render_template_string("""
    <h2>DOM XSS Playground</h2>
    <div id="dom-target"></div>
    <script>
      const rawHash = decodeURIComponent(window.location.hash.slice(1));
      const hashPayload = rawHash.includes('=') ? rawHash.split('=').slice(1).join('=') : rawHash;
      if (hashPayload) {
        document.getElementById('dom-target').innerHTML = hashPayload;
      }
    </script>
    """)


@app.route('/openapi.json')
def openapi_spec():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "Vulnerable Test API", "version": "1.0.0"},
        "servers": [{"url": "/"}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
                "headerKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                },
                "queryKey": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "api_token",
                },
                "sessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "sessionid",
                },
            }
        },
        "paths": {
            "/api/comment": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "example": "tester"},
                                        "comment": {"type": "string", "example": "hello"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Comment echo"}},
                }
            },
            "/api/search": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "q": {"type": "string", "example": "admin"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Search results"}},
                }
            },
            "/api/run": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "command": {"type": "string", "example": "status"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Command output"}},
                }
            },
            "/api/file": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "example": "report.txt"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "File contents"}},
                }
            },
            "/api/template": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "template": {"type": "string", "example": "Hello {{ name }}"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Rendered template"}},
                }
            },
            "/api/xml": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/xml": {
                                "schema": {"type": "string"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "Parsed XML"}},
                }
            },
            "/api/users/{user_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "example": 1},
                        },
                        {
                            "name": "view",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "example": "summary"},
                        },
                    ],
                    "responses": {"200": {"description": "User details"}},
                }
            },
            "/api/secure/reflect": {
                "get": {
                    "security": [
                        {
                            "bearerAuth": [],
                            "headerKey": [],
                            "sessionCookie": [],
                        }
                    ],
                    "parameters": [
                        {
                            "name": "X-Trace",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string", "example": "trace-id"},
                        },
                        {
                            "name": "theme",
                            "in": "cookie",
                            "required": False,
                            "schema": {"type": "string", "example": "light"},
                        },
                    ],
                    "responses": {"200": {"description": "Protected reflection"}},
                }
            },
            "/api/secure/query": {
                "get": {
                    "security": [
                        {
                            "queryKey": [],
                        }
                    ],
                    "parameters": [
                        {
                            "name": "item",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "example": "sample"},
                        },
                    ],
                    "responses": {"200": {"description": "Protected query endpoint"}},
                }
            },
        },
    })


@app.route('/api/comment', methods=['POST'])
def api_comment():
    payload = request.get_json(silent=True) or {}
    name = payload.get('name', '')
    comment = payload.get('comment', '')
    return render_template_string(
        f"<h2>API Comment</h2><p><strong>{name}</strong></p><div>{comment}</div>"
    )


@app.route('/api/search', methods=['POST'])
def api_search():
    payload = request.get_json(silent=True) or {}
    query = payload.get('q', '')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    try:
        sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        c.execute(sql)
        results = c.fetchall()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@app.route('/api/run', methods=['POST'])
def api_run():
    payload = request.get_json(silent=True) or {}
    command = payload.get('command', '')
    if 'sleep 2' in command or 'timeout 2' in command:
        time.sleep(2)
        return jsonify({"output": "slept"})
    if 'whoami' in command or 'id' in command:
        return jsonify({"output": "uid=1000(scanner) gid=1000(scanner)"})
    if 'cat /etc/passwd' in command:
        return jsonify({"output": "root:x:0:0:root:/root:/bin/bash"})
    return jsonify({"output": "command not executed"})


@app.route('/api/file', methods=['POST'])
def api_file():
    payload = request.get_json(silent=True) or {}
    file_path = payload.get('file', '')
    if 'passwd' in file_path:
        return "root:x:0:0:root:/root:/bin/bash\n"
    if 'win.ini' in file_path.lower():
        return "[extensions]\n"
    return "requested file not found", 404


@app.route('/api/template', methods=['POST'])
def api_template():
    payload = request.get_json(silent=True) or {}
    template = payload.get('template', 'Hello')
    return render_template_string(template)


@app.route('/api/xml', methods=['POST'])
def api_xml():
    xml_body = request.get_data(as_text=True) or ''
    if 'file:///etc/passwd' in xml_body:
        return "root:x:0:0:root:/root:/bin/bash\n"
    if 'c:/windows/win.ini' in xml_body.lower():
        return "[extensions]\n"
    if '169.254.169.254' in xml_body:
        return "instanceId=i-123456"
    if '<!entity' in xml_body.lower():
        return "XML external entity error"
    return "<ok/>"


@app.route('/api/users/<user_id>')
def api_user(user_id):
    view = request.args.get('view', 'summary')
    return jsonify({"user_id": user_id, "view": view})


@app.route('/api/secure/reflect')
def api_secure_reflect():
    auth_header = request.headers.get("Authorization", "")
    api_key = request.headers.get("X-API-Key", "")
    session_cookie = request.cookies.get("sessionid", "")
    if auth_header != f"Bearer {API_BEARER_TOKEN}" or api_key != API_HEADER_KEY or session_cookie != API_SESSION_COOKIE:
        return jsonify({"error": "unauthorized"}), 401

    trace = request.headers.get("X-Trace", "")
    theme = request.cookies.get("theme", "")
    return render_template_string(
        f"<h2>Secure Reflection</h2><div>{trace}</div><div>{theme}</div>"
    )


@app.route('/api/secure/query')
def api_secure_query():
    if request.args.get("api_token") != API_QUERY_KEY:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"item": request.args.get("item", "")})


GRAPHQL_SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {
                    "name": "searchUsers",
                    "args": [
                        {
                            "name": "q",
                            "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                        }
                    ],
                    "type": {"kind": "OBJECT", "name": "SearchResult", "ofType": None},
                },
                {
                    "name": "user",
                    "args": [
                        {
                            "name": "userId",
                            "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                        }
                    ],
                    "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                },
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Mutation",
            "fields": [
                {
                    "name": "updateProfile",
                    "args": [
                        {
                            "name": "displayName",
                            "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                        }
                    ],
                    "type": {"kind": "OBJECT", "name": "MutationResult", "ofType": None},
                }
            ],
        },
        {
            "kind": "OBJECT",
            "name": "SearchResult",
            "fields": [
                {
                    "name": "result",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                }
            ],
        },
        {
            "kind": "OBJECT",
            "name": "User",
            "fields": [
                {
                    "name": "userId",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                },
                {
                    "name": "username",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                },
            ],
        },
        {
            "kind": "OBJECT",
            "name": "MutationResult",
            "fields": [
                {
                    "name": "ok",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                },
                {
                    "name": "message",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                },
            ],
        },
        {"kind": "SCALAR", "name": "String", "fields": None},
        {"kind": "SCALAR", "name": "ID", "fields": None},
        {"kind": "SCALAR", "name": "Boolean", "fields": None},
    ],
}


def _graphql_value(payload, name, default="sample"):
    variables = payload.get("variables") or {}
    if isinstance(variables, dict) and name in variables:
        return variables.get(name)

    query = payload.get("query", "") or ""
    pattern = rf'{name}\s*:\s*"([^"]*)"'
    match = re.search(pattern, query)
    if match:
        return match.group(1)
    return default


@app.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    if request.method == 'GET':
        return render_template_string(
            "<h2>GraphQL Endpoint</h2><p>POST GraphQL queries here.</p>"
        )

    payload = request.get_json(silent=True) or {}
    query = payload.get("query", "") or ""

    if "__schema" in query or "__type" in query:
        return jsonify({"data": {"__schema": GRAPHQL_SCHEMA}})

    if "searchUsers" in query:
        search = _graphql_value(payload, "q", "sample")
        if "'" in str(search):
            return jsonify({
                "errors": [
                    {"message": f"sqlite3.OperationalError: unrecognized token near {search}"}
                ]
            }), 200
        return jsonify({"data": {"searchUsers": {"result": str(search)}}})

    if "updateProfile" in query:
        display_name = _graphql_value(payload, "displayName", "anon")
        return jsonify({"data": {"updateProfile": {"ok": True, "message": str(display_name)}}})

    if "user" in query:
        user_id = _graphql_value(payload, "userId", "1")
        user_map = {
            "1": {"userId": "1", "username": "admin"},
            "2": {"userId": "2", "username": "user"},
        }
        return jsonify({"data": {"user": user_map.get(str(user_id), {"userId": str(user_id), "username": "guest"})}})

    return jsonify({"errors": [{"message": "Unsupported GraphQL operation"}]}), 400


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
    print("\n" + "=" * 60)
    print("WARNING: VULNERABLE TEST APPLICATION - DO NOT USE IN PRODUCTION")
    print("=" * 60)
    print("\nStarting server at http://127.0.0.1:5000")
    print("\nVulnerable endpoints:")
    print("  - http://127.0.0.1:5000/search?q=test")
    print("  - http://127.0.0.1:5000/login")
    print("  - http://127.0.0.1:5000/comment")
    print("  - http://127.0.0.1:5000/profile?id=1")
    print("  - http://127.0.0.1:5000/redirect?url=https://google.com")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
