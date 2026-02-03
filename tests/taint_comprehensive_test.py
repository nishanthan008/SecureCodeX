# Comprehensive Taint Analysis Test - Python
# This file tests all vulnerability types covered by Python taint rules

from flask import Flask, request, render_template_string, redirect
import os
import subprocess
import sqlite3
import pickle
import yaml
import requests
from jinja2 import Template

app = Flask(__name__)

# ============================================================================
# SQL INJECTION TESTS
# ============================================================================

@app.route('/sqli/flask')
def sqli_flask():
    user_id = request.args.get('id')  # Source
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # Sink
    return "Query executed"

@app.route('/sqli/safe')
def sqli_safe():
    user_id = request.args.get('id')  # Source
    user_id = int(user_id)  # Sanitizer
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # Should NOT flag (sanitized)
    return "Safe query"

# ============================================================================
# NOSQL INJECTION TESTS
# ============================================================================

@app.route('/nosql/mongodb')
def nosql_mongodb():
    from pymongo import MongoClient
    username = request.json.get('username')  # Source
    client = MongoClient()
    db = client.mydb
    # VULNERABLE: Untrusted input in query
    result = db.users.find({'username': username})  # Sink
    return "Query executed"

# ============================================================================
# COMMAND INJECTION TESTS
# ============================================================================

@app.route('/cmd/os')
def cmd_os():
    filename = request.args.get('file')  # Source
    # VULNERABLE: Direct command execution
    os.system(f"cat {filename}")  # Sink
    return "Command executed"

@app.route('/cmd/subprocess')
def cmd_subprocess():
    cmd = request.form.get('command')  # Source
    # VULNERABLE: shell=True with user input
    subprocess.run(cmd, shell=True)  # Sink
    return "Subprocess executed"

# ============================================================================
# CODE INJECTION TESTS
# ============================================================================

@app.route('/code/eval')
def code_eval():
    expr = request.args.get('expr')  # Source
    # VULNERABLE: eval with user input
    result = eval(expr)  # Sink
    return str(result)

@app.route('/code/exec')
def code_exec():
    code = request.form.get('code')  # Source
    # VULNERABLE: exec with user input
    exec(code)  # Sink
    return "Code executed"

# ============================================================================
# TEMPLATE INJECTION (SSTI) TESTS
# ============================================================================

@app.route('/ssti/jinja2')
def ssti_jinja2():
    template_str = request.args.get('template')  # Source
    # VULNERABLE: render_template_string with user input
    return render_template_string(template_str)  # Sink

# ============================================================================
# XSS TESTS
# ============================================================================

@app.route('/xss/reflected')
def xss_reflected():
    name = request.args.get('name')  # Source
    # VULNERABLE: Unescaped user input in response
    from flask import make_response
    return make_response(f"<h1>Hello {name}</h1>")  # Sink

# ============================================================================
# SSRF TESTS
# ============================================================================

@app.route('/ssrf/requests')
def ssrf_requests():
    url = request.args.get('url')  # Source
    # VULNERABLE: Unvalidated URL
    response = requests.get(url)  # Sink
    return response.text

# ============================================================================
# PATH TRAVERSAL TESTS
# ============================================================================

@app.route('/path/traversal')
def path_traversal():
    filename = request.args.get('file')  # Source
    # VULNERABLE: Direct file access
    with open(filename, 'r') as f:  # Sink
        content = f.read()
    return content

# ============================================================================
# DESERIALIZATION TESTS
# ============================================================================

@app.route('/deserialize/pickle')
def deserialize_pickle():
    data = request.get_data()  # Source
    # VULNERABLE: Unpickling untrusted data
    obj = pickle.loads(data)  # Sink
    return "Deserialized"

@app.route('/deserialize/yaml')
def deserialize_yaml():
    data = request.get_data()  # Source
    # VULNERABLE: yaml.load() without safe_load
    obj = yaml.load(data)  # Sink
    return "Deserialized"

# ============================================================================
# OPEN REDIRECT TESTS
# ============================================================================

@app.route('/redirect/open')
def open_redirect():
    url = request.args.get('next')  # Source
    # VULNERABLE: Unvalidated redirect
    return redirect(url)  # Sink

if __name__ == '__main__':
    app.run(debug=True)
