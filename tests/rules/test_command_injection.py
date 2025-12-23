
# VULNERABLE: python-os-command-injection
import os
import flask
import subprocess

app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    hostname = flask.request.args.get("host")
    # EXPLOITABLE: Untrusted input used in shell command
    os.system("ping -c 1 " + hostname) # $SINK
    return "Pinged " + hostname

# SECURE: python-os-command-injection
import shlex
@app.route("/ping_secure")
def ping_secure():
    hostname = flask.request.args.get("host")
    # SAFE: Sanitized via shlex.quote()
    safe_host = shlex.quote(hostname)
    os.system("ping -c 1 " + safe_host) # $SINK (Sanitized)
    return "Pinged " + safe_host

# SECURE: python-os-command-injection (List approach)
@app.route("/ping_list")
def ping_list():
    hostname = flask.request.args.get("host")
    # SAFE: Using list of arguments (no shell expansion)
    subprocess.run(["ping", "-c", "1", hostname]) # $SINK (Safe)
    return "Pinged " + hostname
