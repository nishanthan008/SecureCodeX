
# VULNERABLE: python-path-traversal
import os
import flask

app = flask.Flask(__name__)

@app.route("/read")
def read_file():
    filename = flask.request.args.get("file")
    # EXPLOITABLE: Untrusted input directly used in path
    path = os.path.join("uploads", filename)
    with open(path, "r") as f: # $SINK
        return f.read()

# SECURE: python-path-traversal
@app.route("/read_secure")
def read_secure():
    filename = flask.request.args.get("file")
    # SAFE: Sanitized via os.path.basename()
    safe_name = os.path.basename(filename)
    path = os.path.join("uploads", safe_name)
    with open(path, "r") as f: # $SINK (Safe)
        return f.read()
