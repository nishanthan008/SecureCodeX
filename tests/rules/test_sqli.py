
# VULNERABLE: python-sqli-high-fidelity
import flask
import sqlite3

app = flask.Flask(__name__)
db = sqlite3.connect("test.db")

@app.route("/user")
def get_user():
    user_id = flask.request.args.get("id")
    # EXPLOITABLE: Direct concatenation of untrusted input into SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor = db.cursor()
    cursor.execute(query) # $SINK
    return str(cursor.fetchone())

# SECURE: python-sqli-high-fidelity
@app.route("/user_secure")
def get_user_secure():
    user_id = flask.request.args.get("id")
    # SAFE: Sanitized via int() casting
    clean_id = int(user_id)
    query = "SELECT * FROM users WHERE id = " + str(clean_id)
    cursor = db.cursor()
    cursor.execute(query) # $SINK (Sanitized)
    return str(cursor.fetchone())

# NEGATIVE: python-sqli-high-fidelity
@app.route("/user_constant")
def get_user_constant():
    # SAFE: Constant string, no external source
    query = "SELECT * FROM users WHERE id = 123"
    cursor = db.cursor()
    cursor.execute(query) # $SINK (Constant)
    return str(cursor.fetchone())
