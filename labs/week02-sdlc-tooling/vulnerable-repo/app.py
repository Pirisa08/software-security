"""
Remediated sample for Week 2 security practice.
Fixes the vulnerabilities identified by SAST + secret scanning.
"""

import os
import sqlite3
import subprocess
import bcrypt

from flask import Flask, request

app = Flask(__name__)

# CWE-798: secrets are loaded from environment variables
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")

    # CWE-89 fix: use a parameterized query
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # CWE-78 fix: pass arguments as a list and do not use shell=True
    return subprocess.check_output(["ping", "-c", "1", host])


def store_password(pw):
    # CWE-327 fix: use bcrypt instead of MD5
    hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
    return hashed.decode()


if __name__ == "__main__":
    # CWE-489 fix: disable Flask debug mode
    app.run(debug=False)