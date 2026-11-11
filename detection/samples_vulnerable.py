# A deliberately vulnerable file used ONLY to test the detector. Never deploy it.
import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)
API_KEY = "sk-live-1234567890abcdef"


@app.route("/login")
def login():
    user = request.args.get("user")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user + "'")
    return "ok"


@app.route("/hello")
def hello():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    subprocess.run(f"nslookup {host}", shell=True)
    return "done"
