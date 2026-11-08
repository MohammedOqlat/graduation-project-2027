# Safe version: the detector must report NOTHING here.
import os
import sqlite3
import subprocess
from html import escape
from flask import Flask, request

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY")


@app.route("/login")
def login():
    user = request.args.get("user")
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (user,))
    return "ok"


@app.route("/hello")
def hello():
    name = request.args.get("name")
    return f"<h1>Hello {escape(name)}</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host])
    return "done"
