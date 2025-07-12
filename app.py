from flask import Flask, render_template, request, redirect, url_for, session
from supabase import create_client, Client
from dotenv import load_dotenv
from flask_argon2 import Argon2
import os

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
app.secret_key = os.urandom(24)  
argon2 = Argon2(app)

@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    password_hash = argon2.generate_password_hash(password)

    data = {
        "username": username,
        "email": email,
        "password_hash": password_hash  
    }

    supabase.table("users").insert(data).execute()
    return redirect(url_for("index"))

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    response = supabase.table("users").select("*").eq("username", username).execute()
    users = response.data

    if not users:
        return "Kullanıcı bulunamadı!"

    user = users[0]
    hashed_password = user["password_hash"]

    if argon2.check_password_hash(hashed_password, password):
        session["user"] = username  
        return redirect(url_for("index"))
    else:
        return "Hatalı şifre!"

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
