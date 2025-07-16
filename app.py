
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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
    logged_in = user is not None

    user_data = None
    if logged_in:
        response = supabase.table("users").select("*").eq("username", user).execute()
        if response.data:
            user_data = response.data[0]

    return render_template("index.html", user=user_data, logged_in=logged_in)

@app.route('/register_page', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
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
        session['user'] = username
        return redirect(url_for("index"))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        response = supabase.table('users').select('*').eq('username', username).execute()
        users = response.data

        if not users:
            return "Kullanıcı bulunamadı!", 401

        user = users[0]
        hashed_password = user['password_hash']

        if argon2.check_password_hash(hashed_password, password):
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return "Hatalı şifre!", 401

    return render_template('login.html')

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

@app.route('/settings')
def settings_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    response = supabase.table('users').select('*').eq('username', username).execute()
    user_data = response.data[0] if response.data else None

    return render_template('settings.html', user=user_data)

@app.route('/update_username', methods=['POST'])
def update_username():
    if 'user' not in session:
        return redirect(url_for('login'))

    old_username = session['user']
    new_username = request.form.get('new_username')

    supabase.table('users').update({'username': new_username}).eq('username', old_username).execute()
    session['user'] = new_username

    return redirect(url_for('settings_page'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        return "Yeni şifreler uyuşmuyor!", 400

    response = supabase.table('users').select('*').eq('username', user).execute()
    db_user = response.data[0]

    if not argon2.check_password_hash(db_user['password_hash'], current_password):
        return "Mevcut şifre yanlış!", 401

    new_password_hash = argon2.generate_password_hash(new_password)
    supabase.table('users').update({'password_hash': new_password_hash}).eq('username', user).execute()

    return redirect(url_for('settings_page'))

@app.route('/forum')
def forum_page():
    return render_template('forum.html')

@app.route('/help')
def help_page():
    return render_template('help.html')




@app.route("/chat")
def chat_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('forum.html')


max_message_limit = 200

@app.route("/send_message", methods=["POST"])
def send_message():
    if 'user' not in session:
        return "Unauthorized", 401
    try:
        data = request.get_json()
        message = data.get("message")
        username = session['user']

        print("DEBUG | Mesaj:", message)
        print("DEBUG | Kullanıcı:", username)

        supabase.table("messages").insert({
            "username": username,
            "message_text": message
        }).execute()

        count_res = supabase.table("messages").select("id", count="exact").execute()
        total_count = count_res.count

        excess = total_count - max_message_limit
        if excess > 0:
            oldest = supabase.table("messages")\
                .select("id")\
                .order("timestamp", desc=False)\
                .limit(excess)\
                .execute()

            for row in oldest.data:
                supabase.table("messages").delete().eq("id", row['id']).execute()

        return jsonify(status="ok")

    except Exception as e:
        print("HATA:", str(e))
        return jsonify(error="Server error", detay=str(e)), 500



@app.route("/get_messages", methods=["GET"])
def get_messages():
    res = supabase.table("messages").select("*").order("timestamp", desc=False).limit(max_message_limit).execute()
    return jsonify(messages=res.data)


if __name__ == "__main__":
    app.run(debug=True)
