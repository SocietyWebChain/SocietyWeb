from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from supabase import create_client, Client
from dotenv import load_dotenv
import re
import os
import datetime
import dns.resolver
import socket
from gotrue.errors import AuthApiError

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = Flask(__name__)
app.secret_key = os.urandom(24)

max_message_limit = 200

@app.before_request
def check_ban():
    if 'user_id' in session:
        try:
            user_id = session['user_id']
            user_response = supabase.auth.admin.get_user_by_id(user_id)
            user_data = user_response.user
            user_metadata = user_data.user_metadata or {}

            banned_until = user_metadata.get('banned_until')
            if banned_until and banned_until != "null":
                try:
                    banned_time = datetime.datetime.fromisoformat(banned_until)
                    if datetime.datetime.now() < banned_time:
                        return render_template("banned.html", banned_until=banned_until)
                except Exception as e:
                    print("Ban kontrolünde tarih hatası:", e)

        except Exception as e:
            print("Ban kontrol hatası:", e)

@app.route('/register_page', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        username = request.form.get("username")

        email_check = supabase_admin.table("profiles").select("id").eq("email", email).execute()
        if email_check.data:
            return render_template('register.html', error="Bu e-posta zaten kayıtlı.")

        username_check = supabase_admin.table("profiles").select("id").eq("username", username).execute()
        if username_check.data:
            return render_template('register.html', error="Bu kullanıcı adı zaten alınmış.")

        try:
            response = supabase.auth.sign_up({
                "email": email,
                "password": password
            })
            if response.user:
                user_id = response.user.id

                try:
                    profile_insert = supabase_admin.table("profiles").insert({
                        "id": user_id,
                        "email": email,
                        "username": username
                    }).execute()

                    if profile_insert.data: 
                        return render_template('login.html', success="Kayıt başarılı! Giriş yapabilirsiniz.")
                    else:
                        return render_template('register.html', error="Profil kaydedilemedi. Lütfen tekrar deneyin.")
                except Exception as e:
                    print(f"Profil kaydedilirken hata oluştu: {e}")
                    return render_template('register.html', error=f"Profil kaydedilemedi: {e}")

            else:
                print(f"Auth kaydı başarısız: {response.error.message if response.error else 'No specific error message'}")
                return render_template('register.html', error="Auth kaydı başarısız. Lütfen tekrar deneyin.")

        except Exception as e:
            print(f"Kullanıcı kaydı sırasında hata oluştu: {e}")
            return render_template('register.html', error=f"Auth kaydı başarısız: {e}. Lütfen tekrar deneyin.")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            if response.user:
                session['user'] = response.user.user_metadata.get('display_name', response.user.email)
                session['user_id'] = response.user.id
                return redirect(url_for('index'))
            else:
                error_message = "Giriş başarısız. Lütfen e-posta ve şifrenizi kontrol edin."
                return render_template('login.html', error=error_message)

        except AuthApiError as e:
            msg = str(e).lower()
            if "email" in msg and "confirm" in msg:
                error_message = "E-posta adresiniz henüz doğrulanmamış. Lütfen e-postanızı kontrol edin ve hesabınızı doğrulayın."
            elif "invalid login credentials" in msg:
                error_message = "Geçersiz giriş bilgileri. Lütfen tekrar deneyin."
            else:
                error_message = f"Giriş başarısız: {str(e)}"

            return render_template('login.html', error=error_message)

    return render_template('login.html')

@app.route("/")
def index():
    user = session.get("user")
    logged_in = user is not None
    return render_template("index.html", user=user, logged_in=logged_in)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/settings')
def settings_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']  
    return render_template('settings.html', username=username)

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


def is_user_banned(user_id):
    response = supabase.table("banned_users").select("*").eq("user_id", user_id).execute()
    return len(response.data) > 0

@app.route("/send_message", methods=["POST"])
def send_message():
    user_id = session.get("user_id")
    
    if not user_id:
        abort(401)
        print("Yetkin yok!")
        
    if is_user_banned(user_id):
        abort(403)
    
    if 'user' not in session or 'user_id' not in session:
        print("ne")
        return "Unauthorized", 401
        
    try:
        data = request.get_json()
        message = data.get("message")
        display_name = session['user']
        user_id = session['user_id']

        supabase.table("messages").insert({
            "user_id": user_id,
            "display_name": display_name,
            "messages": message
        }).execute()

        count_res = supabase.table("messages").select("id", count="exact").execute()
        total_count = count_res.count

        excess = total_count - max_message_limit
        if excess > 0:
            oldest = supabase.table("messages")\
                .select("id")\
                .order("created_at", desc=False)\
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
    res = supabase.table("messages").select("*").order("created_at", desc=False).limit(max_message_limit).execute()
    return jsonify(messages=res.data)

@app.route("/update_username", methods=["POST"])
def update_username():
    new_username = request.form.get("new_username")
    response = supabase.auth.update_user(
        {"data": {"display_name": new_username}}
    )

    if response:
        session['user'] = new_username
        return redirect(url_for("index"))
    else:
        return jsonify({"error": "Update failed"}), 400

@app.route("/change_password", methods=["POST"])
def change_password():
    new_password = request.form.get("new_password")
    response = supabase.auth.update_user(
        {"password": new_password}
    )

    if response:
        return redirect(url_for("index"))
    else:
        return jsonify({"error": "Update failed"}), 400

@app.route('/resend_verify', methods=['POST'])
def resend_verify():
    email = request.form.get('email')
    try:
        supabase.auth.reset_password_for_email(email)
        success_message = "Doğrulama (şifre sıfırlama) e-postası yeniden gönderildi!"
        return render_template('login.html', success=success_message, email=email)
    except Exception as e:
        error_message = f"Doğrulama e-postası gönderilemedi: {str(e)}"
        return render_template('login.html', error=error_message, email=email)

if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host='0.0.0.0', port=port, debug=True)
