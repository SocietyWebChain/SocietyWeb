from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from supabase import create_client, Client
from dotenv import load_dotenv
import re
import os
import datetime
import dns.resolver
import socket
from gotrue.errors import AuthApiError
from flask_caching import Cache

load_dotenv()
 
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

max_message_limit = 200

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

@cache.memoize(timeout=60)
def is_user_banned(user_id):
    response = supabase.table("banned_users").select("*").eq("user_id", user_id).execute()
    
    return len(response.data) > 0
@app.context_processor
def inject_logged_in():
    return dict(logged_in='user' in session)

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
        
        if not email or not password or not username:
            return render_template('register.html', error="Tüm alanları doldurun.")
        
        email_check = supabase_admin.table("profiles").select("id").eq("email", email).execute()
        if email_check.data:
            return render_template('register.html', error="Bu e-posta zaten kayıtlı.")
        
        username_check = supabase_admin.table("profiles").select("id").eq("username", username).execute()
        if username_check.data:
            return render_template('register.html', error="Bu kullanıcı adı zaten alınmış.")
        
        try:
            response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username
                    }
                }
            })
            
            if hasattr(response, 'user') and response.user:
                return render_template('login.html', success="Kayıt başarılı! Email onaylayıp giriş yapabilirsiniz.")
            else:
                error_message = "Auth kaydı başarısız. Lütfen tekrar deneyin."
                if hasattr(response, 'error') and response.error:
                    if hasattr(response.error, 'message'):
                        error_message = f"Kayıt başarısız: {response.error.message}"
                    else:
                        error_message = f"Kayıt başarısız: {str(response.error)}"
                
                print(f"Auth kaydı başarısız: {error_message}")
                return render_template('register.html', error=error_message)
                
        except Exception as e:
            print(f"Kullanıcı kaydı sırasında hata oluştu: {e}")
            return render_template('register.html', error="Kayıt sırasında hata oluştu. Lütfen tekrar deneyin.")
    
    return render_template('register.html')

@app.route('/password_reset_password', methods=['GET'])
def password_reset_password():
    return render_template('password_reset_password.html')

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
                result = supabase.table("profiles").select("username").eq("id", response.user.id).single().execute()
                display_name = result.data['username']
                session['display_name'] = display_name
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
    if 'user_id' not in session or 'display_name' not in session:
        return jsonify(error="Unauthorized"), 401

    try:
        data = request.get_json()
        message = data.get("message")
        display_name = session['display_name']
        user_id = session['user_id']

        supabase.rpc("add_message_and_cleanup", {
            "p_user_id": user_id,
            "p_display_name": display_name,
            "p_message": message,
            "p_max_limit": max_message_limit
        }).execute()

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
    user_id = session.get("user_id")


    auth_response = supabase.auth.update_user(
        {"data": {"display_name": new_username}}
    )
    if not auth_response:
        return jsonify({"error": "Auth metadata update failed"}), 400

    update_response = supabase.table("profiles").update({
        "username": new_username
    }).eq("id", user_id).execute()

    if not update_response.data:
        return jsonify({"error": "Profiles update failed"}), 400

    session['display_name'] = new_username

    return redirect(url_for("index"))


@app.route("/change_password", methods=["POST"])
def change_password():
    new_password = request.form.get("new_password")

    response = supabase.auth.update_user(
        {"password": new_password}
    )

    if not response:
        return jsonify({"error": "Password update failed"}), 400

    return redirect(url_for("index"))

@app.route('/resend_verify', methods=['GET', 'POST'])
def resend_verify():
    error = ""
    success = ""
    if request.method == "POST":
        email = request.form.get('email')
        if not email:
            return render_template('login.html', error="E‑posta adresi gereklidir.")

        try:
            response = supabase.auth.resend({
                "type": "signup",
                "email": email,
                "options": {
                    "email_redirect_to": "https://universitetopluluklari.com/login",
                },
            })
            success = "Doğrulama maili başarıyla gönderildi."
        except Exception as e:
            error = f"Bir hata oluştu: {e}"

        return render_template('login.html', error=error, success=success)
    return redirect(url_for('login'))
                                 
@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == "POST":
        return render_template('index')

    return render_template('password_reset_email.html')

@app.route('/resetting_password', methods=['GET', 'POST'])
def resetting_password():
    email = request.form.get('email')
    try:
        supabase.auth.reset_password_for_email(email)
        flash("Şifre sıfırlama e-postası gönderildi!", "success")
    except Exception as e:
        print(e)
        flash("Bir hata oluştu. Lütfen tekrar deneyin.", "error")
    return redirect(url_for('login'))

@app.route('/password_change', methods=['GET', 'POST'])
def password_change():
        if request.method == "POST":
        email = request.form.get('email')
        
        try:
            redirect_url = request.url_root + 'password_change'
            supabase.auth.reset_password_for_email(
                email, 
                {"redirect_to": redirect_url}
            )
            success_message = "Şifre sıfırlama e-postası gönderildi! E-postanızı kontrol edin."
            return render_template('login.html', success=success_message, email=email)
            
        except Exception as e:
            error_message = f"E-posta gönderilemedi: {str(e)}"
            return render_template('login.html', error=error_message, email=email)
    
    return render_template('password_reset.html')


@app.route("/password_change", methods=["GET", "POST"])
def password_change():
    if request.method == "GET":
        # URL parametrelerinden token bilgilerini al
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        
        if access_token and refresh_token:
            try:
                supabase.auth.set_session(access_token, refresh_token)
                return render_template("password_reset.html", 
                                     access_token=access_token,
                                     refresh_token=refresh_token)
            except Exception as e:
                return render_template("password_reset.html", 
                                     error=f"Token doğrulama hatası: {e}")
        else:
            # Hash'ten token alınacaksa normal template'i döndür
            return render_template("password_reset.html")

    if request.method == "POST":
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")
        access_token = request.form.get("access_token")
        refresh_token = request.form.get("refresh_token")
        
        # Şifre eşleşme kontrolü
        if password != password_confirm:
            return render_template("password_reset.html", 
                                 error="Şifreler eşleşmiyor.",
                                 access_token=access_token,
                                 refresh_token=refresh_token)
        
        # Token kontrolü
        if not access_token:
            return render_template("password_reset.html", 
                                 error="Geçersiz token.",
                                 access_token=access_token,
                                 refresh_token=refresh_token)
        
        try:
            # Session'ı ayarla
            if refresh_token:
                supabase.auth.set_session(access_token, refresh_token)
            
            # Şifreyi güncelle
            supabase.auth.update_user({"password": password})
            
            return render_template("password_reset.html", 
                                 success="Şifre başarıyla değiştirildi! Giriş yapabilirsiniz.")
                                 
        except Exception as e:
            return render_template("password_reset.html", 
                                 error=f"Şifre güncellenirken hata: {e}",
                                 access_token=access_token,
                                 refresh_token=refresh_token)
    
    return render_template("password_reset.html")
    
#if __name__ == "__main__":
#    app.run(debug=True)
