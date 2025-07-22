
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
import os

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/register_page', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        username = request.form.get("username") 
        
        #var olan kullanıcı adı ve email ile kayıt olma, mail girildiginden emin olma

        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "display_name": username,  
                    "username": username       
                }
            }
        })
        
        if response.user:
            return render_template('login.html', success="Kayıt başarılı! Giriş yapabilirsiniz.")
        else:
            return render_template('register.html', error="Kayıt başarısız. Lütfen tekrar deneyin.")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        #email dogrulaması yapılmadıysa uygun geri bildirim ve error handling eklenecek

        if response.user:
            session['user'] = response.user.user_metadata.get('display_name', response.user.email)
            session['user_id'] = response.user.id
            print("DEBUG | SESSİON:",session)
            return redirect(url_for('index'))
        else:
            error_message = "Giriş başarısız. Lütfen tekrar deneyin."
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


max_message_limit = 200

@app.route("/send_message", methods=["POST"])
def send_message():
    if 'user' not in session or 'user_id' not in session:
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

if __name__ == "__main__":
    app.run(debug=True)
