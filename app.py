from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash, send_from_directory
from supabase import create_client, Client
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
from gotrue.errors import AuthApiError
from flask_caching import Cache
from PIL import Image
import re
from markupsafe import Markup, escape
import sys
import io
import os
import uuid


sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

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

icons_map = defaultdict(dict)

icons_res = supabase.table("community_links").select("*").execute()

for row in icons_res.data:
    icons_map[str(row["community_id"])][row["platform"]] = row["url"]
    
events_map = defaultdict(list)
    
com_events = supabase.table("community_events").select("*").execute()

for row_events in com_events.data:
    raw_time = row_events["time"]
    raw_date_from = row_events["from"]
    raw_date_to = row_events["to"]
    
    parsed_from = datetime.strptime(raw_date_from, "%Y-%m-%d")
    parsed_to = datetime.strptime(raw_date_to, "%Y-%m-%d")
    
    if parsed_from == parsed_to:
        # aynı gün aynı ay
        formatted_from = parsed_from.strftime("%-d %B")
        formatted_to = formatted_from
    elif parsed_from.month == parsed_to.month and parsed_from.year == parsed_to.year:
        # aynı ay içinde farklı gün
        formatted_from = parsed_from.strftime("%-d")
        formatted_to = parsed_to.strftime("%-d %B")
    else:
        # farklı ay (veya yıl)
        formatted_from = parsed_from.strftime("%-d %B")
        formatted_to = parsed_to.strftime("%-d %B")
    if raw_time: 
        parsed_time = datetime.strptime(raw_time, "%H:%M:%S")
        formatted_time = parsed_time.strftime("%H:%M") 
    else:
        formatted_time = None   
    
    events_map[row_events["community_id"]].append({
        "event": row_events["events"],
        "from": formatted_from,
        "to": formatted_to,
        "time": formatted_time
    })


def linkify(text):
    if not text:
        return ""
    
    # Önce özel karakterleri güvenli hale getir
    text = escape(text)
    
    # www. ile başlayanlara http ekle
    text = re.sub(
        r'(^|[^/])(www\.[^\s]+)',
        r'\1<a href="http://\2" target="_blank">\2</a>',
        text
    )
    
    # http:// veya https:// ile başlayan linkler
    text = re.sub(
        r'(https?://[^\s]+)',
        r'<a href="\1" target="_blank">\1</a>',
        text
    )
    
    return Markup(text)

# Jinja'ya filtre olarak ekle
app.jinja_env.filters['linkify'] = linkify


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
    user_id = session.get("user_id")
    role = session.get("role", "user")
    logged_in = user_id is not None

    # Topluluklar
    communities = supabase.table("communities").select("*").execute().data
    com = supabase.table("communities").select("id, owner, title").execute()

    com_list = []
    for c in com.data:
        c["user_owner"] = (str(c["owner"]) == str(user_id))
        com_list.append(c)

    # Etkinlikler -> her request'te taze çek
    events_map = defaultdict(list)
    com_events = supabase.table("community_events").select("*").execute()
    for row_events in com_events.data:
        try:
            raw_time = row_events["time"]
            raw_date_from = row_events["from"]
            raw_date_to = row_events["to"]

            parsed_from = datetime.strptime(raw_date_from[:10], "%Y-%m-%d")
            parsed_to = datetime.strptime(raw_date_to[:10], "%Y-%m-%d")

            if parsed_from == parsed_to:
                formatted_from = parsed_from.strftime("%-d %B")
                formatted_to = formatted_from
            elif parsed_from.month == parsed_to.month and parsed_from.year == parsed_to.year:
                formatted_from = parsed_from.strftime("%-d")
                formatted_to = parsed_to.strftime("%-d %B")
            else:
                formatted_from = parsed_from.strftime("%-d %B")
                formatted_to = parsed_to.strftime("%-d %B")

            formatted_time = None
            if raw_time:
                try:
                    parsed_time = datetime.strptime(raw_time, "%H:%M:%S")
                    formatted_time = parsed_time.strftime("%H:%M")
                except ValueError:
                    formatted_time = raw_time[:5]  # 'HH:MM'

            events_map[row_events["community_id"]].append({
                "event": row_events["events"],
                "from": formatted_from,
                "to": formatted_to,
                "time": formatted_time
            })
        except Exception as e:
            print(f"Etkinlik parse hatası: {e}")

    # Kullanıcının toplulukları
    user_communities = []
    if user_id:
        user_communities = supabase.table("communities").select("id").eq("owner", str(user_id)).execute().data
        profile = supabase.table("profiles").select("id, role").eq("id", str(user_id)).single().execute()
        if profile.data:
            session["role"] = profile.data["role"]

    has_community = len(user_communities) > 0

    return render_template( "index.html", user_id=user_id, logged_in=logged_in, communities=communities, icons_map=dict(icons_map), events_map=events_map, com_list=com_list, role=role, has_community=has_community)


@app.route("/community/new", methods=["GET", "POST"])
def create_community():
    user_id = session.get("user_id")
    if not user_id:
        return "Giriş yapmanız gerekli", 403

    if request.method == "POST":
        title = request.form.get("title")
        desc = request.form.get("long_desc")
        category = request.form.get("category")
        tagline = request.form.get("tagline")

        # Yeni community oluştur
        new_com = supabase_admin.table("communities").insert({
            "title": title,
            "long_desc": desc,
            "category": category,
            "tagline": tagline,
            "owner": str(user_id)
        }).execute()

        com_id = new_com.data[0]["id"]

        # Fotoğraf yükleme (varsa)
        file = request.files.get("image")
        if file and file.filename:
            file_bytes = file.read()
            filename = f"{com_id}_{uuid.uuid4().hex}{os.path.splitext(file.filename)[1]}"
            supabase_admin.storage.from_("logolar").upload(
                filename,
                file_bytes,
                {"content-type": file.content_type}
            )
            public_url = supabase_admin.storage.from_("logolar").get_public_url(filename)
            supabase_admin.table("communities").update({
                "image_url": public_url,
                "image_path": filename
            }).eq("id", str(com_id)).execute()

        # Linkler
        link_ids = request.form.getlist("link_id[]")
        platforms = request.form.getlist("platform[]")
        urls = request.form.getlist("url[]")

        for lid, p, u in zip(link_ids, platforms, urls):
            if not p.strip() or not u.strip():
                continue
            supabase_admin.table("community_links").insert({
                "community_id": str(com_id),
                "platform": p,
                "url": u
            }).execute()

        # Etkinlikler
        event_ids = request.form.getlist("event_id[]")
        event_starts = request.form.getlist("event_start[]")
        event_times = request.form.getlist("event_time[]")
        event_ends = request.form.getlist("event_end[]")
        event_descs = request.form.getlist("event_desc[]")

        for eid, start, st_time, end, desc in zip(event_ids, event_starts, event_times, event_ends, event_descs):
            if not start or not end or not desc.strip():
                continue
            supabase_admin.table("community_events").insert({
                "community_id": str(com_id),
                "from": start,
                "to": end,
                "time": st_time if st_time else None,
                "events": desc
            }).execute()

        flash("Topluluk başarıyla oluşturuldu", "success")
        return redirect(url_for("index"))

    return render_template("create_community.html")



@app.route("/community/<uuid:com_id>/upload_image", methods=["POST"])
def upload_image(com_id):
    user_id = session.get("user_id")
    role = session.get("role", "user")

    # Yetki kontrolü → sadece owner yükleyebilir
    com = supabase.table("communities").select("owner").eq("id", str(com_id)).single().execute()
    if not com.data or str(com.data["owner"]) != str(user_id):
        return "Yetkiniz yok", 403

    file = request.files.get("image")
    if not file:
        return "Dosya yok", 400
    
    file_bytes = file.read()
    
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
    except:
        return "Geçersiz resim dosyası",400

    # Dosya ismini benzersiz yap (uuid ile)
    filename = f"{com_id}_{uuid.uuid4().hex}{os.path.splitext(file.filename)[1]}"

    # Storage'a yükle (private bucket, admin client ile)
    res = supabase_admin.storage.from_("logolar").upload(
        filename,
        file_bytes,
        {"content-type": file.content_type}
    )

    public_url = supabase_admin.storage.from_("logolar").get_public_url(filename)
    
    supabase_admin.table("communities").update({
        "image_url": public_url
    }).eq("id", str(com_id)).execute()

    return redirect(url_for("index"))


@app.route("/community/<uuid:com_id>/edit", methods=["GET", "POST"])
def edit_community(com_id):
    user_id = session.get("user_id")

    com = supabase.table("communities").select("*").eq("id", str(com_id)).single().execute()
    if not com.data or str(com.data["owner"]) != str(user_id):
        return "Yetkiniz yok", 403

    links = supabase.table("community_links").select("*").eq("community_id", str(com_id)).execute().data
    events = supabase.table("community_events").select("*").eq("community_id", str(com_id)).execute().data

    if request.method == "POST":
        title = request.form.get("title")
        desc = request.form.get("long_desc")
        category = request.form.get("category")
        tagline = request.form.get("tagline")

        # Metin alanlarını güncelle
        supabase_admin.table("communities").update({
            "title": title,
            "long_desc": desc,
            "category": category,
            "tagline": tagline
        }).eq("id", str(com_id)).execute()

        # Fotoğraf güncelle
        file = request.files.get("image")
        if file and file.filename:
            old_path = com.data.get("image_path")
            if old_path:
                try:
                    supabase_admin.storage.from_("logolar").remove([old_path])
                except:
                    pass
            file_bytes = file.read()
            filename = f"{com_id}_{uuid.uuid4().hex}{os.path.splitext(file.filename)[1]}"
            supabase_admin.storage.from_("logolar").upload(filename, file_bytes, {"content-type": file.content_type})
            public_url = supabase_admin.storage.from_("logolar").get_public_url(filename)
            supabase_admin.table("communities").update({
                "image_url": public_url,
                "image_path": filename
            }).eq("id", str(com_id)).execute()

        # Linkler
        link_ids = request.form.getlist("link_id[]")
        platforms = request.form.getlist("platform[]")
        urls = request.form.getlist("url[]")

        # Önce eski linkleri sil
        supabase_admin.table("community_links").delete().eq("community_id", str(com_id)).execute()

        for lid, p, u in zip(link_ids, platforms, urls):
            if not p.strip() or not u.strip():
                continue
            supabase_admin.table("community_links").insert({
                "community_id": str(com_id),
                "platform": p,
                "url": u
            }).execute()

        # Etkinlikler
        event_ids = request.form.getlist("event_id[]")
        event_starts = request.form.getlist("event_start[]")
        event_times = request.form.getlist("event_time[]")
        event_ends = request.form.getlist("event_end[]")
        event_descs = request.form.getlist("event_desc[]")

        # Önce eski etkinlikleri sil
        supabase_admin.table("community_events").delete().eq("community_id", str(com_id)).execute()

        for eid, start, st_time, end, desc in zip(event_ids, event_starts, event_times, event_ends, event_descs):
            if not start or not end or not desc.strip():
                continue
            supabase_admin.table("community_events").insert({
                "community_id": str(com_id),
                "from": start,
                "to": end,
                "time": st_time if st_time else None,
                "events": desc
            }).execute()

        flash("Değişiklikler başarıyla kaydedildi", "success")
        return redirect(url_for("index"))

    return render_template("edit_community.html", community=com.data, links=links, events=events)



@app.route("/community/<uuid:com_id>/add_link", methods=["POST"])
def add_link(com_id):
    user_id = session.get("user_id")

    # Owner kontrolü
    com = supabase.table("communities").select("owner, title").eq("id", str(com_id)).single().execute()
    if not com.data or str(com.data["owner"]) != str(user_id):
        return "Yetkiniz yok", 403

    platform = request.form.get("platform")
    url = request.form.get("url")

    if not platform or not url:
        return "Eksik bilgi", 400

    # Supabase'e kaydet
    supabase_admin.table("community_links").insert({
        "community_id": str(com_id),
        "platform": platform,
        "url": url
    }).execute()

    flash("Link başarıyla eklendi", "success")
    return redirect(url_for("edit_community", com_id=com_id))



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

@app.route("/cerez")
def cerez_page():
    return render_template('cerez.html')

@app.route("/gizlilik")
def gizlilik_page():
    return render_template('gizlilik.html')

@app.route("/kullanım_kosul")
def kullanım_kosul_page():
    return render_template('kullanım_kosul.html')

@app.route('/ads.txt')
def ads():
    return send_from_directory('.','ads.txt')



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

@app.route("/password_change", methods=["GET", "POST"])
def password_change():
    if request.method == "POST":
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")
        access_token = request.form.get("access_token")
        refresh_token = request.form.get("refresh_token")
        
        if password != password_confirm:
            return render_template("password_reset_password.html", 
                                 error="Şifreler eşleşmiyor.",
                                 access_token=access_token,
                                 refresh_token=refresh_token)
        
        if not access_token:
            return render_template("password_reset_password.html", 
                                 error="Geçersiz token.",
                                 access_token=access_token,
                                 refresh_token=refresh_token)
        
        try:
            if refresh_token:
                supabase.auth.set_session(access_token, refresh_token)
            
            supabase.auth.update_user({"password": password})
            
            return render_template("password_reset_password.html", 
                                 success="Şifre başarıyla değiştirildi! Giriş yapabilirsiniz.")
                                 
        except Exception as e:
            return render_template("password_reset_password.html", 
                                 error=f"Şifre güncellenirken hata: {e}",
                                 access_token=access_token,
                                 refresh_token=refresh_token)
    
    return render_template("password_reset_password.html")
    
#if __name__ == "__main__":
#    app.run(debug=True)
def get_any_admin_id():
    """Herhangi bir admin ID'si döndürür"""
    try:
        # Tüm adminleri bul
        response = supabase.table('users').select('id').eq('role', 'admin').execute()
        
        if response.data and len(response.data) > 0:
            # İlk adminin ID'sini döndür
            return response.data[0]['id']
        else:
            # Eğer users tablosu yoksa, auth tablosundan bak
            response = supabase.from_('auth.users').select('id').eq('raw_user_meta_data->>role', 'admin').execute()
            if response.data and len(response.data) > 0:
                return response.data[0]['id']
            
        print("Hiç admin bulunamadı!")
        return None
        
    except Exception as e:
        print(f"Hata: {e}")
        return None

# Kullanım:
admin_id = get_any_admin_id()
if admin_id:
    print(f"Bulunan admin ID: {admin_id}")
else:
    print("Admin bulunamadı!")