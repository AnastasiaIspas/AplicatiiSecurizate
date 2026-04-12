from flask import Flask, request, session, redirect, url_for, render_template, flash
import database
import hashlib
import time

app = Flask(__name__)

# VULNERABIL 4.5: secret key slab si hardcodat
app.secret_key = "secret123"

# VULNERABIL 4.5: cookie-uri fara protectii
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None


# ------------------------------------------------------------------ #
#  INDEX
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# ------------------------------------------------------------------ #
#  REGISTER
# ------------------------------------------------------------------ #
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # VULNERABIL 4.1: nicio validare de politica parola
        if not email or not password:
            flash("Completeaza toate campurile.", "error")
            return render_template("register.html")

        if database.get_user_by_email(email):
            flash("Email-ul exista deja.", "error")
            return render_template("register.html")

        # VULNERABIL 4.2: parola stocata ca MD5 (hash slab, fara salt)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        database.create_user(email, password_hash)

        database.log_action(None, "REGISTER", "auth", email, request.remote_addr)
        flash("Cont creat! Te poti autentifica.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ------------------------------------------------------------------ #
#  LOGIN
# ------------------------------------------------------------------ #
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # VULNERABIL 4.3: nicio limitare a numarului de incercari
        user = database.get_user_by_email(email)

        if not user:
            # VULNERABIL 4.4: mesaj diferit -> user enumeration
            flash("Utilizatorul nu exista!", "error")
            return render_template("login.html")

        password_hash = hashlib.md5(password.encode()).hexdigest()
        if user["password_hash"] != password_hash:
            # VULNERABIL 4.4: mesaj diferit -> user enumeration
            flash("Parola gresita!", "error")
            database.log_action(user["id"], "LOGIN_FAIL", "auth", str(user["id"]), request.remote_addr)
            return render_template("login.html")

        # VULNERABIL 4.5: sesiune fara expirare, fara rotatie token
        session["user_id"] = user["id"]
        session["email"]   = user["email"]
        session["role"]    = user["role"]

        database.log_action(user["id"], "LOGIN", "auth", str(user["id"]), request.remote_addr)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ------------------------------------------------------------------ #
#  LOGOUT
# ------------------------------------------------------------------ #
@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    # VULNERABIL 4.5: sesiunea nu e invalidata server-side
    # (cookie-ul sters doar pe client, poate fi reutilizat)
    session.clear()
    if user_id:
        database.log_action(user_id, "LOGOUT", "auth", str(user_id), request.remote_addr)
    return redirect(url_for("login"))


# ------------------------------------------------------------------ #
#  DASHBOARD
# ------------------------------------------------------------------ #
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    tickets = database.get_tickets_by_user(session["user_id"])
    return render_template("dashboard.html", tickets=tickets)


# ------------------------------------------------------------------ #
#  CREARE TICKET
# ------------------------------------------------------------------ #
@app.route("/ticket/new", methods=["GET", "POST"])
def new_ticket():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title       = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity    = request.form.get("severity", "LOW")

        if not title:
            flash("Titlul este obligatoriu.", "error")
            return render_template("new_ticket.html")

        database.create_ticket(title, description, severity, session["user_id"])
        database.log_action(session["user_id"], "CREATE_TICKET", "ticket", title, request.remote_addr)
        flash("Ticket creat cu succes!", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_ticket.html")


# ------------------------------------------------------------------ #
#  FORGOT PASSWORD
# ------------------------------------------------------------------ #
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    token_preview = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user  = database.get_user_by_email(email)

        if user:
            # VULNERABIL 4.6: token predictibil bazat pe timestamp
            token = str(int(time.time()))
            database.save_reset_token(user["id"], token)

            # In productie s-ar trimite pe email; aici il afisam direct
            # pentru a demonstra vulnerabilitatea
            token_preview = token
            flash(f"Token de resetare generat (simulare email): {token}", "warning")
        else:
            flash("Daca emailul exista, vei primi instructiuni.", "info")

    return render_template("forgot_password.html", token_preview=token_preview)


# ------------------------------------------------------------------ #
#  RESET PASSWORD
# ------------------------------------------------------------------ #
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "")

    if request.method == "POST":
        token        = request.form.get("token", "")
        new_password = request.form.get("password", "")

        reset = database.get_reset_token(token)
        if not reset:
            flash("Token invalid.", "error")
            return render_template("reset_password.html", token=token)

        # VULNERABIL 4.6: token reutilizabil (nu e marcat ca folosit)
        # VULNERABIL 4.6: nicio verificare de expirare
        # VULNERABIL 4.1: nicio validare a noii parole
        password_hash = hashlib.md5(new_password.encode()).hexdigest()
        database.update_password(reset["user_id"], password_hash)

        database.log_action(reset["user_id"], "PASSWORD_RESET", "auth", str(reset["user_id"]), request.remote_addr)
        flash("Parola a fost resetata cu succes!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# ------------------------------------------------------------------ #
#  RUN
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    database.init_db()
    print("\n[!] Versiunea VULNERABILA (v1) pornita pe http://127.0.0.1:5000")
    print("[!] Aceasta versiune contine vulnerabilitati INTENTIONATE pentru demonstratie.\n")
    app.run(debug=True, port=5000)
