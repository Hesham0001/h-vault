import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet 

from additions import error,load_or_create_key

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///vault.db")

key = load_or_create_key()
f = Fernet(key)

@app.route("/")
def index():
    """Show accounts"""
    if not session.get("user_id"):
        return redirect("/login")
    user_id = session["user_id"]
    accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", user_id) 
    for account in accounts:
        # Decrypt the account password before displaying it
        account["password_encrypted"] = f.decrypt(account["password_encrypted"]).decode()
    return render_template("index.html", accounts=accounts)     

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return error("Must valid username")
        elif not request.form.get("password"):
            return error("Must valid password")

        if not request.form.get("confirmation"):
            return error("Must write same password to confirmation")

        if request.form.get("password") != request.form.get("confirmation"):
            return error("passwords do not match")

        user = request.form.get("username")
        password = generate_password_hash(request.form.get(
            "password"), method='scrypt', salt_length=16)

        rows = db.execute("SELECT * FROM users WHERE username = ?", user)
        if len(rows) != 0:
            return error("The username is already used.")

        new_id = db.execute("INSERT INTO users (username, hash, hint) VALUES(?, ?, ?)",user,password,request.form.get("hint") or None)

        session["user_id"] = new_id
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return error("must valid username")

        elif not request.form.get("password"):
            return error("must valid password")

        username = request.form.get("username")
        password = request.form.get("password")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            hint = rows[0]["hint"] if len(rows) == 1 else None
            if hint:
                return error(f"Invalid password. <br><br><span style='color: green; font-weight: bold;'>Hint: {hint}</span>")
            return error("invalid username and/or password")

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")

@app.route("/confirm_deletion")
def confirm_deletion():
    if not session.get("user_id"):
        return redirect("/login")
    return render_template("confirm_deletion.html")

@app.route("/deletion", methods=["POST"])
def deletion():
    if not session.get("user_id"):
        return redirect("/login")

    password = request.form.get("password")

    row = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
    if not row or not check_password_hash(row[0]["hash"], password):
        return error("Password incorrect")

    db.execute("DELETE FROM accounts WHERE user_id = ?", session["user_id"])
    db.execute("DELETE FROM users WHERE id = ?", session["user_id"])
    session.clear()
    return redirect("/")



@app.route("/add_account", methods=["GET", "POST"])
def add_account():
    """Add account"""
    if not session.get("user_id"):
        return redirect("/login")

    if request.method == "POST":
        if not request.form.get("platform"):
            return error("Must valid platform name")
        elif not request.form.get("account_username"):
            return error("Must valid account username")
        elif not request.form.get("account_password"):
            return error("Must valid account password")

        user_id = session["user_id"]
        platform = request.form.get("platform")
        account_username = request.form.get("account_username")
        account_password = f.encrypt(request.form.get("account_password").encode())

        db.execute("INSERT INTO accounts (user_id, platform, account_username, password_encrypted) VALUES(?, ?, ?, ?)",
                   user_id, platform, account_username, account_password)

        flash("Account added successfully!")
        return redirect("/")

    else:
        return render_template("add_account.html")

@app.route("/delete_account", methods=["POST"])
def delete_account():
    """Delete account"""
    db.execute("DELETE FROM accounts WHERE id = ?", request.form.get("account_id"))
    return redirect("/")

@app.route("/clear", methods=["POST"])
def clear():
    """Clear all accounts"""
    user_id = session["user_id"]
    db.execute("DELETE FROM accounts WHERE user_id = ?", user_id)
    return redirect("/")

@app.route("/generate")
def generate():
    if not session.get("user_id"):
        return redirect("/login")
    return render_template("generate.html")

@app.route("/be_safe")
def be_safe():  
    if not session.get("user_id"):
        return redirect("/login")
    return render_template("be_safe.html")

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=True)