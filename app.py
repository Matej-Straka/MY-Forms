import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

import os


from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


@app.route("/", methods=["GET", "POST"])
def form():
    if request.method == "POST":
        db.execute("INSERT INTO responses VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", request.form.get("1"), request.form.get("2"), request.form.get("3"), request.form.get(
            "4"), request.form.get("5"), request.form.get("6"), request.form.get("7"), request.form.get("8"), request.form.get("9"), request.form.get("10"))
        return redirect("/sended")
    else:
        namene = db.execute("SELECT * FROM form")
        return render_template("form.html", name=namene)


@app.route("/sended", methods=["GET", "POST"])
def sended():
    return render_template("sended.html")


@app.route("/home")
@login_required
def index():
    if request.method == "POST":

        return render_template("index.html")

    else:
        responses = db.execute("SELECT * FROM responses")
        names = db.execute("SELECT name FROM form")
        r1 = db.execute("SELECT '1' FROM responses")
        r2 = db.execute("SELECT '2' FROM responses")
        r3 = db.execute("SELECT '3' FROM responses")
        r4 = db.execute("SELECT '4' FROM responses")
        r5 = db.execute("SELECT '5' FROM responses")
        r6 = db.execute("SELECT '6' FROM responses")
        r7 = db.execute("SELECT '7' FROM responses")
        r8 = db.execute("SELECT '8' FROM responses")
        r9 = db.execute("SELECT '9' FROM responses")
        r10 = db.execute("SELECT '10' FROM responses")

        return render_template("index.html", responses=responses, names=names)


@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "POST":
        for i in range(10):
            if request.form.get(f"checkbox_{i + 1}") == "on":
                db.execute("UPDATE form SET hidden = ? WHERE id = ?", '', (i+1))
            else:
                db.execute("UPDATE form SET hidden = ? WHERE id = ?", 'hidden', (i+1))
            if request.form.get(f"name_{i + 1}") != '':
                db.execute("UPDATE form SET name = ? WHERE id = ?", request.form.get(f"name_{i + 1}"), (i+1))

        return redirect("/")

    else:
        return render_template("edit.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/home")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) != 0:
            return apology("used username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("your password does not match", 400)

        # Query database for username
        db.execute("INSERT INTO USERS(username, hash) VALUES(?, ?)", request.form.get(
            "username"), generate_password_hash(request.form.get("password")))
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/home")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        rows = db.execute("SELECT * FROM users")
        if rows == []:
            return render_template("register.html")
        else:
            return redirect("/")