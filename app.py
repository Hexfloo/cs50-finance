import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    # Update user's portfolio (each share's price might change)
    userID = session["user_id"]
    userTransactionsFromDB = db.execute(
        "SELECT symbol, SUM(shares) AS shares, price, name, total FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", userID)

    for stock in userTransactionsFromDB:
        currentPrice = lookup(stock["symbol"])["price"]
        currentSymbol = lookup(stock["symbol"])["symbol"]
        db.execute("UPDATE transactions SET price = ? WHERE user_id = ? AND symbol = ?", currentPrice, userID, currentSymbol)

    # Query for user's information to desplay
    cashFromDB = db.execute("SELECT cash FROM users WHERE id = ?", userID)
    currentCash = usd(cashFromDB[0]["cash"])
    # Calculate total equity
    equity = 0
    for share in userTransactionsFromDB:
        equity += int(share["total"])
    equity += int(cashFromDB[0]["cash"])
    equity = usd(equity)
    return render_template("index.html", userPortfolio=userTransactionsFromDB, cash=currentCash, equity=equity)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        # Ensure user inputs a symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol")

        # Lookup quote with lookup() func from helpers.py
        quote = lookup(symbol)
        if not quote:
            return apology("Incorrect symbol")

        # Ensure share value is valid
        shares = request.form.get("shares")
        if not shares:
            return apology("Invalid shares")
        if not shares.isdigit():
            return apology("Invalid shares")
        if int(shares) < 0:
            return apology("Invalid shares")

        shares = int(shares)

        # Check if user can purchase wanted shares
        userID = session["user_id"]
        currentStockPrice = lookup(symbol)["price"]
        amountForShares = currentStockPrice * shares
        # the return from db is a dictionary, to get the amount we need to reach for specific item
        cashFromDB = db.execute("SELECT cash FROM users WHERE id = ?", userID)
        currentCash = cashFromDB[0]["cash"]
        if amountForShares > currentCash:
            return apology("Insufficient funds")

        # Add transaction to transactions table, and update cash of user
        updatedCash = currentCash - amountForShares
        currentTime = datetime.now()
        name = lookup(symbol)["name"]
        total = lookup(symbol)["price"] * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updatedCash, userID)
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, date, total) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   userID, symbol, name, shares, currentStockPrice, currentTime, total)

        flash("Bought!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Query for all user's transactions
    userID = session["user_id"]
    userTransactionsFromDB = db.execute("SELECT * FROM transactions WHERE user_id = ?", userID)

    return render_template("history.html", userPortfolio=userTransactionsFromDB)


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
        return redirect("/")

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        # Ensure user inputs a symbol
        if not request.form.get("symbol"):
            return apology("must provide symbol")

        # Lookup quote with lookup() func from helpers.py
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("Lookup unsuccessful")
        formattedPrice = usd(quote["price"])
        return render_template("quoted.html", quote=quote, formattedPrice=formattedPrice)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        userPassword = request.form.get("password")
        username = request.form.get("username")

        # Ensure username was submitted
        if not username:
            return apology("must provide username")

        # Ensure password was submitted
        if not userPassword:
            return apology("must provide password")

        # Ensure password confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password confirmation")

        # Ensure password and confirmation are equal
        if userPassword != request.form.get("confirmation"):
            return apology("Password and confirmation do not match")

        # If username and password passed all above,
        # Insert new user into users table
        hashedPassword = generate_password_hash(userPassword, method="pbkdf2:sha256", salt_length=4)
        try:
            newUser = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashedPassword)
        except:
            return apology("username already exists")

        # Start user session
        session["user_id"] = newUser
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        userID = session["user_id"]

        # Ensure user inputs a symbol and shares
        if not symbol or not shares:
            return apology("Must select symbol and share amount")

        # Ensure user has stocks of this symbol
        userSymbolsFromDB = db.execute("SELECT symbol FROM transactions WHERE user_id = ?", userID)
        userSymbols = []
        for symbl in userSymbolsFromDB:
            userSymbols.append(symbl["symbol"])
        if symbol not in userSymbols:
            return apology("Symbol not owned")
        sharesFromSymbol = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ?", userID, symbol)
        if sharesFromSymbol[0]["shares"] < shares:
            return apology("Not enough shares from symbol")

        # Update user's cash
        currentStockPrice = lookup(symbol)["price"]
        amountFromShares = currentStockPrice * shares
        cashFromDB = db.execute("SELECT cash FROM users WHERE id = ?", userID)
        currentCash = cashFromDB[0]["cash"]
        updatedCash = currentCash + amountFromShares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updatedCash, userID)

        currentTime = datetime.now()
        name = lookup(symbol)["name"]
        total = currentStockPrice * shares
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, date, total) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   userID, symbol, name, (-1)*shares, currentStockPrice, currentTime, total)

        # Update user's transactions

        flash("Sold!")
        return redirect("/")

    else:
        userID = session["user_id"]
        userSymbolsFromDB = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", userID)
        userSymbols = []
        for symbl in userSymbolsFromDB:
            userSymbols.append(symbl["symbol"])
        return render_template("sell.html", userSymbols=userSymbols)
