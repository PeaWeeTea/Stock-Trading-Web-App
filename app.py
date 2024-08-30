import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    """Show portfolio of stocks"""

    # Get user's current amount of cash
    user_id = session['user_id']
    cash = round((db.execute("SELECT cash FROM users WHERE id = ?", user_id))[0]['cash'], 2)

    # Get username
    username = (db.execute("SELECT username FROM users WHERE id = ?", user_id))[0]['username']

    # Get user's net worth (value of shares + wallet)
    stocks = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = ?", user_id)
    total_shares_value = 0.0
    holdings = list()
    for stock in stocks:
        current_price = (lookup(stock['symbol']))['price']
        total_shares_value += current_price * stock['shares']
        holding_value = current_price * stock['shares']
        holdings.append({'symbol': stock['symbol'], 'shares': stock['shares'], 'stock_price': usd(current_price), 'holding_value': usd(holding_value)})

    # Get value of stock shares and cash in user's wallet
    total_worth = total_shares_value + cash

    return render_template("index.html", cash=usd(cash), total_worth=usd(total_worth), holdings=holdings, username=username)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == 'POST':

        # Check if user input invalid symbol/no symbol or negative amount of shares
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide a symbol")
        if not shares:
            return apology("must buy 1 or more shares")
        if not shares.isdigit():
            return apology("shares must be integers")

        shares = int(shares)

        if lookup(symbol) == None:
            return apology("symbol is invalid")
        if shares <= 0:
            return apology("must buy 1 or more shares")


        # Lookup how much money the user has
        user_id = session["user_id"]
        user_cash = round(float((db.execute("SELECT cash FROM users WHERE id = ?", user_id))[0]['cash']), 2)

        # Check if user has enough money to buy the shares
        share_price = float((lookup(symbol))['price'])
        total_price = float(share_price * shares)
        print(user_cash)
        print(total_price)
        if (user_cash - total_price) < 0.0:
            return apology("you cannot afford these shares")

        # Purchase the shares
        time = datetime.now()
        db.execute("INSERT INTO purchases (user_id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
                   user_id, symbol.upper(), shares, total_price, time)
        print(db.execute("SELECT symbol FROM stocks WHERE symbol = ?", symbol.upper()))
        if not db.execute("SELECT symbol FROM stocks WHERE symbol = ? AND user_id = ?", symbol.upper(), user_id):
            db.execute("INSERT INTO stocks(user_id, symbol, shares) VALUES (?, ?, ?)", user_id, symbol.upper(), shares)
        else:
            print(db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol.upper()))
            new_shares = shares + (db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol.upper()))[0]['shares']
            db.execute("UPDATE stocks SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, user_id, symbol.upper())

        # Subtract purchase price from user's cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash - total_price, user_id)

        # Redirect user to home screen
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # collect all purchases and sales of the user into a list of dictionaries
    user_id = session['user_id']
    transactions = []

    purchases = db.execute("SELECT time, symbol, shares, price FROM purchases WHERE user_id = ?", user_id)
    for purchase in purchases:
        purchase['transaction_type'] = "Bought"
        transactions.append(purchase)

    sales = db.execute("SELECT time, symbol, shares, price FROM sales WHERE user_id = ?", user_id)
    for sale in sales:
        sale['transaction_type'] = "Sold"
        transactions.append(sale)


    # sort the list of transactions from oldest date to newest
    for transaction in transactions:
        transaction['time'] = datetime.strptime(transaction['time'], "%Y-%m-%d %H:%M:%S")
        # correct the syntax money prints as
        transaction['price'] = usd(transaction['price'])
    transactions = sorted(transactions, key=lambda transaction: transaction['time'])
    for transaction in transactions:
        transaction['time'] = transaction['time'].strftime("%m/%d/%Y, %H:%M:%S")

    # get username
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']

    # plug sorted list of transactions into history.html template
    return render_template("history.html", transactions=transactions, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password")

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
    """Get stock quote."""

    if request.method == 'POST':
        # Check if user input a symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide stock symbol")

        # Render the quoted page and embed the symbol and prices into it
        prices = lookup(symbol)
        if not prices:
            return apology("failure to find stock with your symbol")
        return render_template("quoted.html", prices=prices)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Check if username is empty
        username = request.form.get("username")
        if not username:
            return apology("must provide username")

        # Check if password is empty or passwords don't match
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password:
            return apology("must provide password")
        if password != confirmation:
            return apology("both passwords must be the same")

        # Try to insert username and password hash into database and return apology if username already exists
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        except ValueError:
            return apology("this username already exists")

        # Redirect user to homepage
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session['user_id']

    if request.method == 'POST':

        # Get user inputs symbol and shares
        symbol = str((request.form.get("symbol"))).upper()
        shares = request.form.get("shares")

        # Check user inputs for symbol and shares
        if not symbol:
            return apology("must select a stock")
        if not shares:
            return apology("must enter a number of shares to sell")
        shares = int(shares)

        # Check if user owns any shares and if shares-to-sell is positive int
        if shares <= 0:
            return apology("must sell a positive number of shares")
        if not db.execute("SELECT symbol FROM stocks WHERE symbol = ?", symbol):
            return apology("you do not own shares in this stock")

        # If total shares user has - shares to sell is < 0 then apologise
        total_shares = db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]['shares']
        if (total_shares - shares) < 0:
            message = "you do not own " + str(shares) + " shares to sell"
            return apology(message)


        # Update the tables stocks and sales in finance.db

        # insert the sale into sales table of database
        time = datetime.now()
        price = float(lookup(symbol)['price']) * float(shares)
        db.execute("INSERT INTO sales (user_id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)", user_id, symbol, shares, price, time)
        # subtract shares from stocks table in db
        new_shares = total_shares - shares
        db.execute("UPDATE stocks SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, user_id, symbol)
        # Add the price of selling the stock to user's wallet
        new_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash'] + price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)
        # Delete record from stocks if there are no more shares in the stock
        if int(db.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]['shares']) == 0:
            db.execute("DELETE FROM stocks WHERE user_id = ? AND symbol = ? AND shares = ?", user_id, symbol, 0)

        # Redirect user to homepage
        return redirect("/")


    else:
        # Get the user's stock symbols from their purchases into a list with no duplicates
        symbols_dict = db.execute("SELECT symbol FROM stocks WHERE user_id = ?", user_id)
        symbols = []
        for symbol_dict in symbols_dict:
            symbols.append(symbol_dict['symbol'])
        symbols = set(symbols)

        return render_template("sell.html", symbols=symbols)


@app.route("/profile")
@login_required
def profile():
    user_id = session['user_id']

    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    return render_template("profile.html", username=username)


@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    user_id = session['user_id']

    # Get user's input for new password
    new_password = request.form.get("new_password")
    confirmation = request.form.get("confirmation")

    # check if user input is empty
    if not new_password:
        return apology("must provide new password")
    if new_password != confirmation:
        return apology("both passwords must be the same")

    # change user's password hash in the db
    db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), user_id)

    # Redirect user to log in
    return redirect("/login")

