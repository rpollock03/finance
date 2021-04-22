import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd



# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached. Whenever we make request from server it goes to
# server rather than cache. Fresh data each time.
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
# basically links python code to the sql database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
#if not os.environ.get("API_KEY"):
    #raise RuntimeError("API_KEY not set")


# login required for every route. User must be logged in in order to access page
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # the following code retrieves cash balance, stock symbol/name, quantity & buyprice ie info from databases
    userDetails = db.execute("SELECT cash FROM users WHERE id = :id", id=session.get("user_id"))
    holdings = db.execute("SELECT * FROM transactions WHERE userID = :id AND currentHolding > 0", id=session.get("user_id"))
    balance = userDetails[0]["cash"]
    portfolioValue=balance
    # SELECT returns a dict from the database which we are passing through to HTML. Need to use a loop in order to
    # use the lookup function on each holding to find current price
    for stock in holdings:
        # append new key-value pairs to each dict item
        stock['currentPrice']=lookup(stock["symbol"])["price"]
        stock['holdingValue']=stock['currentPrice']*stock['currentHolding']
        # add the value of the holding to portfolioValue
        portfolioValue+=stock['holdingValue']
    # print(holdings) should now show each item in dictionary has 2 new key-value pairs - currentPrice and holdingValue
    return render_template("index.html",holdings=holdings, balance=balance, portfolioValue=portfolioValue)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # if POST then user has submitted buy form
    if request.method=="POST":
        # ensure inputs are valid and assign to variables
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Please select a stock",400)
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Quantity must be a postive number",400)
        if shares < 1:
            return apology("Please select valid amount of stock to buy",400)

        # lookup latest details of stock through lookup/API. Returns dict with price, symbol, name
        stockInfo = lookup(symbol)
        if not stockInfo:
            return apology("Stock doesn't exist",400)
        # check current user can afford the stock
        userInfo = db.execute("SELECT cash FROM users WHERE id = :id",id=session.get("user_id"))
        balance = userInfo[0]["cash"]
        totalPrice=stockInfo['price'] * shares
        if balance < totalPrice:
            return apology("You can't afford this!",400)
        # update user balance to reflect purchase
        updatedBalance = balance - totalPrice
        updatedUserInfo=db.execute("UPDATE users SET cash = :newCash WHERE id=:id", newCash= updatedBalance, id=session.get("user_id"))
        if not updatedUserInfo:
            return apology("Error buying stock",400)
        # add to holdings records INSERT INTO. Using slash to continue statement onto next line.
        result = db.execute("INSERT INTO transactions (userID, stockName, dateTime, price, shares, symbol, currentHolding, transType)\
        VALUES(:userID, :stockName, :dateTime, :price, :shares, :symbol, :currentHolding, :transType)", userID=session.get("user_id"),\
        stockName=stockInfo['name'], dateTime=datetime.now(), price=stockInfo['price'], shares=shares, symbol=symbol, currentHolding=shares, transType='Buy')
        flash('You successfully bought shares')
        return redirect(url_for('index'))
    # if GET request then blank form is being requested.
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    # Get username from HTTP request. Remember .args for GET request, .form for POST
    requestedUserName=request.args.get("username")
    # create bool and set default to true
    usernameAvailable=True
    #if SELECT query returns nothing, then we know username hasn't been taken.
    userName=db.execute("SELECT * FROM users WHERE userName=:q",q=requestedUserName)
    if not userName:
        return jsonify(usernameAvailable)
    #if there is a record for that username, then the username is taken and we pass that back.
    usernameAvailable=False
    return jsonify(usernameAvailable)

@app.route("/settings", methods=["GET", "POST"])
@login_required
# WE USE .ARGS FOR GET REQUESTS FORM FOR POST REQUESTS
def changepw():
    if request.method=="POST":
        if request.form.get("newPassword"):
            newPassword= generate_password_hash(request.form.get("newPassword"))
            updatePassword=db.execute("UPDATE users SET hash=:newHash WHERE id=:id", newHash=newPassword,id=session.get("user_id"))
            if not updatePassword:
                return apology("error updating password", 400)
            flash('Password changed')
            return redirect(url_for('index'))
    else:
        return render_template("settings.html")

@app.route("/deposit", methods=["POST"])
def deposit():
    addCash=float(request.form.get("addCash"))
    userInfo=db.execute("SELECT cash FROM users WHERE ID=:userID",userID=session.get("user_id"))
    currentBalance=userInfo[0]["cash"]
    newBalance=round((addCash+currentBalance),2)
    updateBalance=db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=newBalance, id=session.get("user_id"))
    if not updateBalance:
        return apology("error",400)
    # add to transactions
    result = db.execute("INSERT INTO transactions (userID, dateTime, transType)\
    VALUES(:userID, :dateTime, :transType)", userID=session.get("user_id"), dateTime=datetime.now(), transType='Deposit')
    flash('Deposit Successful')
    return redirect(url_for('index'))

# checkpw is validating password during register
@app.route("/checkpw",methods=["GET"])
def checkpw():
    confirmation=request.args.get("conf")
    newPassword=request.args.get("new")
    validation = True
    if newPassword==confirmation:
        print ("PASS MATCH SUCCESS")
        return jsonify(validation)
    else:
        validation = False
        return jsonify(validation)

# checkPassword checks LOGIN password is correct
@app.route("/checkPassword",methods=["GET"])
def checkPassword():
    password=request.args.get("password")
    username=request.args.get("username")
    userInfo=db.execute("SELECT hash FROM users WHERE username=:username",username=username)
    hashedPasswordOnFile=userInfo[0]["hash"]
    # checkpasswordhash function imported, compares hashed password 1st parameter with string parameter 2nd parameter
    validation = check_password_hash(hashedPasswordOnFile,password)
    return jsonify(validation)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions= db.execute("SELECT * FROM transactions WHERE userID=:userID", userID=session.get("user_id"))
    return render_template("history.html",transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        # remember, request.form retrieves key value pairs http (args for get request)
        # .get retrives specific one. so we access user submitted value assigned to username in form
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)


        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    """Get stock quote."""
    # if POST request then form submitted and we need to return the quote
    if request.method =="POST":
        # get the name of the stock user is requesting quote for
        stockSymbol = request.form.get("symbol")
        if not stockSymbol:
            return apology("Please select a stock",400)
        # use lookup function to assign latest details of stock to quote
        quote = lookup(stockSymbol)
        if not quote:
            return apology("Stock doesn't exist",400)
        # quote returns a dict ie dict = {'name':'value', 'name':'value',...}
        # we access via dict['Name'] and pass to render_template, using usd() function to normalize value
        return render_template("quoted.html",name=quote['name'], price=usd(quote['price']), symbol=quote['symbol'])
  # if GET request then form is being requested.
    if request.method == "GET":
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # if a form has been submitted (ie received via POST)
    if request.method == "POST":
        # check username/password not blank and assign to variables
        userName= request.form.get("username")
        password = request.form.get("password")
        if not userName or not password:
            return apology("must provide username and password",400)
        # check passwords match
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("passwords do not match",400)
        # hash password and add user details to database via INSERT QUERY
        hashedPassword = generate_password_hash(password)
        # because table includes autoincrementing primary key, insert returns value of new row's primary key
        # userName has UNIQUE constraint, if taken newUserID will fail
        # the :placeholders protect against SQL injection attacks.
        newUserID = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username = userName, hash=hashedPassword)
        if not newUserID:
            return apology("Sorry, this username is already taken",400)
        # Log user in automatically
        session["user_id"] = newUserID
        flash('You successfully registered')
        return redirect(url_for('index'))
    # else if it was a GET request, it means they were redirected to the form, and data not been submitted yet.
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # if GET request retrieve stock holdings (transactions w/ holdings>0) to populate select menu
    if request.method == "GET":
        holdings=db.execute("SELECT transID, stockName, symbol, currentHolding FROM transactions WHERE userID=:userID AND currentHolding>0", userID=session.get("user_id"))
        return render_template("sell.html",holdings=holdings)
    # if POST process sell order
    if request.method=="POST":
        # sellStock is transID passed as value from select menu
        # form validation
        try:
            sellStock = int(request.form.get("symbol"))
        except:
            return apology("Please select a stock",400)
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Quantity must be a postive number",400)
        if shares<1:
            return apology("Quantity must be a positive number",400)

        # get the data we need from SQL database
        holdingInfo=db.execute("SELECT * FROM transactions WHERE transID=:transID",transID=sellStock)
        userInfo=db.execute("SELECT cash FROM users WHERE ID=:userID",userID=session.get("user_id"))
        cash=userInfo[0]["cash"]
        symbol=holdingInfo[0]["symbol"]
        sellPrice=(lookup(symbol))["price"]
        stockName=holdingInfo[0]["stockName"]
        totalSellValue=sellPrice*shares
        currentlyHeld=holdingInfo[0]["currentHolding"]

        if currentlyHeld<shares:
            return apology("You don't have enough of that stock to sell",400)

        # update user's cash balance with the value of the sale
        updatedCash=db.execute("UPDATE users SET cash=:newCash WHERE id=:id",\
                        newCash=cash + totalSellValue,id=session.get("user_id"))

        #update transactions field 'currentHolding' which keeps track of how many shares user has at any time
        updatedHolding=db.execute("UPDATE transactions SET currentHolding=:newHolding WHERE transID=:transID",\
                                    newHolding=currentlyHeld-shares ,transID=sellStock)

        #record the sell transaction by adding new line into transactions
        newSell=db.execute("INSERT INTO transactions (userID, stockName, symbol, price, dateTime, shares, transType)\
                                        VALUES(:userID,:stockName, :symbol, :price, :dateTime, :shares, :transType)",\
                                        userID=session.get("user_id"), stockName=stockName, symbol=symbol,\
                                        price=sellPrice, dateTime=datetime.now(), shares=shares, transType='Sell')

        if not newSell:
            return apology("Error selling stock",400)
        flash('You successfully sold shares')
        return redirect(url_for('index'))

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
