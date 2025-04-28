# Store this code in 'app.py' file
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from PyPDF2 import PdfMerger
import MySQLdb.cursors
import re
import os
import stripe
import requests
import time
import threading
from plyer import notification

from flask_sqlalchemy import SQLAlchemy

import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)

if not os.path.exists('logs'):
    os.mkdir('logs')

# Set up error log file
file_handler = RotatingFileHandler('logs/error.log', maxBytes=10240, backupCount=5)
file_handler.setLevel(logging.ERROR)  # Only log errors or higher (ERROR, CRITICAL)

# Set format for logs
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
file_handler.setFormatter(formatter)

# Add the file handler to the app's logger
app.logger.addHandler(file_handler)


app.secret_key = "your_secret_key"
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a strong secret key

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Generate reset token
def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset')

# Verify reset token
def verify_reset_token(token, expiration=300):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
        return email
    except Exception:
        return None


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'geeklogin'

# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/geeklogin'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin@localhost/geeklogin'

# http://localhost/adminer-5.0.6.php?username=root&db=geeklogin
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Flask-Mail (SMTP Settings)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your email provider's SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'developer3@logicalquad.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'd*NWXuH*9*Pblkdxs'  # Replace with your email password

mysql = MySQL(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

db = SQLAlchemy(app)


reminder_interval = 1  # Default to 1 hour

# Set upload folder
UPLOAD_FOLDER = "uploads"
UPLOAD_FOLDER1 = "static/uploads"

if not os.path.exists(UPLOAD_FOLDER1):
    os.makedirs(UPLOAD_FOLDER1)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["UPLOAD_FOLDER1"] = UPLOAD_FOLDER1

# Stripe API Key
stripe.api_key = ""

# Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)

class Accounts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)

@app.route("/products")
def product_index():
    products = Product.query.all()
    return render_template("products.html", products=products)

# Add Product (Admin Panel)
@app.route("/add-product", methods=["GET", "POST"])
def add_product():
    if request.method == "POST":
        name = request.form["name"]
        price = float(request.form["price"])
        image = request.files["image"]
        
        if image:
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER1"], filename)
            image.save(image_path)

            new_product = Product(name=name, price=price, image=filename)
            db.session.add(new_product)
            db.session.commit()

            flash("Product added successfully!", "success")
            return redirect(url_for("product_index"))

    return render_template("add_product.html")

# Cart Page
@app.route("/cart")
def cart():
    cart_items = session.get("cart", {})
    return render_template("cart.html", cart_items=cart_items)


# Add to Cart
@app.route("/add-to-cart/<int:product_id>")
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

    if "cart" not in session:
        session["cart"] = {}

    cart = session["cart"]

    if str(product_id) in cart:
        cart[str(product_id)]["quantity"] += 1
    else:
        cart[str(product_id)] = {"name": product.name, "price": product.price, "quantity": 1, "image": product.image}

    session.modified = True
    flash("Added to cart!", "success")
    return redirect(url_for("cart"))

@app.route("/view-product/<int:product_id>")
def view_product(product_id):
    product_detils = Product.query.get_or_404(product_id)
    return render_template("view_product.html", product=product_detils)



    # Checkout Page
@app.route("/checkout")
def checkout():
    cart_items = session.get("cart", {})
    total_amount = sum(item["price"] * item["quantity"] for item in cart_items.values())
    return render_template("checkout.html", total_amount=total_amount)

# Stripe Payment Processing
# Pay Route
@app.route("/pay", methods=["POST"])
def pay():
    cart_items = session.get("cart", {})
    total_amount = int(sum(item["price"] * item["quantity"] for item in cart_items.values()) * 100)  # cents

    try:
        stripe.Charge.create(
            amount=total_amount,
            currency="usd",
            source=request.form["stripeToken"],
            description="E-commerce Payment"
        )
        session.pop("cart", None)  # Clear cart after payment
        session.modified = True
        app.logger.error('This is a test error!111')
        flash("Payment successful!", "success")
        return redirect(url_for("index"))

    except stripe.error.StripeError:
        app.logger.error('This is a test error!222', exc_info=True)
        session.pop("cart", None)  # Clear cart after payment
        session.modified = True
        flash("Payment failed. Please try again.", "danger")
        return redirect(url_for("index"))
       
        # return redirect(url_for("checkout"))

    except Exception as e:
        app.logger.error('This is a test error!333')
        flash(f"An unexpected error occurred: {str(e)}", "danger")
        return redirect(url_for("checkout"))

# @app.route('/')
# API_KEY = ""  # Replace with your actual API key
BASE_URL = "https://newsapi.org/v2/everything"

@app.route("/", methods=["GET"])
def index():
    query = "technology"  # Default topic
    if request.method == "POST":
        query = request.form.get("category", "technology")  # Get user input

    params = {
        "q": query,
        "apiKey": "",
        "pageSize": 4,
        "sortBy": "publishedAt",
        "language": "en"
    }

    response = requests.get(BASE_URL, params=params)
    news_data = response.json().get("articles", [])  # Get articles
    # print(news_data)  # Corrected indentation

    return render_template("index.html", articles=news_data, category=query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            hashed_password_from_db = account['password']  # Get hashed password from DB
            
            if bcrypt.check_password_hash(hashed_password_from_db, password):  # ✅ Verify password correctly
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                return redirect(url_for('dashbord'))
            else:
                msg = 'Incorrect username or password!'
        else:
            msg = 'Incorrect username or password!'

        cursor.close()
    
    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
	session.pop('loggedin', None)
	session.pop('id', None)
	session.pop('username', None)
	return redirect(url_for('login'))

@app.route('/register', methods =['GET', 'POST'])
def register():
	msg = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
		username = request.form['username']
		password = request.form['password']

		# hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

		email = request.form['email']
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
		account = cursor.fetchone()
		if account:
			msg = 'Account already exists !'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			msg = 'Invalid email address !'
		elif not re.match(r'[A-Za-z0-9]+', username):
			msg = 'Username must contain only characters and numbers !'
		elif not username or not password or not email:
			msg = 'Please fill out the form !'
		else:
			hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # ✅ Hash password before storing
			cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s)', (username, hashed_password, email, ))
			mysql.connection.commit()
			msg = 'You have successfully registered !'
	elif request.method == 'POST':
		msg = 'Please fill out the form !'
	return render_template('register.html', msg = msg)



@app.route("/dashbord", methods=["GET", "Post"])
def dashbord():
    if 'loggedin' not in session:
        return redirect(url_for('login')) 

    query = "technology"  # Default topic
    if request.method == "POST":
        query = request.form.get("category", "technology")  # Get user input

    params = {
        "q": query,
        "apiKey": "",
        "pageSize": 8,
        "sortBy": "publishedAt",
        "language": "en"
    }

    response = requests.get(BASE_URL, params=params)
    news_data = response.json().get("articles", [])  # Get articles
    # print(news_data)  # Corrected indentation

    return render_template("dashbord.html", articles=news_data, category=query)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Check if email exists in the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Generate a secure token with email
            token = serializer.dumps(email, salt='password-reset-salt')

            # Create password reset link
            reset_url = url_for('reset_password', token=token, _external=True)
			
            # Send email with reset link
            msg = Message('Password Reset Request', sender='developer@logicalquad.com', recipients=[email])
            msg.body = f'Click the link below to reset your password:\n{reset_url}\n\nIf you did not request this, ignore this email.'
            mail.send(msg)

            Flask('Password reset link sent! Check your email.', 'info')
        else:
            Flask('No account found with this email.', 'danger')

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=300)  # Token valid for 1 hour
    except:
        Flask('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update password in database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('UPDATE accounts SET password = %s WHERE email = %s', (hashed_password, email))
        mysql.connection.commit()
        cursor.close()

        Flask('Your password has been reset. You can now log in!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route("/merge-pdf", methods=["GET", "POST"])
def merge_pdf():

    if 'loggedin' not in session:
        return redirect(url_for('login')) 
        
    if request.method == "POST":
        uploaded_files = request.files.getlist("pdf_files")  # Get multiple files
        merger = PdfMerger()
        pdf_paths = []

        for file in uploaded_files:
            if file.filename.endswith(".pdf"):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                pdf_paths.append(filepath)
                merger.append(filepath)

        # Save merged PDF
        merged_pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], "merged.pdf")
        merger.write(merged_pdf_path)
        merger.close()

        # Send merged PDF for download
        return send_file(merged_pdf_path, as_attachment=True)

    return render_template("merge_pdf.html")

@app.route("/notifications", methods=["GET"])
def show_notification():
    if 'loggedin' not in session:
        return redirect(url_for('login')) 

    return render_template("notification.html", interval=reminder_interval)

def send_notification():
    """Function to send a desktop notification at regular intervals."""
    global reminder_interval
    while True:
        time.sleep(reminder_interval * 3600)  # Corrected sleep calculation
        notification.notify(
            title="Drink Water Reminder",
            message="Time to drink some water! Stay hydrated.",
            timeout=10
        )


@app.route("/set-reminder", methods=["POST"])
def set_reminder():
    """Update the reminder interval based on user input."""
    global reminder_interval
    try:
        reminder_interval = float(request.form["interval"])
        print(f"Reminder set to every {reminder_interval} hours!", "success")
    except ValueError:
        print("Please enter a valid number!", "danger")
    return redirect(url_for('dashbord'))
    
    
@app.route('/add-user', methods=["GET"])
def new_user_add():
    # return redirect(url_for('dashbord'))
    return render_template('adduser.html')

@app.route('/view-user/<int:id>', methods=["GET"])
def view_user(id):
    try:
        db = database_connection()  # Assign db connection to a variable
        if db is None:
            return "Database connection failed.", 500
        
        cursor = db.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        view_user = cursor.fetchone()  # Fetch single user as dictionary

        cursor.close()
        db.close()

        print(view_user)  # Debug: Print the user details

        return render_template('viewuser.html', users=view_user)

    except Exception as e:
        print(f"Database error: {e}")
        return "An error occurred while fetching user.", 500


def database_connection():
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="admin", db="geeklogin")
        return db
    except MySQLdb.Error as e:
        print(f"Database connection error: {e}")
        return None


@app.route('/edit-user/<int:id>', methods=["GET"])
def edit_user(id):
    try:
        db = database_connection()  # Assign db connection to a variable
        if db is None:
            return "Database connection failed.", 500
        cursor = db.cursor(MySQLdb.cursors.DictCursor)  # Use DictCursor for dictionary-like result
        cursor.execute("SELECT * FROM accounts where id = %s", (id,))
        edit_user = cursor.fetchone()  # Fetch all users as a list of dictionaries

        cursor.close()
        db.close()

        print(view_user)  # Debugging: Check if it fetches all data correctly

        return render_template('updateuser.html', users=edit_user)
    
    except Exception as e:
        print(f"Database error: {e}")
        return "An error occurred while fetching users.", 500 

@app.route('/all-users')
def show_all_users():
    if 'loggedin' not in session:
        return redirect(url_for('login')) 

    try:
        db = database_connection()  # Assign db connection to a variable
        if db is None:
            return "Database connection failed.", 500
        cursor = db.cursor(MySQLdb.cursors.DictCursor)  # Use DictCursor for dictionary-like result
        cursor.execute("SELECT * FROM accounts")
        users = cursor.fetchall()  # Fetch all users as a list of dictionaries

        cursor.close()
        db.close()

        print(users)  # Debugging: Check if it fetches all data correctly

        return render_template('allusers.html', users=users)
    
    except Exception as e:
        print(f"Database error: {e}")
        return "An error occurred while fetching users.", 500 

# Create User
@app.route('/add', methods=['GET','POST'])
def add_user():
    msg = ''
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, email, password))
    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
    account = cursor.fetchone()
    if account:
        msg = 'Account already exists !'
    elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        msg = 'Invalid email address !'
    elif not re.match(r'[A-Za-z0-9]+', username):
        msg = 'Username must contain only characters and numbers !'
    elif not username or not password or not email:
        msg = 'Please fill out the form !'
    else:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # ✅ Hash password before storing
        cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s)', (username, hashed_password, email))
        mysql.connection.commit()
        msg = 'You have successfully User!'
        return redirect(url_for('show_all_users'))
        return render_template('', msg = msg)

# # Update User
@app.route('/update/<int:id>', methods=['POST'])
def update_user(id):
    try:
        db = database_connection()  # Assign db connection to a variable
        if db is None:
            return "Database connection failed.", 500
        cursor = db.cursor(MySQLdb.cursors.DictCursor)  # ✅ Use DictCursor

        # Fetch the existing user
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        user = cursor.fetchone()

        if user:
            username = request.form['username']
            email = request.form['email']

            # ✅ Use SQL UPDATE instead of modifying `user` dictionary
            cursor.execute("UPDATE accounts SET username = %s, email = %s WHERE id = %s", (username, email, id))
            db.commit()

            # Flask("User Updated Successfully!", "info")

        cursor.close()
        db.close()

    except Exception as e:
        print(f"Error updating user: {e}")

    return redirect(url_for('show_all_users'))


# # Delete User
@app.route('/delete-user/<int:id>', methods=['POST', 'GET'])  # Allow GET & POST requests
def delete_user(id):
    try:
        db = database_connection()  # Assign db connection to a variable
        if db is None:
            return "Database connection failed.", 500
        cursor = db.cursor()

        # Check if user exists
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        user = cursor.fetchone()

        if user:
            cursor.execute("DELETE FROM accounts WHERE id = %s", (id,))
            db.commit()
        #    Flask("User Deleted Successfully!", "danger")

        cursor.close()
        db.close()

    except Exception as e:
        # Flask(f"Error deleting user: {e}", "danger")
        print(f"Error deleting user: {e}")

    return redirect(url_for('show_all_users'))  # ✅ Correct function name

# Create Tables If Not Exists
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    threading.Thread(target=send_notification, daemon=True).start()
    app.run(debug=True, host="0.0.0.0", port=8083)