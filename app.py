from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, session, flash, jsonify, make_response, url_for
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import os
import sqlite3
import bcrypt
import random
import traceback
import razorpay
from itsdangerous import URLSafeTimedSerializer

import config
from utils.pdf_generator import generate_pdf
app = Flask(__name__)

if not config.SECRET_KEY:
    raise ValueError("SECRET_KEY is not set in environment variables")

app.secret_key = config.SECRET_KEY
serializer = URLSafeTimedSerializer(app.secret_key)

# ---------------- FILE UPLOAD CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Product images
UPLOAD_FOLDER = os.path.join(
    BASE_DIR, 'static', 'uploads', 'product_images'
)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ✅ Admin profile images (ADD THIS HERE)
ADMIN_UPLOAD_FOLDER = os.path.join(
    BASE_DIR, 'static', 'uploads', 'admin_profiles'
)
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)


# ---------------- EMAIL CONFIGURATION ----------------
if not config.MAIL_USERNAME or not config.MAIL_PASSWORD:
    raise ValueError("Mail credentials are not set")

app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER

mail = Mail(app)


# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    conn = sqlite3.connect(config.DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ----------------  Razorpay Setup FUNCTION --------------

if not config.RAZORPAY_KEY_ID or not config.RAZORPAY_KEY_SECRET:
    raise ValueError("Razorpay keys are not set in environment variables")

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']

    # 1️⃣ Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # 2️⃣ Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')



# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")



# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = admin["password"]

    # If stored as TEXT instead of bytes
    if isinstance(stored_hashed_password, str):
        stored_hashed_password = stored_hashed_password.encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Step 3: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])
# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')

# =================================================================
# UPDATED PRODUCT LIST WITH SEARCH + CATEGORY FILTER
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']
    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch categories only from this admin's products
    cursor.execute("""
        SELECT DISTINCT category 
        FROM products 
        WHERE admin_id = ?
    """, (admin_id,))
    categories = cursor.fetchall()

    # Build filtered query
    query = """
        SELECT * FROM products 
        WHERE admin_id = ?
    """
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )


# =================================================================
# DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT image FROM products 
        WHERE product_id=? AND admin_id=?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    # 🔒 If product doesn't belong to this admin
    if not product:
        cursor.close()
        conn.close()
        flash("Unauthorized action or product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)

    # Delete image file safely
    if image_name and os.path.exists(image_path):
        os.remove(image_path)

    # Delete DB record securely
    cursor.execute("""
        DELETE FROM products 
        WHERE product_id=? AND admin_id=?
    """, (item_id, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')



# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")

# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = float(request.form['price'])  # Convert to float for SQLite REAL
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO products 
        (name, description, category, price, image, admin_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, description, category, price, filename, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/item-list')



# =================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Unauthorized access!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)



# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Unauthorized access!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)



# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = float(request.form['price'])  # Convert to float
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch product ONLY if it belongs to this admin
    cursor.execute("""
        SELECT * FROM products 
        WHERE product_id = ? AND admin_id = ?
    """, (item_id, admin_id))

    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Unauthorized access!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ Handle image replacement
    if new_image and new_image.filename != "":
        
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename

    else:
        final_image_name = old_image_name

    # 4️⃣ Secure update (only admin’s own product)
    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?, updated_at=CURRENT_TIMESTAMP
        WHERE product_id=? AND admin_id=?
    """, (name, description, category, price, final_image_name, item_id, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')




# =================================================================
# ROUTE 1: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT admin_id, name, email, profile_image FROM admin WHERE admin_id=?",
        (admin_id,)
    )
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']

        # If stored as TEXT instead of bytes
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session for UI consistency
    session['admin_name'] = name
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')


# =================================================================
# ADMIN FORGOT PASSWORD
# =================================================================

@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'POST':

        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
        admin = cursor.fetchone()

        cursor.close()
        conn.close()

        if not admin:
            flash("Admin email not found!", "danger")
            return redirect('/admin-forgot-password')

        token = serializer.dumps(email, salt='admin-password-reset')

        reset_link = url_for(
            'admin_reset_password',
            token=token,
            _external=True
        )

        msg = Message(
            subject="SmartCart Admin Password Reset",
            recipients=[email]
        )

        msg.body = f"""
Hello Admin,

Click the link below to reset your password:

{reset_link}

This link expires in 30 minutes.
        """

        mail.send(msg)

        flash("Reset link sent to admin email!", "success")
        return redirect('/admin-login')

    return render_template("admin/admin_forgot_password.html")


# =================================================================
# ADMIN RESET PASSWORD
# =================================================================

@app.route('/admin-reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):

    try:
        email = serializer.loads(
            token,
            salt='admin-password-reset',
            max_age=1800
        )
    except:
        flash("Reset link expired or invalid!", "danger")
        return redirect('/admin-login')

    if request.method == 'POST':

        new_password = request.form['password']

        hashed_pw = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE admin
            SET password=?
            WHERE email=?
        """, (hashed_pw, email))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Admin password updated successfully!", "success")
        return redirect('/admin-login')

    return render_template("admin/admin_reset_password.html")



# =================================================================
#   USER REGISTRATION – STEP 1 (Send OTP)
# =================================================================

@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already registered")
            cursor.close()
            conn.close()
            return redirect('/user-register')

        otp = random.randint(100000, 999999)

        session['register_email'] = email
        session['register_otp'] = str(otp)

        msg = Message(
            subject="SmartCart Registration OTP",
            sender=config.MAIL_USERNAME,
            recipients=[email],
            body=f"Your OTP for SmartCart registration is: {otp}"
        )

        mail.send(msg)

        cursor.close()
        conn.close()

        flash("OTP sent to your email")
        return redirect('/verify-register-otp')

    return render_template(
        'user/user_register.html',
        show_public_navbar=True
    )




# =================================================================
#       VERIFY OTP
# =================================================================
@app.route('/verify-register-otp', methods=['GET', 'POST'])
def verify_register_otp():

    if request.method == 'POST':

        user_otp = request.form['otp']

        if user_otp == session.get('register_otp'):
            return redirect('/complete-registration')
        else:
            flash("Invalid OTP")
            return redirect('/verify-register-otp')

    return render_template('user/verify_register_otp.html',
                           show_public_navbar=True)


# =================================================================
# COMPLETE REGISTRATION (Store Hashed Password)
# =================================================================

@app.route('/complete-registration', methods=['GET', 'POST'])
def complete_registration():

    if request.method == 'POST':

        name = request.form['name']
        mobile = request.form['mobile']
        password = request.form['password']
        email = session.get('register_email')

        if not email:
            return redirect('/user-register')

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO users (name, email, mobile, password)
            VALUES (?, ?, ?, ?)
        """, (name, email, mobile, hashed_password))

        conn.commit()

        cursor.close()
        conn.close()

        session.pop('register_email', None)
        session.pop('register_otp', None)

        flash("Registration Successful! Please login.")
        return redirect('/')

    return render_template(
        'user/complete_registration.html',
        show_public_navbar=True
    )

# =================================================================
# USER LOGIN (BCRYPT VALIDATION)
# =================================================================

@app.route('/', methods=['GET', 'POST'])
def user_login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:

            stored_password = user['password']

            # If stored as TEXT instead of bytes
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')

            if bcrypt.checkpw(
                password.encode('utf-8'),
                stored_password
            ):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['user_email'] = user['email']

                flash("Login Successful")
                return redirect('/user-home')
            else:
                flash("Invalid Password")
        else:
            flash("Email not registered")

    return render_template(
        'user/user_login.html',
        show_public_navbar=True
    )


# =================================================================
# USER HOME
# =================================================================

@app.route('/user-home')
def user_home():

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products LIMIT 8")
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'user/user_home.html',
        user_name=session['user_name'],
        products=products
    )

# =================================================================
# USER PRODUCTS
# =================================================================

@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        return redirect('/user-login')

    search = request.args.get('search')
    category = request.args.get('category')
    max_price = request.args.get('max_price')

    query = "SELECT * FROM products WHERE 1=1"
    values = []

    if search:
        query += " AND name LIKE ?"
        values.append(f"%{search}%")

    if category:
        query += " AND category=?"
        values.append(category)

    if max_price:
        query += " AND price <= ?"
        values.append(float(max_price))  # Convert to float

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(query, values)
    products = cursor.fetchall()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'user/user_products.html',
        products=products,
        categories=categories
    )


# =================================================================
# PRODUCT DETAILS
# =================================================================

@app.route('/user/product/<int:product_id>')
def product_details(product_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id=?",
        (product_id,)
    )

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template(
        'user/product_details.html',
        product=product
    )


# =================================================================
# ADD ITEM TO CART (DB VERSION)
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check product exists
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found.", "danger")
        return redirect(url_for('user_products'))

    # Check if product already in cart
    cursor.execute("""
        SELECT * FROM cart 
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE cart 
            SET quantity = quantity + 1 
            WHERE user_id=? AND product_id=?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, 1)
        """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item added to cart!", "success")
    return redirect(url_for('product_details', product_id=product_id))


# =================================================================
# VIEW CART (DB VERSION)
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.product_id, c.quantity,
               p.name, p.price, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    cursor.close()
    conn.close()

    grand_total = sum(
        float(item['price']) * int(item['quantity'])
        for item in cart_items
    )

    return render_template(
        "user/cart.html",
        cart=cart_items,
        grand_total=grand_total
    )


# =================================================================
# INCREASE QUANTITY
# =================================================================

@app.route('/user/cart/increase/<int:pid>')
def increase_quantity(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart
        SET quantity = quantity + 1
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')



# =================================================================
# DECREASE QUANTITY
# =================================================================

@app.route('/user/cart/decrease/<int:pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Decrease quantity
    cursor.execute("""
        UPDATE cart
        SET quantity = quantity - 1
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    # Remove if quantity <= 0
    cursor.execute("""
        DELETE FROM cart
        WHERE user_id=? AND product_id=? AND quantity <= 0
    """, (session['user_id'], pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')



# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<int:pid>')
def remove_from_cart(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cart
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')



# =================================================================
# AJAX ADD TO CART
# =================================================================
@app.route('/user/add-to-cart-ajax/<int:product_id>')
def add_to_cart_ajax(product_id):

    if 'user_id' not in session:
        return {"error": "not_logged_in"}, 401

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if product exists
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        return {"error": "Product not found"}, 404

    # Check if already in cart
    cursor.execute("""
        SELECT * FROM cart
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE cart
            SET quantity = quantity + 1
            WHERE user_id=? AND product_id=?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, 1)
        """, (user_id, product_id))

    conn.commit()

    # Get updated cart count
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM cart
        WHERE user_id=?
    """, (user_id,))

    row = cursor.fetchone()
    count = row["count"] if row else 0

    cursor.close()
    conn.close()

    return {
        "message": "Item added!",
        "cart_count": count
    }


# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================

@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch cart from DB
    cursor.execute("""
        SELECT c.product_id, c.quantity,
               p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    if not cart_items:
        cursor.close()
        conn.close()
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total
    total_amount = sum(
        float(item['price']) * int(item['quantity'])
        for item in cart_items
    )

    razorpay_amount = int(total_amount * 100)

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": 1
    })

    session['razorpay_order_id'] = razorpay_order['id']

    cursor.close()
    conn.close()

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )




# =================================================================
# TEMP SUCCESS PAGE (Verification in Day)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )

# =================================================================
# Route: Verify Payment and Store Order
# =================================================================
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Signature verification failed: %s", str(e))
        flash("Payment verification failed.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ FETCH CART
    cursor.execute("""
        SELECT c.product_id, c.quantity,
               p.name, p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))
    cart_items = cursor.fetchall()

    if not cart_items:
        cursor.close()
        conn.close()
        flash("Cart is empty.", "danger")
        return redirect('/user/products')

    # 2️⃣ CHECK USER ADDRESS EXISTS
    cursor.execute("""
        SELECT * FROM user_addresses
        WHERE user_id = ?
    """, (user_id,))
    address = cursor.fetchone()

    if not address:
        cursor.close()
        conn.close()
        flash("Please add delivery address first.", "warning")
        return redirect('/user/address')

    # 3️⃣ Calculate total
    total_amount = sum(
        float(item['price']) * int(item['quantity'])
        for item in cart_items
    )

    try:
        # 4️⃣ Insert order (NO address snapshot — normalized design)
        cursor.execute("""
            INSERT INTO orders (
                user_id,
                razorpay_order_id,
                razorpay_payment_id,
                amount,
                payment_status
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid'
        ))

        order_db_id = cursor.lastrowid

        # 5️⃣ Insert order items
        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items
                (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (
                order_db_id,
                item['product_id'],
                item['name'],
                item['quantity'],
                item['price']
            ))

        # 6️⃣ Clear cart
        cursor.execute("DELETE FROM cart WHERE user_id=?", (user_id,))

        conn.commit()

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order saving failed: %s", str(e))
        flash("Error saving order.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()



# =================================================================
# Route: Order Success Page
# =================================================================
@app.route('/user/order-success/<int:order_id>')
def order_success(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order (security check)
    cursor.execute("""
        SELECT * FROM orders 
        WHERE order_id=? AND user_id=?
    """, (order_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/products')

    # Fetch order items
    cursor.execute("""
        SELECT * FROM order_items 
        WHERE order_id=?
    """, (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/order_success.html",
        order=order,
        items=items
    )


# =================================================================
# 🧾 My Orders Page (List user's orders)
# =================================================================

@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC",
        (session['user_id'],)
    )
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)



# ==============================================================
# USER ADDRESS ROUTE
# ==============================================================

@app.route('/user/address', methods=['GET', 'POST'])
def user_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check existing address
    cursor.execute(
        "SELECT * FROM user_addresses WHERE user_id=?",
        (user_id,)
    )
    address = cursor.fetchone()

    if request.method == "POST":

        full_name = request.form['full_name']
        phone = request.form['phone']
        pincode = request.form['pincode']
        state = request.form['state']
        city = request.form['city']
        full_address = request.form['full_address']

        if address:
            # Update existing address
            cursor.execute("""
                UPDATE user_addresses
                SET full_name=?, phone=?, pincode=?,
                    state=?, city=?, full_address=?
                WHERE user_id=?
            """, (full_name, phone, pincode, state, city, full_address, user_id))
        else:
            # Insert new address
            cursor.execute("""
                INSERT INTO user_addresses
                (user_id, full_name, phone, pincode, state, city, full_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, full_name, phone, pincode, state, city, full_address))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Address saved successfully!", "success")
        return redirect('/user/pay')  # Redirect to payment

    cursor.close()
    conn.close()

    return render_template("user/address.html", address=address)



# =================================================================
# GENERATE INVOICE PDF
# =================================================================
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order + address together
    cursor.execute("""
        SELECT o.*, ua.full_name, ua.phone, ua.pincode,
               ua.state, ua.city, ua.full_address
        FROM orders o
        JOIN user_addresses ua ON o.user_id = ua.user_id
        WHERE o.order_id=? AND o.user_id=?
    """, (order_id, session['user_id']))

    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Fetch order items
    cursor.execute(
        "SELECT * FROM order_items WHERE order_id=?",
        (order_id,)
    )
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response



# =================================================================
# Forgot Password
# =================================================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':

        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user:
            flash("Email not found!", "danger")
            return redirect('/forgot-password')

        token = serializer.dumps(email, salt='password-reset')

        reset_link = url_for(
            'reset_password',
            token=token,
            _external=True
        )

        msg = Message(
            subject="SmartCart Password Reset",
            recipients=[email]
        )

        msg.body = f"""
Hello,

Click the link below to reset your password:

{reset_link}

This link expires in 30 minutes.
        """

        mail.send(msg)

        flash("Reset link sent to your email!", "success")
        return redirect('/user-login')

    return render_template(
        "user/forgot.html",
        show_public_navbar=True
    )



# =================================================================
# ROUTE : RESET
# =================================================================

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    try:
        email = serializer.loads(
            token,
            salt='password-reset',
            max_age=1800
        )
    except:
        flash("Reset link expired or invalid!", "danger")
        return redirect('/user-login')

    if request.method == 'POST':

        new_password = request.form['password']

        hashed_pw = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET password=?
            WHERE email=?
        """, (hashed_pw, email))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect('/user-login')

    return render_template(
        'user/reset.html',
        show_public_navbar=True
    )


# =================================================================
# ROUTE : ABOUT
# =================================================================

@app.route('/about')
def about():
    return render_template('user/about.html',
                           show_public_navbar=True)

# =================================================================
# ROUTE : CONTACT
# =================================================================

@app.route('/contact')
def contact():
    return render_template('user/contact.html',
                           show_public_navbar=True)


# =================================================================
# USER LOGOUT
# =================================================================

@app.route('/user-logout')
def user_logout():

    session.clear()
    flash("Logged out successfully")
    return redirect('/')



# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)
