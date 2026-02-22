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

    SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL")
    signup_email = session['signup_email']

    # Decide role
    if signup_email == SUPER_ADMIN_EMAIL:
        role = "super_admin"
        is_approved = 1
    else:
        role = "admin"
        is_approved = 0

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO admin (name, email, password, role, is_approved)
        VALUES (?, ?, ?, ?, ?)
    """, (
        session['signup_name'],
        signup_email,
        hashed_password,
        role,
        is_approved
    ))

    conn.commit()
    cursor.close()
    conn.close()

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

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=? AND is_deleted=0", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # 🔐 Check Password
    stored_hashed_password = admin["password"]

    if isinstance(stored_hashed_password, str):
        stored_hashed_password = stored_hashed_password.encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # 🚫 Check if Blocked
    if admin["is_blocked"] == 1:
        flash("Your account has been blocked by Super Admin.", "danger")
        return redirect('/admin-login')

    # ⏳ Check if Approved
    if admin["is_approved"] == 0:
        flash("Your account is waiting for Super Admin approval.", "warning")
        return redirect('/admin-login')

    # ✅ Login Success → Store Session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']
    session['role'] = admin['role']   # VERY IMPORTANT

    flash("Login Successful!", "success")

    # 👑 Redirect Based on Role
    if admin['role'] == 'super_admin':
        return redirect('/superadmin-dashboard')
    else:
        return redirect('/admin-dashboard')

# =================================================================
# ROUTE 5: ADMIN DASHBOARD (ADMIN ONLY)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 🚫 Prevent superadmin from accessing normal admin dashboard
    if session.get("role") not in ["admin", "super_admin"]:
        return "Access Denied", 403

    return render_template(
        "admin/dashboard.html",
        admin_name=session['admin_name']
    )

# =================================================================
# ROUTE 6: SUPER ADMIN DASHBOARD (SUMMARY)
# =================================================================
@app.route('/superadmin-dashboard')
def superadmin_dashboard():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    if session.get("role") != "super_admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Total Revenue
    cursor.execute("""
        SELECT SUM(amount)
        FROM orders
        WHERE payment_status='paid'
    """)
    total_revenue = cursor.fetchone()[0] or 0

    # 🔹 Total Admins (FIXED)
    cursor.execute("""
        SELECT COUNT(*)
        FROM admin
        WHERE role = 'admin'
        AND is_deleted = 0
    """)
    total_admins = cursor.fetchone()[0]

    # 🔹 Pending Admins
    cursor.execute("""
        SELECT COUNT(*)
        FROM admin
        WHERE is_approved = 0
        AND role = 'admin'
        AND is_deleted = 0
    """)
    pending_admins = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "admin/super_dashboard.html",
        total_revenue=total_revenue,
        total_admins=total_admins,
        pending_admins=pending_admins
    )

# =================================================================
# MANAGE ADMINS (SUPER ADMIN ONLY)
# =================================================================
@app.route('/manage-admins')
def manage_admins():

    if 'admin_id' not in session:
        return redirect('/admin-login')

    if session.get("role") != "super_admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Get all admins with revenue
    cursor.execute("""
        SELECT a.admin_id,
               a.name,
               a.email,
               a.is_approved,
               a.is_blocked,
               IFNULL(SUM(oi.price * oi.quantity), 0) AS revenue
        FROM admin a
        LEFT JOIN products p ON a.admin_id = p.admin_id
        LEFT JOIN order_items oi ON p.product_id = oi.product_id
        LEFT JOIN orders o ON oi.order_id = o.order_id
        AND o.payment_status = 'Paid'
        WHERE a.role = 'admin' AND a.is_deleted = 0
        GROUP BY a.admin_id
    """)

    admins = cursor.fetchall()

    conn.close()

    return render_template("admin/manage_admins.html", admins=admins)

# =================================================================
# ROUTE : Approve
# =================================================================

@app.route('/approve-admin/<int:admin_id>',methods=["POST"])
def approve_admin(admin_id):

    if session.get("role") != "super_admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE admin SET is_approved=1 WHERE admin_id=?", (admin_id,))
    conn.commit()
    conn.close()

    flash("Admin approved successfully!", "success")
    return redirect('/manage-admins')




# =================================================================
# ROUTE : Block Admin
# =================================================================

@app.route('/block-admin/<int:admin_id>', methods=['POST'])
def block_admin(admin_id):

    if session.get("role") != "super_admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE admin SET is_blocked=1 WHERE admin_id=?", (admin_id,))
    conn.commit()
    conn.close()

    flash("Admin blocked successfully!", "danger")
    return redirect('/manage-admins')

# =================================================================
# ROUTE : Unblock Admin
# =================================================================

@app.route('/unblock-admin/<int:admin_id>', methods=['POST'])
def unblock_admin(admin_id):

    if session.get("role") != "super_admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE admin SET is_blocked=0 WHERE admin_id=?", (admin_id,))
    conn.commit()
    conn.close()

    flash("Admin unblocked successfully!", "success")
    return redirect('/manage-admins')

# =================================================================
# ROUTE : Delete Admin
# =================================================================

@app.route('/delete-admin/<int:admin_id>',methods=["POST"])
def delete_admin(admin_id):

    if session.get("role") != "super_admin":
        return "Access Denied", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Check revenue
    cursor.execute("""
        SELECT IFNULL(SUM(oi.price * oi.quantity), 0)
        FROM products p
        LEFT JOIN order_items oi ON p.product_id = oi.product_id
        LEFT JOIN orders o ON oi.order_id = o.order_id
            AND o.payment_status='Paid'
        WHERE p.admin_id = ?
    """, (admin_id,))

    revenue = cursor.fetchone()[0]

    if revenue > 0:
        conn.close()
        flash("Cannot delete admin with revenue history. Block instead.", "danger")
        return redirect('/manage-admins')

    # 🔹 Safe to delete
    cursor.execute("UPDATE admin SET is_deleted=1 WHERE admin_id=?", (admin_id,))
    conn.commit()
    conn.close()

    flash("Admin deleted successfully!", "success")
    return redirect('/manage-admins')

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
# UPDATED PRODUCT LIST (ROLE + VIEW AWARE)
# =================================================================

@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    role = session.get("role")
    admin_id = session['admin_id']
    view = request.args.get('view', 'all')  # mine or all

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # ====================================================
    # SUPERADMIN LOGIC
    # ====================================================
    if role == "super_admin":

        # My Products
        if view == "mine":
            query = """
                SELECT p.*, a.name AS owner_name
                FROM products p
                JOIN admin a ON p.admin_id = a.admin_id
                WHERE p.admin_id = ? AND p.is_deleted = 0
            """
            params = [admin_id]

        # All Products
        else:
            query = """
                SELECT p.*, a.name AS owner_name
                FROM products p
                JOIN admin a ON p.admin_id = a.admin_id
                WHERE p.is_deleted = 0
            """
            params = []

    # ====================================================
    # NORMAL ADMIN LOGIC
    # ====================================================
    else:
        query = """
            SELECT p.*, a.name AS owner_name
            FROM products p
            JOIN admin a ON p.admin_id = a.admin_id
            WHERE p.admin_id = ? AND p.is_deleted = 0
        """
        params = [admin_id]

    # SEARCH FILTER
    if search:
        query += " AND p.name LIKE ?"
        params.append(f"%{search}%")

    # CATEGORY FILTER
    if category_filter:
        query += " AND p.category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        role=role,
        admin_id=admin_id,
        view=view
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
        UPDATE products
        SET is_deleted=1
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

    # 1️⃣ Check login
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 2️⃣ Check role
    if session.get("role") not in ["admin", "super_admin"]:
        return "Access Denied", 403

    return render_template("admin/add_item.html")

# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():


    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')
    
    # 2️⃣ Then check role
    if session.get("role") not in ["admin", "super_admin"]:
        return "Access Denied", 403

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = float(request.form['price'])  # Convert to float for SQLite REAL
    image_file = request.files['image']
    quantity = int(request.form['quantity'])

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
        (name, description, category, price, image,quantity, admin_id)
        VALUES (?, ?, ?, ?, ?, ? ,?)
    """, (name, description, category, price, filename, quantity,admin_id))

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

    role = session.get("role")
    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 👑 SUPERADMIN → can fetch any product
    if role == "super_admin":
        cursor.execute("""
            SELECT * FROM products 
            WHERE product_id = ? AND is_deleted = 0
        """, (item_id,))
    else:
        # 👤 NORMAL ADMIN → only their product
        cursor.execute("""
            SELECT * FROM products 
            WHERE product_id = ? AND admin_id = ? AND is_deleted = 0
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

    role = session.get("role")
    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = float(request.form['price'])
    quantity = int(request.form['quantity'])
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 👑 SUPERADMIN → no admin restriction
    if role == "super_admin":
        cursor.execute("""
            SELECT * FROM products 
            WHERE product_id = ? AND is_deleted = 0
        """, (item_id,))
    else:
        cursor.execute("""
            SELECT * FROM products 
            WHERE product_id = ? AND admin_id = ? AND is_deleted = 0
        """, (item_id, admin_id))

    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Unauthorized access!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # Image replacement
    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        if old_image_name:
            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 🔥 UPDATE QUERY
    if role == "super_admin":
        cursor.execute("""
            UPDATE products
            SET name=?, description=?, category=?, price=?, quantity=?, image=?, updated_at=CURRENT_TIMESTAMP
            WHERE product_id=?
        """, (name, description, category, price, quantity, final_image_name, item_id))
    else:
        cursor.execute("""
            UPDATE products
            SET name=?, description=?, category=?, price=?, quantity=?, image=?, updated_at=CURRENT_TIMESTAMP
            WHERE product_id=? AND admin_id=?
        """, (name, description, category, price, quantity, final_image_name, item_id, admin_id))

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Fetch product with quantity
    cursor.execute("""
        SELECT product_id, quantity 
        FROM products 
        WHERE product_id=?
    """, (product_id,))
    product = cursor.fetchone()

    if not product:
        conn.close()
        flash("Product not found.", "danger")
        return redirect('/user/products')

    if product['quantity'] <= 0:
        conn.close()
        flash("Product is out of stock!", "danger")
        return redirect('/user/products')

    # 🔹 Check existing cart quantity
    cursor.execute("""
        SELECT quantity FROM cart
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))
    existing = cursor.fetchone()

    current_cart_qty = existing['quantity'] if existing else 0

    if current_cart_qty + 1 > product['quantity']:
        conn.close()
        flash("Not enough stock available!", "warning")
        return redirect('/user/products')

    # 🔹 Safe to add
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
    conn.close()

    flash("Item added to cart!", "success")
    return redirect('/user/products')


# =================================================================
# VIEW CART (DB VERSION)
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        return redirect('/')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.product_id, c.quantity,
               p.name, p.price, p.image,
               p.quantity AS product_stock 
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
        return redirect('/')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get stock
    cursor.execute("SELECT quantity FROM products WHERE product_id=?", (pid,))
    product = cursor.fetchone()

    # Get cart quantity
    cursor.execute("""
        SELECT quantity FROM cart
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))
    cart_item = cursor.fetchone()

    if not product or not cart_item:
        conn.close()
        return redirect('/user/cart')

    if cart_item['quantity'] >= product['quantity']:
        conn.close()
        flash("Stock limit reached!", "warning")
        return redirect('/user/cart')

    cursor.execute("""
        UPDATE cart
        SET quantity = quantity + 1
        WHERE user_id=? AND product_id=?
    """, (session['user_id'], pid))

    conn.commit()
    conn.close()

    return redirect('/user/cart')

# =================================================================
# DECREASE QUANTITY
# =================================================================

@app.route('/user/cart/decrease/<int:pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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

    try:
        # 🔒 START TRANSACTION
        conn.execute("BEGIN")

        # 1️⃣ Fetch cart with latest stock
        cursor.execute("""
            SELECT c.product_id, c.quantity,
                   p.name, p.price, p.quantity AS stock
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = ?
        """, (user_id,))
        cart_items = cursor.fetchall()

        if not cart_items:
            raise Exception("Cart empty")

        # 2️⃣ CHECK STOCK BEFORE ORDER
        for item in cart_items:
            if item['quantity'] > item['stock']:
                raise Exception(f"Insufficient stock for {item['name']}")

        # 3️⃣ CHECK ADDRESS
        cursor.execute("""
            SELECT * FROM user_addresses
            WHERE user_id = ?
        """, (user_id,))
        address = cursor.fetchone()

        if not address:
            raise Exception("Address missing")

        # 4️⃣ Calculate total
        total_amount = sum(
            float(item['price']) * int(item['quantity'])
            for item in cart_items
        )

        # 5️⃣ Insert order
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
            'Paid'
        ))

        order_db_id = cursor.lastrowid

        # 6️⃣ Insert order items + Reduce stock
        for item in cart_items:

            # Insert item
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

            # 🔥 Reduce stock safely
            cursor.execute("""
                UPDATE products
                SET quantity = quantity - ?
                WHERE product_id = ?
            """, (item['quantity'], item['product_id']))

        # 7️⃣ Clear cart
        cursor.execute("DELETE FROM cart WHERE user_id=?", (user_id,))

        conn.commit()

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order failed: %s", str(e))
        flash(str(e), "danger")
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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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
        return redirect('/')

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



# ---------------------------------------------------------
# Disable browser caching for protected pages
# ---------------------------------------------------------
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)

