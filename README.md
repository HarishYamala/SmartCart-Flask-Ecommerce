🛒 SmartCart – Multi-Vendor Flask E-Commerce Platform

SmartCart is a full-featured Multi-Vendor E-commerce Web Application built using Flask + SQLite.
It supports complete shopping workflow including authentication, cart management, payments, role-based access control, and invoice generation.

🚀 Core Features
👑 Super Admin System

Environment-based Super Admin assignment

Approve / Block / Delete Admins

View Total Platform Revenue

View Individual Admin Revenue

Role-based dashboard redirection

Protected routes with session validation

Super Admin email is configured via environment variable (SUPER_ADMIN_EMAIL)

👨‍💼 Admin Panel (Multi-Vendor)

Admin Registration with OTP verification

Secure Login (bcrypt hashing)

Role-based access (admin / super_admin)

Product Management (Add / Update / Soft Delete)

Image Upload Handling

Profile Management (Image + Password Update)

Password Reset via Email

Inventory Tracking (Quantity Control)

👤 User System

User Registration with OTP

Secure Login System

Forgot Password & Reset Flow

Session-based Authentication

Cache-safe logout (Back-button protected)

🛍 Product & Cart

Product Browsing & Search

Category Filtering

Add to Cart (Database-based)

Increase / Decrease Quantity

Remove Items

Persistent Cart (DB stored)

Soft-delete product handling

💳 Payment Integration

Razorpay Test Mode Integration

Secure Payment Verification

Digital Signature Validation

Order Status Tracking

📦 Orders & Invoice

Order Creation & Storage

Order Items Tracking

Order History Page

Downloadable PDF Invoice

Address Management System

🛠 Tech Stack

Backend: Flask (Python)

Database: SQLite (Raw SQL – No ORM)

Authentication: bcrypt

Payment Gateway: Razorpay

Email Service: Flask-Mail (SMTP)

PDF Generation: HTML → PDF

Frontend: HTML, CSS, Jinja2

🔐 Role-Based Architecture
Role	Access Level
User	Shop & Order
Admin	Manage Own Products
Super Admin	Manage Admins + View Platform Analytics

Role is assigned dynamically during registration:

SUPER_ADMIN_EMAIL=your_email@gmail.com

If admin registers using this email → automatically becomes super_admin.

📂 Project Structure
SmartCart-Flask-Ecommerce/
│
├── app.py
├── config.py
├── init_db.py
├── schema.sql
├── requirements.txt
├── templates/
├── static/
└── utils/

Database schema is centralized in schema.sql
No migration or upgrade script required.

⚙ Local Installation
1️⃣ Clone Repository
git clone https://github.com/HarishYamala/SmartCart-Flask-Ecommerce.git
cd SmartCart-Flask-Ecommerce
2️⃣ Create Virtual Environment
python -m venv venv
source venv/Scripts/activate   # Windows
3️⃣ Install Dependencies
pip install -r requirements.txt
4️⃣ Set Environment Variables

Create .env file:

SECRET_KEY=your_secret
MAIL_USERNAME=your_email
MAIL_PASSWORD=your_password
RAZORPAY_KEY_ID=your_key
RAZORPAY_KEY_SECRET=your_secret
SUPER_ADMIN_EMAIL=your_email
5️⃣ Initialize Database
python init_db.py
6️⃣ Run Application
python app.py

Visit:

http://127.0.0.1:5000
🌍 Deployment Ready

Fully compatible with PythonAnywhere

Environment-based configuration

No hardcoded credentials

No manual database edits required

Clone → Run → Works

🛡 Security Highlights

✔ bcrypt password hashing
✔ Session-based role validation
✔ Cache-control headers to prevent back-button access
✔ Soft delete strategy (data integrity)
✔ Environment variable based secrets

📈 Platform Capabilities

Multi-vendor structure

Revenue aggregation

Admin performance tracking

Order analytics foundation ready

Easily extendable to PostgreSQL

📌 Future Enhancements

Sales analytics charts

Commission calculation automation

Admin payout system

REST API version

Docker containerization

Cloud deployment (AWS / Render / Railway)

👨‍💻 Author

Harish Yamala
Aspiring Backend Developer & Data Analyst
GitHub: https://github.com/HarishYamala

⭐ If you like this project, give it a star!