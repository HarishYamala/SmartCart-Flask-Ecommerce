# 🛒 SmartCart – Flask E-Commerce Web Application

SmartCart is a full-featured E-commerce web application built using **Flask + SQLite**.  
It supports complete shopping workflow including authentication, cart management, payments, and invoice generation.

---

## 🚀 Features

### 👨‍💼 Admin Panel
- Admin Registration with OTP verification
- Secure Login (bcrypt hashing)
- Add / Update / Delete Products
- Image Upload Handling
- Profile Management
- Password Reset via Email

### 👤 User System
- User Registration with OTP
- Secure Login System
- Forgot Password & Reset Flow
- Session-based Authentication

### 🛍 Product & Cart
- Product Browsing & Search
- Category Filtering
- Add to Cart (AJAX + DB based)
- Increase / Decrease Quantity
- Remove Items
- Persistent Cart (Database stored)

### 💳 Payment Integration
- Razorpay Test Mode Integration
- Secure Payment Verification
- Digital Signature Validation

### 📦 Orders
- Order Creation & Storage
- Order Items Tracking
- Order History Page
- Downloadable PDF Invoice
- Address Management System

---

## 🛠 Tech Stack

- **Backend:** Flask (Python)
- **Database:** SQLite
- **Authentication:** bcrypt
- **Payment Gateway:** Razorpay
- **Email Service:** Flask-Mail (SMTP)
- **PDF Generation:** Custom HTML → PDF
- **Frontend:** HTML, CSS, Jinja2

---

## 📂 Project Structure

```
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
```

---

## ⚙ Installation (Local Setup)

1️⃣ Clone the repository:

```
git clone https://github.com/HarishYamala/SmartCart-Flask-Ecommerce.git
cd SmartCart-Flask-Ecommerce
```

2️⃣ Create virtual environment:

```
python -m venv venv
source venv/Scripts/activate   # Windows
```

3️⃣ Install dependencies:

```
pip install -r requirements.txt
```

4️⃣ Initialize database:

```
python init_db.py
```

5️⃣ Run the app:

```
python app.py
```

Visit:

```
http://127.0.0.1:5000
```

---

## 🔐 Environment Variables Required

Set the following before running:

- SECRET_KEY
- MAIL_USERNAME
- MAIL_PASSWORD
- RAZORPAY_KEY_ID
- RAZORPAY_KEY_SECRET

---

## 🎯 Key Highlights

✔ Raw SQL (No ORM used)  
✔ MySQL → SQLite Migration  
✔ Secure Password Hashing  
✔ Payment Gateway Integration  
✔ PDF Invoice System  
✔ Clean MVC Structure  
✔ Production-ready architecture  

---

## 📌 Future Improvements

- Multi-address support
- Order status tracking
- Admin analytics dashboard
- Docker deployment
- Production deployment on cloud

---

## 👨‍💻 Author

**Harish Yamala**  
Aspiring Data Analyst & Backend Developer  
GitHub: https://github.com/HarishYamala

---

⭐ If you like this project, give it a star!
