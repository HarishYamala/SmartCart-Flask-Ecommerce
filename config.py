# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

# ------------------------------------
# Configuration File for SmartCart
# ------------------------------------

import os

# Secret Key (used for sessions)
SECRET_KEY = "abc1234"

# SQLite Database Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "smartcart.db")

# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'harishyamala2002@gmail.com'
MAIL_PASSWORD = 'nzswxvsuwseontdh'   # Gmail App Password
MAIL_DEFAULT_SENDER = 'harishyamala2002@gmail.com'

# Razorpay Setup (Test Mode)
RAZORPAY_KEY_ID = "rzp_test_SG3xbBtNeuA6oX"
RAZORPAY_KEY_SECRET = "uT3Oin77WeNdRYhYPpJfmp1q"
