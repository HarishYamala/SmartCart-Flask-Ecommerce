import sqlite3

conn = sqlite3.connect("smartcart.db")
cursor = conn.cursor()

print("Starting DB upgrade...")

# Add order_status
try:
    cursor.execute("ALTER TABLE orders ADD COLUMN order_status TEXT DEFAULT 'Pending'")
    print("order_status added.")
except:
    print("order_status already exists.")

# Add commission column
try:
    cursor.execute("ALTER TABLE admin ADD COLUMN commission_percentage REAL DEFAULT 10")
    print("commission_percentage added.")
except:
    print("commission_percentage already exists.")

# Add soft delete
try:
    cursor.execute("ALTER TABLE admin ADD COLUMN is_deleted INTEGER DEFAULT 0")
    print("admin is_deleted added.")
except:
    print("admin is_deleted already exists.")

try:
    cursor.execute("ALTER TABLE products ADD COLUMN is_deleted INTEGER DEFAULT 0")
    print("products is_deleted added.")
except:
    print("products is_deleted already exists.")

# Indexes
cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_admin ON products(admin_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_order_items_product ON order_items(product_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(payment_status)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id)")
cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_cart ON cart(user_id, product_id)")

print("Indexes created.")

conn.commit()
conn.close()

print("Database upgrade complete!")