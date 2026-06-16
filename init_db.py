"""
Run this once to create all MySQL tables automatically.
Usage:  python init_db.py
Requires DATABASE_URL in .env to point to MySQL.
"""
from app import app, db

with app.app_context():
    db.create_all()
    print("All tables created successfully in MySQL.")
