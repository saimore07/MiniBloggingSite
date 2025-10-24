#!/usr/bin/env python3
"""
Database initialization script for MiniBlog
Run this script to create all database tables
"""

import os
import sys
from app import app, db
from models import User, Post, Comment, Like

def init_database():
    """Initialize the database with all tables"""
    print("🚀 Initializing MiniBlog database...")
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Check if we need to create an admin user
            admin_user = User.query.filter_by(role='admin').first()
            if not admin_user:
                print("👤 Creating default admin user...")
                admin = User(
                    username='admin',
                    email='admin@miniblog.com',
                    role='admin'
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created:")
                print("   Email: admin@miniblog.com")
                print("   Password: admin123")
            else:
                print("ℹ️  Admin user already exists")
            
            print("🎉 Database initialization complete!")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            sys.exit(1)

if __name__ == '__main__':
    init_database()
