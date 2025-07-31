#!/usr/bin/env python3
"""
Database initialization script for Autism Therapy Platform
Run this script to create the database and add sample data
"""

from app import app, db, User, Child, TherapyPlan, Activity, Resource, Message, ForumPost
from werkzeug.security import generate_password_hash
from datetime import datetime, date, timedelta
import os

def create_database():
    """Create all database tables"""
    print("Creating database tables...")
    with app.app_context():
        db.create_all()
        print("Database tables created successfully")

def create_sample_users():
    """Create sample users for testing"""
    print("Creating sample users...")
    
    with app.app_context():
        # Admin user
        admin = User(
            username='admin',
            email='admin@therapyplatform.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            full_name='System Administrator',
            phone='+250788123456'
        )
        
        # Therapist user
        therapist = User(
            username='dr_smith',
            email='therapist@therapyplatform.com',
            password_hash=generate_password_hash('therapist123'),
            role='therapist',
            full_name='Dr. Sarah Smith',
            phone='+250788654321'
        )
        
        # Caregiver user
        caregiver = User(
            username='parent_john',
            email='parent@therapyplatform.com',
            password_hash=generate_password_hash('parent123'),
            role='caregiver',
            full_name='John Uwimana',
            phone='+250788987654'
        )
        
        # Check if users already exist
        if not User.query.filter_by(username='admin').first():
            db.session.add(admin)
        if not User.query.filter_by(username='dr_smith').first():
            db.session.add(therapist)
        if not User.query.filter_by(username='parent_john').first():
            db.session.add(caregiver)
            
        db.session.commit()
        print("Sample users created successfully")
        print("  - Admin: admin / admin123")
        print("  - Therapist: dr_smith / therapist123")
        print("  - Caregiver: parent_john / parent123")

def create_sample_data():
    """Create sample children, therapy plans, and activities"""
    print("Creating sample data...")
    
    with app.app_context():
        # Get users
        caregiver = User.query.filter_by(username='parent_john').first()
        therapist = User.query.filter_by(username='dr_smith').first()
        
        if not caregiver or not therapist:
            print("Sample users not found. Run create_sample_users() first.")
            return
        
        # Create sample child
        if not Child.query.filter_by(name='Emma Uwimana').first():
            child = Child(
                name='Emma Uwimana',
                age=5,
                diagnosis='Autism Spectrum Disorder',
                caregiver_id=caregiver.id
            )
            db.session.add(child)
            db.session.commit()
            
            # Create therapy plan
            therapy_plan = TherapyPlan(
                title='Communication Skills Development',
                description='Focus on improving verbal and non-verbal communication skills through structured activities.',
                child_id=child.id,
                therapist_id=therapist.id,
                start_date=date.today(),
                end_date=date.today() + timedelta(days=90)
            )
            db.session.add(therapy_plan)
            db.session.commit()
            
            # Create sample activities
            activities = [
                {
                    'title': 'Picture Exchange Communication',
                    'description': 'Use picture cards to help child communicate basic needs and wants.',
                    'frequency': 'Daily',
                    'duration_minutes': 15,
                    'instructions': '1. Show picture cards\n2. Encourage child to point or hand you the card\n3. Verbally state what the picture represents\n4. Reward successful communication'
                },
                {
                    'title': 'Social Story Reading',
                    'description': 'Read social stories to help child understand social situations.',
                    'frequency': 'Daily',
                    'duration_minutes': 10,
                    'instructions': '1. Choose appropriate social story\n2. Read with child\n3. Discuss the story\n4. Practice the social skill'
                },
                {
                    'title': 'Mirror Play Interaction',
                    'description': 'Use mirror play to encourage eye contact and social interaction.',
                    'frequency': '3 times per week',
                    'duration_minutes': 20,
                    'instructions': '1. Sit in front of mirror with child\n2. Make faces and gestures\n3. Encourage imitation\n4. Praise attempts at interaction'
                }
            ]
            
            for activity_data in activities:
                activity = Activity(
                    title=activity_data['title'],
                    description=activity_data['description'],
                    therapy_plan_id=therapy_plan.id,
                    frequency=activity_data['frequency'],
                    duration_minutes=activity_data['duration_minutes'],
                    instructions=activity_data['instructions']
                )
                db.session.add(activity)
            
            db.session.commit()
            print("Sample child and therapy plan created")
        
        # Create sample resources
        sample_resources = [
            {
                'title': 'Understanding Autism Spectrum Disorder',
                'description': 'A comprehensive guide for parents and caregivers about autism.',
                'file_type': 'pdf',
                'category': 'Education',
                'uploaded_by': therapist.id
            },
            {
                'title': 'Communication Strategies Video',
                'description': 'Video demonstrating effective communication techniques.',
                'file_type': 'video',
                'category': 'Communication',
                'uploaded_by': therapist.id
            },
            {
                'title': 'Sensory Activities Guide',
                'description': 'Collection of sensory activities for daily routine.',
                'file_type': 'pdf',
                'category': 'Activities',
                'uploaded_by': therapist.id
            }
        ]
        
        for resource_data in sample_resources:
            if not Resource.query.filter_by(title=resource_data['title']).first():
                resource = Resource(
                    title=resource_data['title'],
                    description=resource_data['description'],
                    file_type=resource_data['file_type'],
                    category=resource_data['category'],
                    uploaded_by=resource_data['uploaded_by'],
                    is_approved=True
                )
                db.session.add(resource)
        
        # Create sample forum post
        if not ForumPost.query.filter_by(title='Welcome to our community!').first():
            forum_post = ForumPost(
                title='Welcome to our community!',
                content='Hello everyone! This is a space where we can share experiences, ask questions, and support each other on our autism therapy journey. Feel free to introduce yourself and share your story.',
                author_id=therapist.id,
                category='General',
                is_approved=True
            )
            db.session.add(forum_post)
        
        # Create sample message
        if not Message.query.filter_by(subject='Welcome to the platform').first():
            message = Message(
                sender_id=therapist.id,
                recipient_id=caregiver.id,
                subject='Welcome to the platform',
                content='Hello! Welcome to our autism therapy platform. I\'m here to help you with Emma\'s therapy journey. Please don\'t hesitate to reach out if you have any questions about the therapy plan or activities.',
                is_read=False
            )
            db.session.add(message)
        
        db.session.commit()
        print("✓ Sample resources, forum post, and message created")

def reset_database():
    """Delete and recreate the database"""
    print("⚠ Resetting database (all data will be lost)...")
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("✓ Database reset successfully")

def main():
    """Main function to initialize the database"""
    print("=== Autism Therapy Platform Database Initialization ===\n")
    
    # Create uploads directory if it doesn't exist
    uploads_dir = os.path.join('static', 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
        print("Created uploads directory")
    
    create_database()
    create_sample_users()
    create_sample_data()
    
    print("\n=== Database Initialization Complete ===")
    print("\nYou can now run the application with: python app.py")
    print("\nDefault login credentials:")
    print("- Admin: admin / admin123")
    print("- Therapist: dr_smith / therapist123")
    print("- Caregiver: parent_john / parent123")
    print("\nAccess the application at: http://localhost:5000")

if __name__ == '__main__':
    main()