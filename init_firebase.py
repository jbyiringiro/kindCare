#!/usr/bin/env python3
"""
Firebase initialization script for Autism Therapy Platform
Run this script to add sample data to Firestore
"""

import os
import sys
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash
from datetime import datetime, date, timedelta

# Initialize Firebase
def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    try:
        if not firebase_admin._apps:
            # Use environment variables or service account key file
            if os.environ.get('FIREBASE_PROJECT_ID'):
                # Use environment variables (for Vercel)
                firebase_config = {
                    "type": "service_account",
                    "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
                    "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
                    "private_key": os.environ.get('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
                    "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
                    "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_CERT_URL')
                }
                cred = credentials.Certificate(firebase_config)
            else:
                # Use service account key file (for local development)
                cred = credentials.Certificate("path/to/your/serviceAccountKey.json")
            
            firebase_admin.initialize_app(cred)
        return firestore.client()
    except Exception as e:
        print(f"Error initializing Firebase: {e}")
        sys.exit(1)

def create_sample_users(db):
    """Create sample users for testing"""
    print("Creating sample users...")
    
    # Admin user
    admin_data = {
        'username': 'admin',
        'email': 'admin@therapyplatform.com',
        'password_hash': generate_password_hash('admin123'),
        'role': 'admin',
        'full_name': 'System Administrator',
        'phone': '+250788123456',
        'created_at': datetime.utcnow(),
        'is_active': True
    }
    
    # Therapist user
    therapist_data = {
        'username': 'dr_smith',
        'email': 'therapist@therapyplatform.com',
        'password_hash': generate_password_hash('therapist123'),
        'role': 'therapist',
        'full_name': 'Dr. Sarah Smith',
        'phone': '+250788654321',
        'created_at': datetime.utcnow(),
        'is_active': True
    }
    
    # Caregiver user
    caregiver_data = {
        'username': 'parent_john',
        'email': 'parent@therapyplatform.com',
        'password_hash': generate_password_hash('parent123'),
        'role': 'caregiver',
        'full_name': 'John Uwimana',
        'phone': '+250788987654',
        'created_at': datetime.utcnow(),
        'is_active': True
    }
    
    # Check if users already exist and create them if they don't
    users_ref = db.collection('users')
    
    # Create admin user
    admin_query = users_ref.where('username', '==', 'admin').limit(1).get()
    if not admin_query:
        users_ref.add(admin_data)
        print("  - Admin user created")
    
    # Create therapist user
    therapist_query = users_ref.where('username', '==', 'dr_smith').limit(1).get()
    if not therapist_query:
        users_ref.add(therapist_data)
        print("  - Therapist user created")
    
    # Create caregiver user
    caregiver_query = users_ref.where('username', '==', 'parent_john').limit(1).get()
    if not caregiver_query:
        users_ref.add(caregiver_data)
        print("  - Caregiver user created")
    
    print("Sample users created successfully")
    print("  - Admin: admin / admin123")
    print("  - Therapist: dr_smith / therapist123")
    print("  - Caregiver: parent_john / parent123")

def create_sample_data(db):
    """Create sample children, therapy plans, and activities"""
    print("Creating sample data...")
    
    # Get users
    users_ref = db.collection('users')
    caregiver_query = users_ref.where('username', '==', 'parent_john').limit(1).get()
    therapist_query = users_ref.where('username', '==', 'dr_smith').limit(1).get()
    
    if not caregiver_query or not therapist_query:
        print("Sample users not found. Run create_sample_users() first.")
        return
    
    caregiver_id = caregiver_query[0].id
    therapist_id = therapist_query[0].id
    
    # Create sample child
    children_ref = db.collection('children')
    child_query = children_ref.where('name', '==', 'Emma Uwimana').limit(1).get()
    
    if not child_query:
        child_data = {
            'name': 'Emma Uwimana',
            'age': 5,
            'diagnosis': 'Autism Spectrum Disorder',
            'caregiver_id': caregiver_id,
            'created_at': datetime.utcnow()
        }
        
        child_ref = children_ref.add(child_data)
        child_id = child_ref[1].id
        
        # Create therapy plan
        therapy_plan_data = {
            'title': 'Communication Skills Development',
            'description': 'Focus on improving verbal and non-verbal communication skills through structured activities.',
            'child_id': child_id,
            'therapist_id': therapist_id,
            'start_date': date.today().isoformat(),
            'end_date': (date.today() + timedelta(days=90)).isoformat(),
            'status': 'active',
            'created_at': datetime.utcnow()
        }
        
        therapy_plans_ref = db.collection('therapy_plans')
        therapy_plan_ref = therapy_plans_ref.add(therapy_plan_data)
        therapy_plan_id = therapy_plan_ref[1].id
        
        # Create sample activities
        activities_data = [
            {
                'title': 'Picture Exchange Communication',
                'description': 'Use picture cards to help child communicate basic needs and wants.',
                'therapy_plan_id': therapy_plan_id,
                'frequency': 'Daily',
                'duration_minutes': 15,
                'instructions': '1. Show picture cards\n2. Encourage child to point or hand you the card\n3. Verbally state what the picture represents\n4. Reward successful communication',
                'created_at': datetime.utcnow()
            },
            {
                'title': 'Social Story Reading',
                'description': 'Read social stories to help child understand social situations.',
                'therapy_plan_id': therapy_plan_id,
                'frequency': 'Daily',
                'duration_minutes': 10,
                'instructions': '1. Choose appropriate social story\n2. Read with child\n3. Discuss the story\n4. Practice the social skill',
                'created_at': datetime.utcnow()
            },
            {
                'title': 'Mirror Play Interaction',
                'description': 'Use mirror play to encourage eye contact and social interaction.',
                'therapy_plan_id': therapy_plan_id,
                'frequency': '3 times per week',
                'duration_minutes': 20,
                'instructions': '1. Sit in front of mirror with child\n2. Make faces and gestures\n3. Encourage imitation\n4. Praise attempts at interaction',
                'created_at': datetime.utcnow()
            }
        ]
        
        activities_ref = db.collection('activities')
        for activity_data in activities_data:
            activities_ref.add(activity_data)
        
        print("Sample child and therapy plan created")
    
    # Create sample resources
    resources_ref = db.collection('resources')
    sample_resources = [
        {
            'title': 'Understanding Autism Spectrum Disorder',
            'description': 'A comprehensive guide for parents and caregivers about autism.',
            'file_type': 'pdf',
            'category': 'Education',
            'uploaded_by': therapist_id,
            'is_approved': True,
            'created_at': datetime.utcnow()
        },
        {
            'title': 'Communication Strategies Video',
            'description': 'Video demonstrating effective communication techniques.',
            'file_type': 'video',
            'category': 'Communication',
            'uploaded_by': therapist_id,
            'is_approved': True,
            'created_at': datetime.utcnow()
        },
        {
            'title': 'Sensory Activities Guide',
            'description': 'Collection of sensory activities for daily routine.',
            'file_type': 'pdf',
            'category': 'Activities',
            'uploaded_by': therapist_id,
            'is_approved': True,
            'created_at': datetime.utcnow()
        }
    ]
    
    for resource_data in sample_resources:
        resource_query = resources_ref.where('title', '==', resource_data['title']).limit(1).get()
        if not resource_query:
            resources_ref.add(resource_data)
    
    # Create sample forum post
    forum_posts_ref = db.collection('forum_posts')
    forum_query = forum_posts_ref.where('title', '==', 'Welcome to our community!').limit(1).get()
    if not forum_query:
        forum_post_data = {
            'title': 'Welcome to our community!',
            'content': 'Hello everyone! This is a space where we can share experiences, ask questions, and support each other on our autism therapy journey. Feel free to introduce yourself and share your story.',
            'author_id': therapist_id,
            'category': 'General',
            'is_approved': True,
            'created_at': datetime.utcnow()
        }
        forum_posts_ref.add(forum_post_data)
    
    # Create sample message
    messages_ref = db.collection('messages')
    message_query = messages_ref.where('subject', '==', 'Welcome to the platform').limit(1).get()
    if not message_query:
        message_data = {
            'sender_id': therapist_id,
            'recipient_id': caregiver_id,
            'subject': 'Welcome to the platform',
            'content': 'Hello! Welcome to our autism therapy platform. I\'m here to help you with Emma\'s therapy journey. Please don\'t hesitate to reach out if you have any questions about the therapy plan or activities.',
            'is_read': False,
            'created_at': datetime.utcnow()
        }
        messages_ref.add(message_data)
    
    print("✓ Sample resources, forum post, and message created")

def main():
    """Main function to initialize Firebase with sample data"""
    print("=== Autism Therapy Platform Firebase Initialization ===\n")
    
    # Initialize Firebase
    db = initialize_firebase()
    
    # Create sample data
    create_sample_users(db)
    create_sample_data(db)
    
    print("\n=== Firebase Initialization Complete ===")
    print("\nDefault login credentials:")
    print("- Admin: admin / admin123")
    print("- Therapist: dr_smith / therapist123")
    print("- Caregiver: parent_john / parent123")

if __name__ == '__main__':
    main()