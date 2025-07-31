import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore, storage
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# --- UPDATED FIREBASE INITIALIZATION WITH ERROR CHECKING ---
# Initialize Firebase
if not firebase_admin._apps:
    # Check for required environment variables
    required_env_vars = [
        'FIREBASE_PROJECT_ID', 'FIREBASE_PRIVATE_KEY_ID', 'FIREBASE_PRIVATE_KEY',
        'FIREBASE_CLIENT_EMAIL', 'FIREBASE_CLIENT_ID', 'FIREBASE_CLIENT_CERT_URL',
        'FIREBASE_STORAGE_BUCKET'
    ]
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables for Firebase: {', '.join(missing_vars)}")

    # For Vercel deployment, we'll use environment variables
    firebase_config = {
        "type": "service_account",
        "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
        "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
        "private_key": os.environ.get('FIREBASE_PRIVATE_KEY').replace('\\n', '\n') if os.environ.get('FIREBASE_PRIVATE_KEY') else None,
        "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
        "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_CERT_URL')
    }
    # Add a check specifically for private_key
    if not firebase_config["private_key"]:
         raise ValueError("FIREBASE_PRIVATE_KEY environment variable is not set or is empty.")

    cred = credentials.Certificate(firebase_config)
    firebase_admin.initialize_app(cred, {
        'storageBucket': os.environ.get('FIREBASE_STORAGE_BUCKET')
    })
# --- END OF UPDATED FIREBASE INITIALIZATION ---

# Initialize Firestore and Storage
db = firestore.client()
bucket = storage.bucket()

# Custom User class (since we're not using SQLAlchemy)
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.password_hash = user_data.get('password_hash')
        self.role = user_data.get('role')
        self.full_name = user_data.get('full_name')
        self.phone = user_data.get('phone')
        self.created_at = user_data.get('created_at')
        self.is_active = user_data.get('is_active', True)
    
    def get_id(self):
        return str(self.id)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    # Fetch user from Firestore
    user_doc = db.collection('users').document(user_id).get()
    if user_doc.exists:
        user_data = user_doc.to_dict()
        user_data['id'] = user_doc.id
        return User(user_data)
    return None

# Helper functions for database operations
def get_user_by_username(username):
    users_ref = db.collection('users')
    query = users_ref.where('username', '==', username).limit(1).get()
    if query:
        user_doc = query[0]
        user_data = user_doc.to_dict()
        user_data['id'] = user_doc.id
        return User(user_data)
    return None

def get_user_by_email(email):
    users_ref = db.collection('users')
    query = users_ref.where('email', '==', email).limit(1).get()
    if query:
        user_doc = query[0]
        user_data = user_doc.to_dict()
        user_data['id'] = user_doc.id
        return User(user_data)
    return None

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        full_name = request.form['full_name']
        phone = request.form.get('phone', '')
        
        # Check if user already exists
        if get_user_by_username(username):
            flash('Username already exists')
            return render_template('register.html')
        if get_user_by_email(email):
            flash('Email already registered')
            return render_template('register.html')
        
        # Create new user in Firestore
        user_data = {
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'role': role,
            'full_name': full_name,
            'phone': phone,
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        
        user_ref = db.collection('users').add(user_data)
        flash('Registration successful!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'caregiver':
        # For caregivers, we need to fetch their children
        children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
        children = []
        for doc in children_docs:
            child_data = doc.to_dict()
            child_data['id'] = doc.id
            children.append(child_data)
        
        # Fetch recent progress logs for their children
        child_ids = [child['id'] for child in children]
        if child_ids:
            logs_query = db.collection('progress_logs').where('child_id', 'in', child_ids).order_by('created_at', direction=firestore.Query.DESCENDING).limit(5).get()
            recent_logs = []
            for doc in logs_query:
                log_data = doc.to_dict()
                log_data['id'] = doc.id
                recent_logs.append(log_data)
        else:
            recent_logs = []
            
        return render_template('dashboard_caregiver.html', children=children, recent_logs=recent_logs)
        
    elif current_user.role == 'therapist':
        # For therapists, fetch their therapy plans
        plans_docs = db.collection('therapy_plans').where('therapist_id', '==', current_user.id).get()
        therapy_plans = []
        for doc in plans_docs:
            plan_data = doc.to_dict()
            plan_data['id'] = doc.id
            therapy_plans.append(plan_data)
            
        # Fetch resources uploaded by this therapist
        resources_docs = db.collection('resources').where('uploaded_by', '==', current_user.id).get()
        resources = []
        for doc in resources_docs:
            resource_data = doc.to_dict()
            resource_data['id'] = doc.id
            resources.append(resource_data)
            
        return render_template('dashboard_therapist.html', therapy_plans=therapy_plans, resources=resources)
        
    elif current_user.role == 'admin':
        # For admin, get counts
        total_users = len(db.collection('users').get())
        total_children = len(db.collection('children').get())
        pending_resources = len(db.collection('resources').where('is_approved', '==', False).get())
        
        return render_template('dashboard_admin.html', 
                             total_users=total_users, 
                             total_children=total_children,
                             pending_resources=pending_resources)
                             
    return render_template('dashboard.html')

@app.route('/children')
@login_required
def children():
    if current_user.role != 'caregiver':
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
    children = []
    for doc in children_docs:
        child_data = doc.to_dict()
        child_data['id'] = doc.id
        children.append(child_data)
        
    return render_template('children.html', children=children)

@app.route('/add_child', methods=['GET', 'POST'])
@login_required
def add_child():
    if current_user.role != 'caregiver':
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        child_data = {
            'name': request.form['name'],
            'age': int(request.form['age']),
            'diagnosis': request.form['diagnosis'],
            'caregiver_id': current_user.id,
            'created_at': datetime.utcnow()
        }
        
        db.collection('children').add(child_data)
        flash('Child added successfully!')
        return redirect(url_for('children'))
        
    return render_template('add_child.html')

@app.route('/therapy_plans')
@login_required
def therapy_plans():
    if current_user.role == 'therapist':
        plans_docs = db.collection('therapy_plans').where('therapist_id', '==', current_user.id).get()
    elif current_user.role == 'caregiver':
        # Get children IDs for this caregiver
        children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
        child_ids = [doc.id for doc in children_docs]
        if child_ids:
            plans_docs = db.collection('therapy_plans').where('child_id', 'in', child_ids).get()
        else:
            plans_docs = []
    else:
        plans_docs = db.collection('therapy_plans').get()
        
    plans = []
    for doc in plans_docs:
        plan_data = doc.to_dict()
        plan_data['id'] = doc.id
        plans.append(plan_data)
        
    return render_template('therapy_plans.html', plans=plans)

@app.route('/create_therapy_plan', methods=['GET', 'POST'])
@login_required
def create_therapy_plan():
    if current_user.role != 'therapist':
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        start_date_str = request.form['start_date']
        end_date_str = request.form['end_date'] if request.form['end_date'] else None
        
        plan_data = {
            'title': request.form['title'],
            'description': request.form['description'],
            'child_id': request.form['child_id'],
            'therapist_id': current_user.id,
            'start_date': datetime.strptime(start_date_str, '%Y-%m-%d').date().isoformat(),
            'status': 'active',
            'created_at': datetime.utcnow()
        }
        
        if end_date_str:
            plan_data['end_date'] = datetime.strptime(end_date_str, '%Y-%m-%d').date().isoformat()
        
        db.collection('therapy_plans').add(plan_data)
        flash('Therapy plan created successfully!')
        return redirect(url_for('therapy_plans'))
    
    # Get all children for the dropdown
    children_docs = db.collection('children').get()
    children = []
    for doc in children_docs:
        child_data = doc.to_dict()
        child_data['id'] = doc.id
        children.append(child_data)
        
    return render_template('create_therapy_plan.html', children=children)

@app.route('/resources')
@login_required
def resources():
    if current_user.role == 'admin':
        resources_docs = db.collection('resources').get()
    else:
        resources_docs = db.collection('resources').where('is_approved', '==', True).get()
        
    resources = []
    for doc in resources_docs:
        resource_data = doc.to_dict()
        resource_data['id'] = doc.id
        resources.append(resource_data)
        
    return render_template('resources.html', resources=resources)

@app.route('/upload_resource', methods=['GET', 'POST'])
@login_required
def upload_resource():
    if current_user.role not in ['therapist', 'admin']:
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        file = request.files.get('file')
        file_path = None
        file_type = None
        
        if file and file.filename:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            
            # Upload to Firebase Storage
            blob = bucket.blob(f"uploads/{unique_filename}")
            
            # Save file temporarily and upload
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                file.save(temp_file.name)
                blob.upload_from_filename(temp_file.name)
            
            # Make the file publicly readable
            blob.make_public()
            file_path = blob.public_url
            file_type = filename.split('.')[-1].lower()
        
        resource_data = {
            'title': title,
            'description': description,
            'file_path': file_path,
            'file_type': file_type,
            'uploaded_by': current_user.id,
            'category': category,
            'is_approved': (current_user.role == 'admin'),
            'created_at': datetime.utcnow()
        }
        
        db.collection('resources').add(resource_data)
        flash('Resource uploaded successfully!')
        return redirect(url_for('resources'))
        
    return render_template('upload_resource.html')

@app.route('/messages')
@login_required
def messages():
    # Fetch sent messages
    sent_messages_docs = db.collection('messages').where('sender_id', '==', current_user.id).get()
    sent_messages = []
    for doc in sent_messages_docs:
        msg_data = doc.to_dict()
        msg_data['id'] = doc.id
        sent_messages.append(msg_data)
    
    # Fetch received messages
    received_messages_docs = db.collection('messages').where('recipient_id', '==', current_user.id).get()
    received_messages = []
    for doc in received_messages_docs:
        msg_data = doc.to_dict()
        msg_data['id'] = doc.id
        received_messages.append(msg_data)
        
    return render_template('messages.html', sent_messages=sent_messages, received_messages=received_messages)

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        message_data = {
            'sender_id': current_user.id,
            'recipient_id': request.form['recipient_id'],
            'subject': request.form['subject'],
            'content': request.form['content'],
            'is_read': False,
            'created_at': datetime.utcnow()
        }
        
        db.collection('messages').add(message_data)
        flash('Message sent successfully!')
        return redirect(url_for('messages'))
    
    # Get potential recipients based on user role
    if current_user.role == 'caregiver':
        recipients_docs = db.collection('users').where('role', '==', 'therapist').get()
    elif current_user.role == 'therapist':
        recipients_docs = db.collection('users').where('role', 'in', ['caregiver', 'therapist']).get()
    else:
        recipients_docs = db.collection('users').get()
        
    recipients = []
    for doc in recipients_docs:
        user_data = doc.to_dict()
        user_data['id'] = doc.id
        recipients.append(user_data)
        
    return render_template('send_message.html', recipients=recipients)

@app.route('/forum')
@login_required
def forum():
    posts_docs = db.collection('forum_posts').where('is_approved', '==', True).order_by('created_at', direction=firestore.Query.DESCENDING).get()
    posts = []
    for doc in posts_docs:
        post_data = doc.to_dict()
        post_data['id'] = doc.id
        posts.append(post_data)
        
    return render_template('forum.html', posts=posts)

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        post_data = {
            'title': request.form['title'],
            'content': request.form['content'],
            'author_id': current_user.id,
            'category': request.form['category'],
            'is_approved': True,
            'created_at': datetime.utcnow()
        }
        
        db.collection('forum_posts').add(post_data)
        flash('Post created successfully!')
        return redirect(url_for('forum'))
        
    return render_template('create_post.html')

@app.route('/progress')
@login_required
def progress():
    if current_user.role == 'caregiver':
        # Get children IDs for this caregiver
        children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
        child_ids = [doc.id for doc in children_docs]
        if child_ids:
            logs_docs = db.collection('progress_logs').where('child_id', 'in', child_ids).order_by('date', direction=firestore.Query.DESCENDING).get()
        else:
            logs_docs = []
    else:
        logs_docs = db.collection('progress_logs').order_by('date', direction=firestore.Query.DESCENDING).get()
        
    logs = []
    for doc in logs_docs:
        log_data = doc.to_dict()
        log_data['id'] = doc.id
        logs.append(log_data)
        
    return render_template('progress.html', logs=logs)

@app.route('/log_progress', methods=['GET', 'POST'])
@login_required
def log_progress():
    if current_user.role != 'caregiver':
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        log_data = {
            'child_id': request.form['child_id'],
            'activity_id': request.form['activity_id'] if request.form['activity_id'] else None,
            'date': datetime.strptime(request.form['date'], '%Y-%m-%d').date().isoformat(),
            'notes': request.form['notes'],
            'rating': int(request.form['rating']),
            'duration_minutes': int(request.form['duration_minutes']) if request.form['duration_minutes'] else None,
            'logged_by': current_user.id,
            'created_at': datetime.utcnow()
        }
        
        db.collection('progress_logs').add(log_data)
        flash('Progress logged successfully!')
        return redirect(url_for('progress'))
    
    # Get children for this caregiver
    children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
    children = []
    for doc in children_docs:
        child_data = doc.to_dict()
        child_data['id'] = doc.id
        children.append(child_data)
        
    # Get activities
    activities_docs = db.collection('activities').get()
    activities = []
    for doc in activities_docs:
        activity_data = doc.to_dict()
        activity_data['id'] = doc.id
        activities.append(activity_data)
        
    return render_template('log_progress.html', children=children, activities=activities)

# API Endpoints
@app.route('/api/children/<child_id>/progress')
@login_required
def api_child_progress(child_id):
    logs_docs = db.collection('progress_logs').where('child_id', '==', child_id).order_by('date').get()
    data = []
    for doc in logs_docs:
        log_data = doc.to_dict()
        # Convert date to string format
        if 'date' in log_data and log_data['date']:
            log_data['date'] = log_data['date'].isoformat() if isinstance(log_data['date'], datetime) else str(log_data['date'])
        data.append(log_data)
        
    return jsonify(data)

# Required for Vercel
handler = app

if __name__ == '__main__':
    app.run(debug=True)