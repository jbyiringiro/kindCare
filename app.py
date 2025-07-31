# app.py
import os
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore, storage
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# --- Initialize Flask app ---
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-fallback-secret-key-change-for-prod')
# Set maximum upload size (e.g., 16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# --- Initialize Firebase ---
# Check if Firebase app is already initialized (important for some environments)
if not firebase_admin._apps:
    # --- Critical: Check for required environment variables ---
    required_env_vars = [
        'FIREBASE_PROJECT_ID', 'FIREBASE_PRIVATE_KEY_ID', 'FIREBASE_PRIVATE_KEY',
        'FIREBASE_CLIENT_EMAIL', 'FIREBASE_CLIENT_ID', 'FIREBASE_CLIENT_CERT_URL',
        'FIREBASE_STORAGE_BUCKET'
    ]
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    if missing_vars:
        # Provide a clear error message if variables are missing
        raise ValueError(f"Missing required environment variables for Firebase setup: {', '.join(missing_vars)}. Please set these in your Render Dashboard.")

    # Prepare Firebase configuration using environment variables
    # The replace('\\n', '\n') is crucial if the private key in the env var uses literal \n characters.
    firebase_config = {
        "type": "service_account",
        "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
        "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
        "private_key": os.environ.get('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
        "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
        "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
        # These URLs are standard for Google OAuth2 and don't usually need to be env vars,
        # but we'll use them from env if provided, with fallbacks.
        "auth_uri": os.environ.get('FIREBASE_AUTH_URI', "https://accounts.google.com/o/oauth2/auth"),
        "token_uri": os.environ.get('FIREBASE_TOKEN_URI', "https://oauth2.googleapis.com/token"),
        "auth_provider_x509_cert_url": os.environ.get('FIREBASE_AUTH_PROVIDER_CERT_URL', "https://www.googleapis.com/oauth2/v1/certs"),
        "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_CERT_URL')
    }

    # Initialize Firebase Admin SDK
    try:
        cred = credentials.Certificate(firebase_config)
        firebase_admin.initialize_app(cred, {
            'storageBucket': os.environ.get('FIREBASE_STORAGE_BUCKET')
        })
        print("Firebase initialized successfully.")
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Firebase: {e}")

# Initialize Firestore and Storage clients
try:
    db = firestore.client()
    bucket = storage.bucket()
    print("Firestore and Storage clients initialized.")
except Exception as e:
    raise RuntimeError(f"Failed to get Firestore/Storage clients: {e}")

# --- User Management ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.password_hash = user_data.get('password_hash')
        self.role = user_data.get('role')
        self.full_name = user_data.get('full_name')
        self.phone = user_data.get('phone')
        # Assuming 'created_at' is stored as a Firestore timestamp or datetime string
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
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            user_data['id'] = user_doc.id
            return User(user_data)
        else:
            return None
    except Exception as e:
        print(f"Error loading user {user_id}: {e}")
        return None # Or handle error as appropriate

# --- Helper Functions ---
def get_user_by_username(username):
    try:
        print(f"DEBUG: Querying Firestore for user with username: '{username}'")
        users_ref = db.collection('users')
        print("DEBUG: Building query object...")
        # --- Use the new style filter to remove the UserWarning ---
        # query_obj = users_ref.where(filter=FieldFilter("username", "==", username)).limit(1)
        # --- OR, keep the old style but be aware of the warning ---
        query_obj = users_ref.where('username', '==', username).limit(1)
        print("DEBUG: Executing query.get()...")
        query = query_obj.get() # <--- This is the likely point of hanging
        print(f"DEBUG: Query executed. Number of documents found: {len(query)}")
        if query:
            user_doc = query[0]
            user_data = user_doc.to_dict()
            user_data['id'] = user_doc.id
            print(f"DEBUG: User data loaded: {user_data.get('username')}")
            return User(user_data)
        print("DEBUG: No user found with that username.")
        return None
    except Exception as e:
        print(f"ERROR: Exception in get_user_by_username for '{username}': {e}")
        import traceback
        traceback.print_exc() # Print the full stack trace for debugging
        return None

def get_user_by_email(email):
    try:
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).limit(1).get()
        if query:
            user_doc = query[0]
            user_data = user_doc.to_dict()
            user_data['id'] = user_doc.id
            return User(user_data)
        return None
    except Exception as e:
        print(f"Error fetching user by email {email}: {e}")
        return None

# --- Routes ---

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
            flash('Username already exists', 'error')
            return render_template('register.html')
        if get_user_by_email(email):
            flash('Email already registered', 'error')
            return render_template('register.html')

        # Create new user data
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

        try:
            # Add user to Firestore
            db.collection('users').add(user_data)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error creating user: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if current_user.role == 'caregiver':
            # Fetch children for the caregiver
            children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
            children = []
            for doc in children_docs:
                child_data = doc.to_dict()
                child_data['id'] = doc.id
                children.append(child_data)

            # Fetch recent progress logs for their children
            child_ids = [child['id'] for child in children]
            recent_logs = []
            if child_ids:
                # Limit to last 5 logs across all children
                logs_query = db.collection('progress_logs').where('child_id', 'in', child_ids).order_by('created_at', direction=firestore.Query.DESCENDING).limit(5).get()
                for doc in logs_query:
                    log_data = doc.to_dict()
                    log_data['id'] = doc.id
                    recent_logs.append(log_data)

            return render_template('dashboard_caregiver.html', children=children, recent_logs=recent_logs)

        elif current_user.role == 'therapist':
            # Fetch therapy plans for the therapist
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
            # Fetch counts for admin dashboard
            total_users = len(db.collection('users').get())
            total_children = len(db.collection('children').get())
            pending_resources = len(db.collection('resources').where('is_approved', '==', False).get())

            return render_template('dashboard_admin.html',
                                 total_users=total_users,
                                 total_children=total_children,
                                 pending_resources=pending_resources)

        else:
            # Default dashboard if role is unrecognized
            return render_template('dashboard.html')
    except Exception as e:
        print(f"Error loading dashboard for user {current_user.id}: {e}")
        flash('An error occurred loading the dashboard.', 'error')
        return render_template('dashboard.html')


# --- Example of a more complex route using Firestore ---
@app.route('/children')
@login_required
def children():
    if current_user.role != 'caregiver':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    try:
        children_docs = db.collection('children').where('caregiver_id', '==', current_user.id).get()
        children = []
        for doc in children_docs:
            child_data = doc.to_dict()
            child_data['id'] = doc.id
            children.append(child_data)
        return render_template('children.html', children=children)
    except Exception as e:
        print(f"Error fetching children for user {current_user.id}: {e}")
        flash('An error occurred fetching children.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_child', methods=['GET', 'POST'])
@login_required
def add_child():
    if current_user.role != 'caregiver':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            child_data = {
                'name': request.form['name'],
                'age': int(request.form['age']),
                'diagnosis': request.form['diagnosis'],
                'caregiver_id': current_user.id,
                'created_at': datetime.utcnow()
            }
            db.collection('children').add(child_data)
            flash('Child added successfully!', 'success')
            return redirect(url_for('children'))
        except ValueError:
            flash('Invalid age provided.', 'error')
        except Exception as e:
            print(f"Error adding child: {e}")
            flash('An error occurred adding the child.', 'error')

    return render_template('add_child.html')

# --- Example of a route using Firebase Storage ---
@app.route('/upload_resource', methods=['GET', 'POST'])
@login_required
def upload_resource():
    if current_user.role not in ['therapist', 'admin']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        file = request.files.get('file')

        file_path = None
        file_type = None

        if file and file.filename:
            try:
                filename = secure_filename(file.filename)
                # Create a unique filename
                unique_filename = f"{uuid.uuid4()}_{filename}"
                
                # Upload to Firebase Storage
                blob = bucket.blob(f"uploads/{unique_filename}")

                # Save file temporarily and upload
                # tempfile.NamedTemporaryFile creates a temporary file on disk
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    file.save(temp_file.name)
                    # Upload the temporary file to Firebase Storage
                    blob.upload_from_filename(temp_file.name)
                
                # Make the file publicly readable (optional, depends on your needs)
                blob.make_public()
                # Get the public URL
                file_path = blob.public_url
                # Determine file type from extension
                file_type = filename.split('.')[-1].lower() if '.' in filename else 'unknown'

            except Exception as e:
                print(f"Error uploading file: {e}")
                flash('An error occurred uploading the file.', 'error')
                # If file upload fails, we might still want to save the resource metadata?
                # Or redirect back. Let's redirect for simplicity.
                return render_template('upload_resource.html')

        # Prepare resource data for Firestore
        resource_data = {
            'title': title,
            'description': description,
            'file_path': file_path, # Will be None if no file was uploaded
            'file_type': file_type,
            'uploaded_by': current_user.id,
            'category': category,
            'is_approved': (current_user.role == 'admin'), # Auto-approve if admin uploads
            'created_at': datetime.utcnow()
        }

        try:
            # Save resource metadata to Firestore
            db.collection('resources').add(resource_data)
            flash('Resource uploaded successfully!', 'success')
            return redirect(url_for('resources')) # Assuming you have a /resources route
        except Exception as e:
            print(f"Error saving resource metadata: {e}")
            flash('An error occurred saving the resource information.', 'error')
            # If Firestore save fails after file upload, the file will remain in Storage.
            # Consider implementing cleanup logic if needed.
            return render_template('upload_resource.html')

    return render_template('upload_resource.html')

# --- Example of a route fetching data from Firestore ---
@app.route('/resources')
@login_required
def resources():
    try:
        if current_user.role == 'admin':
            # Admin sees all resources
            resources_docs = db.collection('resources').get()
        else:
            # Others see only approved resources
            resources_docs = db.collection('resources').where('is_approved', '==', True).get()

        resources = []
        for doc in resources_docs:
            resource_data = doc.to_dict()
            resource_data['id'] = doc.id
            resources.append(resource_data)

        return render_template('resources.html', resources=resources)
    except Exception as e:
        print(f"Error fetching resources: {e}")
        flash('An error occurred fetching resources.', 'error')
        return render_template('resources.html', resources=[]) # Return empty list on error

# --- API Endpoint Example ---
@app.route('/api/children/<child_id>/progress')
@login_required
def api_child_progress(child_id):
    # Basic authorization check (ensure the user has access to this child's data)
    # This is a simplified check. In a real app, you'd verify the child belongs to the user.
    try:
        # Fetch logs for the specific child, ordered by date
        logs_docs = db.collection('progress_logs').where('child_id', '==', child_id).order_by('date').get()
        data = []
        for doc in logs_docs:
            log_data = doc.to_dict()
            # Ensure 'date' is serializable. Firestore timestamps need special handling.
            # If it's a date object or string, this should work.
            # If it's a DatetimeWithNanoseconds, you might need to convert it.
            if 'date' in log_data:
                 # Convert date to ISO format string for JSON serialization
                if hasattr(log_data['date'], 'isoformat'):
                    log_data['date'] = log_data['date'].isoformat()
                else:
                    # If it's already a string or compatible, leave it.
                    # You might need more specific handling based on how you store dates.
                    pass
            data.append(log_data)
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching progress data for child {child_id}: {e}")
        # Return an error response
        return jsonify({'error': 'Failed to fetch progress data'}), 500


# --- Placeholder routes for other features ---
# You'll need to implement these similarly, replacing SQLAlchemy queries with Firestore operations.
@app.route('/therapy_plans')
@login_required
def therapy_plans():
    # Implement using Firestore queries like above
    flash('Therapy plans feature is a placeholder. Implement using Firestore.', 'info')
    return render_template('therapy_plans.html', plans=[])

@app.route('/messages')
@login_required
def messages():
    # Implement using Firestore queries for 'messages' collection
    flash('Messages feature is a placeholder. Implement using Firestore.', 'info')
    return render_template('messages.html', sent_messages=[], received_messages=[])

@app.route('/forum')
@login_required
def forum():
     # Implement using Firestore queries for 'forum_posts' collection
    flash('Forum feature is a placeholder. Implement using Firestore.', 'info')
    return render_template('forum.html', posts=[])

@app.route('/progress')
@login_required
def progress():
     # Implement using Firestore queries for 'progress_logs' collection
    flash('Progress tracking feature is a placeholder. Implement using Firestore.', 'info')
    return render_template('progress.html', logs=[])

# --- Hook for Render ---
# Render expects the WSGI callable to be named `app`
# Gunicorn will use this when started with `gunicorn app:app`
handler = app

if __name__ == '__main__':
    # Running locally with `python app.py`
    app.run(debug=True) # Set debug=False in production
