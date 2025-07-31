from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///therapy_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # caregiver, therapist, admin
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    therapy_plans = db.relationship('TherapyPlan', backref='therapist', lazy=True, foreign_keys='TherapyPlan.therapist_id')
    children = db.relationship('Child', backref='caregiver', lazy=True)
    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    forum_posts = db.relationship('ForumPost', backref='author', lazy=True)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    diagnosis = db.Column(db.String(200))
    caregiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    therapy_plans = db.relationship('TherapyPlan', backref='child', lazy=True)
    progress_logs = db.relationship('ProgressLog', backref='child', lazy=True)

class TherapyPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    status = db.Column(db.String(20), default='active')  # active, completed, paused
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    activities = db.relationship('Activity', backref='therapy_plan', lazy=True)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    therapy_plan_id = db.Column(db.Integer, db.ForeignKey('therapy_plan.id'), nullable=False)
    frequency = db.Column(db.String(50))  # daily, weekly, etc.
    duration_minutes = db.Column(db.Integer)
    instructions = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProgressLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'))
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    rating = db.Column(db.Integer)  # 1-5 scale
    duration_minutes = db.Column(db.Integer)
    logged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(300))
    file_type = db.Column(db.String(50))  # video, pdf, image, article
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100))
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    recipient = db.relationship('User', foreign_keys=[recipient_id])

class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100))
    is_approved = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    replies = db.relationship('ForumReply', backref='post', lazy=True)

class ForumReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('forum_post.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    author = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            full_name=full_name,
            phone=phone
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
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
        children = Child.query.filter_by(caregiver_id=current_user.id).all()
        recent_logs = ProgressLog.query.filter(
            ProgressLog.child_id.in_([child.id for child in children])
        ).order_by(ProgressLog.created_at.desc()).limit(5).all()
        return render_template('dashboard_caregiver.html', children=children, recent_logs=recent_logs)
    
    elif current_user.role == 'therapist':
        therapy_plans = TherapyPlan.query.filter_by(therapist_id=current_user.id).all()
        resources = Resource.query.filter_by(uploaded_by=current_user.id).all()
        return render_template('dashboard_therapist.html', therapy_plans=therapy_plans, resources=resources)
    
    elif current_user.role == 'admin':
        total_users = User.query.count()
        total_children = Child.query.count()
        pending_resources = Resource.query.filter_by(is_approved=False).count()
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
    
    children = Child.query.filter_by(caregiver_id=current_user.id).all()
    return render_template('children.html', children=children)

@app.route('/add_child', methods=['GET', 'POST'])
@login_required
def add_child():
    if current_user.role != 'caregiver':
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        child = Child(
            name=request.form['name'],
            age=int(request.form['age']),
            diagnosis=request.form['diagnosis'],
            caregiver_id=current_user.id
        )
        db.session.add(child)
        db.session.commit()
        flash('Child added successfully!')
        return redirect(url_for('children'))
    
    return render_template('add_child.html')

@app.route('/therapy_plans')
@login_required
def therapy_plans():
    if current_user.role == 'therapist':
        plans = TherapyPlan.query.filter_by(therapist_id=current_user.id).all()
    elif current_user.role == 'caregiver':
        child_ids = [child.id for child in current_user.children]
        plans = TherapyPlan.query.filter(TherapyPlan.child_id.in_(child_ids)).all()
    else:
        plans = TherapyPlan.query.all()
    
    return render_template('therapy_plans.html', plans=plans)

@app.route('/create_therapy_plan', methods=['GET', 'POST'])
@login_required
def create_therapy_plan():
    if current_user.role != 'therapist':
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        plan = TherapyPlan(
            title=request.form['title'],
            description=request.form['description'],
            child_id=int(request.form['child_id']),
            therapist_id=current_user.id,
            start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d').date(),
            end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d').date() if request.form['end_date'] else None
        )
        db.session.add(plan)
        db.session.commit()
        flash('Therapy plan created successfully!')
        return redirect(url_for('therapy_plans'))
    
    children = Child.query.all()
    return render_template('create_therapy_plan.html', children=children)

@app.route('/resources')
@login_required
def resources():
    if current_user.role == 'admin':
        resources = Resource.query.all()
    else:
        resources = Resource.query.filter_by(is_approved=True).all()
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
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            file_type = filename.split('.')[-1].lower()
        
        resource = Resource(
            title=title,
            description=description,
            file_path=file_path,
            file_type=file_type,
            uploaded_by=current_user.id,
            category=category,
            is_approved=(current_user.role == 'admin')
        )
        
        db.session.add(resource)
        db.session.commit()
        flash('Resource uploaded successfully!')
        return redirect(url_for('resources'))
    
    return render_template('upload_resource.html')

@app.route('/messages')
@login_required
def messages():
    sent_messages = Message.query.filter_by(sender_id=current_user.id).all()
    received_messages = Message.query.filter_by(recipient_id=current_user.id).all()
    return render_template('messages.html', sent_messages=sent_messages, received_messages=received_messages)

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        message = Message(
            sender_id=current_user.id,
            recipient_id=int(request.form['recipient_id']),
            subject=request.form['subject'],
            content=request.form['content']
        )
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully!')
        return redirect(url_for('messages'))
    
    # Get potential recipients based on user role
    if current_user.role == 'caregiver':
        recipients = User.query.filter_by(role='therapist').all()
    elif current_user.role == 'therapist':
        recipients = User.query.filter(User.role.in_(['caregiver', 'therapist'])).all()
    else:
        recipients = User.query.all()
    
    return render_template('send_message.html', recipients=recipients)

@app.route('/forum')
@login_required
def forum():
    posts = ForumPost.query.filter_by(is_approved=True).order_by(ForumPost.created_at.desc()).all()
    return render_template('forum.html', posts=posts)

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        post = ForumPost(
            title=request.form['title'],
            content=request.form['content'],
            author_id=current_user.id,
            category=request.form['category']
        )
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully!')
        return redirect(url_for('forum'))
    
    return render_template('create_post.html')

@app.route('/progress')
@login_required
def progress():
    if current_user.role == 'caregiver':
        child_ids = [child.id for child in current_user.children]
        logs = ProgressLog.query.filter(ProgressLog.child_id.in_(child_ids)).order_by(ProgressLog.date.desc()).all()
    else:
        logs = ProgressLog.query.order_by(ProgressLog.date.desc()).all()
    
    return render_template('progress.html', logs=logs)

@app.route('/log_progress', methods=['GET', 'POST'])
@login_required
def log_progress():
    if current_user.role != 'caregiver':
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        log = ProgressLog(
            child_id=int(request.form['child_id']),
            activity_id=int(request.form['activity_id']) if request.form['activity_id'] else None,
            date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
            notes=request.form['notes'],
            rating=int(request.form['rating']),
            duration_minutes=int(request.form['duration_minutes']) if request.form['duration_minutes'] else None,
            logged_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        flash('Progress logged successfully!')
        return redirect(url_for('progress'))
    
    children = Child.query.filter_by(caregiver_id=current_user.id).all()
    activities = Activity.query.all()
    return render_template('log_progress.html', children=children, activities=activities)

# API Endpoints
@app.route('/api/children/<int:child_id>/progress')
@login_required
def api_child_progress(child_id):
    logs = ProgressLog.query.filter_by(child_id=child_id).order_by(ProgressLog.date).all()
    data = [{
        'date': log.date.strftime('%Y-%m-%d'),
        'rating': log.rating,
        'duration': log.duration_minutes,
        'notes': log.notes
    } for log in logs]
    return jsonify(data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)