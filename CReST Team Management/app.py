from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Define the view where users are redirected if not logged in

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    profile_picture = db.Column(db.String(200), nullable=True, default=None)
    
# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility Functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return render_template('home.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Ensure all fields are present
        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", 'danger')
            return redirect(url_for('register'))

        # Validate that both password fields match
        if password != confirm_password:
            flash("Passwords do not match.", 'danger')
            return redirect(url_for('register'))

        # Validate if the username or email already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists.", 'danger')
            return redirect(url_for('register'))

        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash("Email already exists.", 'danger')
            return redirect(url_for('register'))

        # Hash the password before saving it
        hashed_password = generate_password_hash(password)

        # Check if it's the first user in the system
        user_count = User.query.count()

        # Assign 'admin' role to the first user, 'user' role to subsequent users
        if user_count == 0:
            role = 'admin'  # First user is an admin
        else:
            role = 'user'  # All subsequent users are regular users

        # Create a new user
        new_user = User(username=username, email=email, password=hashed_password, role=role)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Profile Route
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get('username')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        profile_picture = request.files.get('profile_picture')

        # Optionally handle the current password check if the new password is provided
        if new_password and current_password:
            if not check_password_hash(current_user.password, current_password):
                flash("Current password is incorrect.", 'danger')
                return redirect(url_for('profile'))

            # Check if new password and confirm password match
            if new_password != confirm_password:
                flash("New passwords do not match.", 'danger')
                return redirect(url_for('profile'))

            # Update the password
            current_user.password = generate_password_hash(new_password)

        # Update the username if it's different
        if username != current_user.username:
            current_user.username = username

        # Handle profile picture upload (optional)
        if profile_picture:
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_picture.filename)
            profile_picture.save(profile_picture_path)
            current_user.profile_picture = profile_picture_path

        # Commit the changes to the database
        db.session.commit()

        flash("Profile updated successfully.", 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')  # Get 'username' from the form
        password = request.form.get('password')  # Get 'password' from the form

        if not username or not password:
            flash('Please provide both username and password.', 'danger')
            return redirect(url_for('login'))

        # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # If login is successful, log in the user
            session['user_id'] = user.id
            session['user_role'] = user.role
            login_user(user)  # Use Flask-Login to log in the user
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    return redirect(url_for('confirm_logout'))

@app.route('/confirm_logout', methods=['GET', 'POST'])
@login_required
def confirm_logout():
    if request.method == 'POST':
        if 'yes' in request.form:
            # Clear the session and log the user out
            session.clear()
            flash('Logged out successfully.', 'success')
            return redirect(url_for('home'))
        elif 'no' in request.form:
            # Redirect the user back to the profile or home page
            return redirect(url_for('home'))  # or url_for('profile') if you want to return to profile
    
    return render_template('confirm_logout.html')

# Admin Route
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin():
    users = User.query.all()
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')
        
        user = User.query.get(user_id)
        if user:
            user.role = new_role
            db.session.commit()
            flash(f"Role updated to {new_role}.", 'success')
            return redirect(url_for('admin'))
        else:
            flash("User not found.", 'danger')
    
    return render_template('admin.html', users=users)

@app.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin'))

# Automated backup system (script example, not scheduled within app.py itself)
@app.route('/backup')
def backup():
    db_path = 'users.db'
    backup_dir = 'backups/'
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_filename = f"users_backup_{timestamp}.db"
    shutil.copy(db_path, os.path.join(backup_dir, backup_filename))
    flash(f"Backup created at {os.path.join(backup_dir, backup_filename)}", 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all tables before running the app
    app.run(debug=True, port=5007)
