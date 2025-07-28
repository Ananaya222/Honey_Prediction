from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, ValidationError

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///honey.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(32)),
    WTF_CSRF_ENABLED=True
)

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20, message='Username must be between 4-20 characters'),
        Regexp(r'^[A-Za-z0-9]+$', message='Username can only contain letters and numbers')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters'),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)',
               message='Password must contain at least 1 letter and 1 number')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Increased for hashed passwords
    
    def __repr__(self):
        return f'<User {self.username}>'

# Helper functions
def init_db():
    with app.app_context():
        db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('home3.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('home'))

    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password, form.password.data):
            session['user'] = user.username
            flash('Logged in successfully!', 'success')
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('home'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login1.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('home'))

    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            new_user = User(
                username=form.username.data,
                password=generate_password_hash(form.password.data)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration', 'danger')
            app.logger.error(f'Registration error: {str(e)}')
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/purity-analysis')
@login_required
def purity_analysis():
    return render_template('purity1.html')

@app.route('/initial-analysis')
@login_required
def initial_analysis():
    return render_template('initial_analysis1.html')

@app.route('/honey-varieties')
def honey_varieties():
    return render_template('varieties1.html')

@app.route('/honey-uses')
def honey_uses():
    return render_template('honeyuse1.html')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
