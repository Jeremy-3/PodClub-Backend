from flask import Flask, jsonify, request, session, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from models import db, User, Channel, Message, Report, ChannelMember
import os
import jwt 
from flask_migrate import Migrate

# Initialize Flask app
app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///podclub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

@app.route('/')
def home():
    return "Welcome to PodClub!"


# Utility function to check if a file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Auth Routes (Register, Login)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Ensure required fields are provided
    if 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({"msg": "Missing required fields"}), 400

    # Role validation (only allow "admin" or "user" roles) and make user default
    role = data.get('role', 'user')  
    if role not in ['admin', 'user']:
        return jsonify({"msg": "Invalid role. It should be 'admin' or 'user'."}), 400

    # Security: Ensure that only a trusted user can sign in  "admin" role
    if role == 'admin':
        # For example, only an authenticated admin can create other admins
        if not current_user.is_admin:
            return jsonify({"msg": "Only an admin can create other admins."}), 403

    # Create the new user
    new_user = User(
        username=data['username'],
        email=data['email'],
        role=role  
    )
    # Hash the password using the set_password method
    new_user.set_password(data['password'])  

    # Add the new user to the database and commit the session
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "User registered successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error registering user", "error": str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = db.session.query(User).filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):  
        access_token = create_access_token(identity=user.id)
        session['user_id'] = user.id
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Invalid credentials"}), 401

# Admin Auth (Admin Login)
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    user = db.session.query(User).filter_by(email=data['email']).first()
    if user and user.check_password(data['password']) and user.role == 'admin': 
        access_token = create_access_token(identity=user.id)
        session['user_id'] = user.id
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Invalid admin credentials"}), 401

# check if user is an admin
def check_admin():
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({"msg": "You need to be logged in to perform this action!"}), 401

    user = db.session.query(User).get(current_user_id)
    if user is None or user.role != 'admin':
        return jsonify({"msg": "You do not have permission to perform this action!"}), 403
    
    
# Routes for Channels (Create, Update, Delete, Invite, etc.)
@app.route('/channels', methods=['POST'])
@jwt_required()
def create_channel():
    current_user_id = session.get('user_id')
    data = request.get_json()
    channel_name = data['name']
    channel_description = data.get('description', '')

    user_channels_count = db.session.query(Channel).filter_by(owner_id=current_user_id).count()
    if user_channels_count >= 5:
        return jsonify({"msg": "You can only create up to 5 channels."}), 400

    new_channel = Channel(name=channel_name, description=channel_description, owner_id=current_user_id)
    db.session.add(new_channel)
    db.session.commit()
    return jsonify({"msg": "Channel created successfully!"}), 201
