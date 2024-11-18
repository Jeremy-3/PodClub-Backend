from flask import Flask, jsonify, request, session, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,get_jwt_identity
from models import db, User, Channel, Message, Report, ChannelMember
import os
import jwt 
from flask_migrate import Migrate
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

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



@app.route('/channels/<int:channel_id>/update_description', methods=['PUT'])
@jwt_required()
def update_channel_description(channel_id):
    current_user_id = session.get('user_id')
    

    channel = db.session.get(Channel, channel_id)

    if not channel:
        return jsonify({"msg": "Channel not found!"}), 404

    if channel.owner_id != current_user_id:
        return jsonify({"msg": "You do not have permission to edit this channel!"}), 403

    data = request.get_json()
    channel.description = data.get('description', channel.description)

    db.session.commit()
    return jsonify({"msg": "Channel description updated!"}), 200


@app.route('/channels/<int:channel_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_channel(channel_id):
    current_user_id = session.get('user_id')
    channel = db.session.query(Channel).get(channel_id)

    if not channel:
        return jsonify({"msg": "Channel not found!"}), 404

    if channel.owner_id != current_user_id:
        return jsonify({"msg": "You do not have permission to delete this channel!"}), 403

    db.session.delete(channel)
    db.session.commit()
    return jsonify({"msg": "Channel deleted successfully!"}), 200

# PyJWT for generating JWT tokens
import jwt  

@app.route('/channels/<int:channel_id>/invite', methods=['POST'])
@jwt_required()
def invite_to_channel(channel_id):
    current_user_id = session.get('user_id')
    channel = db.session.query(Channel).get(channel_id)

    if not channel or channel.owner_id != current_user_id:
        return jsonify({"msg": "You do not have permission to invite users to this channel!"}), 403

    invitee_email = request.json['email']
    invitee = db.session.query(User).filter_by(email=invitee_email).first()

    if invitee:
        if invitee in channel.members:
            return jsonify({"msg": "User is already a member of this channel!"}), 400
    else:
        invitee = None  

    #  PyJWT to create an invite token
    invite_token = jwt.encode(
        {'channel_id': channel_id, 'invitee_email': invitee_email},
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

    # Sending the invite link (for example, via email, here we just print it)
    invite_link = url_for('accept_invite', token=invite_token, _external=True)
    print(f"Send this link to the invitee: {invite_link}")

    return jsonify({"msg": "Invite sent successfully!"}), 200

@app.route('/accept_invite', methods=['GET'])
def accept_invite():
    token = request.args.get('token')

    if not token:
        return jsonify({"msg": "Missing token!"}), 400

    try:
        # Decoding the invite token
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        channel_id = data['channel_id']
        invitee_email = data['invitee_email']

        # Check if the channel exists
        channel = db.session.query(Channel).get(channel_id)
        if not channel:
            return jsonify({"msg": "Channel not found!"}), 404

        # Check if the user is logged in
        current_user_id = session.get('user_id')

        if not current_user_id:
            return jsonify({
                "msg": "You must be logged in to accept this invite.",
                "login_required": True
            }), 401

        # Get the user associated with the session
        current_user = db.session.query(User).get(current_user_id)

        # If the invitee is not registered yet, sign them up
        if not current_user:
            # Check if the invitee's email matches the one from the token
            if current_user_email != invitee_email:
                return jsonify({"msg": "The email doesn't match the invite!"}), 400

            # Proceed with sign up (this is just an example, you can extract from request)
            new_user = User(email=invitee_email, username=invitee_email.split('@')[0])
            new_user.set_password('default_password')  
            db.session.add(new_user)
            db.session.commit()

            current_user = new_user

        # Add the current user to the channel
        if current_user not in channel.members:
            channel.members.append(current_user)
            db.session.commit()
            return jsonify({"msg": "You have successfully joined the channel!"}), 200
        else:
            return jsonify({"msg": "You are already a member of this channel!"}), 400

    except jwt.ExpiredSignatureError:
        return jsonify({"msg": "Invite link expired!"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"msg": "Invalid invite token!"}), 400
    
    # Routes for Messages (Add, Update, Delete, etc.)
@app.route('/messages/<int:channel_id>', methods=['POST'])
@jwt_required()
def add_message(channel_id):
    current_user_id = session.get('user_id')
    data = request.get_json()

    channel = db.session.query(Channel).get(channel_id)

    if not channel:
        return jsonify({"msg": "Channel not found!"}), 404

    new_message = Message(content=data['content'], sender_id=current_user_id, channel_id=channel_id)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({"msg": "Message sent successfully!"}), 201

@app.route('/messages/<int:message_id>/update', methods=['PUT'])
@jwt_required()
def update_message(message_id):
    current_user_id = session.get('user_id')
    data = request.get_json()

    message = db.session.query(Message).get(message_id)

    if not message:
        return jsonify({"msg": "Message not found!"}), 404

    if message.sender_id != current_user_id:
        return jsonify({"msg": "You cannot edit other users' messages!"}), 403

    message.content = data['content']
    db.session.commit()

    return jsonify({"msg": "Message updated successfully!"}), 200
@app.route('/messages/<int:message_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    current_user_id = session.get('user_id')
    message = db.session.query(Message).get(message_id)

    if not message:
        return jsonify({"msg": "Message not found!"}), 404

    if message.sender_id != current_user_id:
        return jsonify({"msg": "You cannot delete other users' messages!"}), 403

    db.session.delete(message)
    db.session.commit()

    return jsonify({"msg": "Message deleted successfully!"}), 200

# Reporting a user (admin action)
@app.route('/report', methods=['POST'])
@jwt_required()
def report_user():
    current_user_id = session.get('user_id')
    data = request.get_json()

    reported_user_email = data.get('email')
    reason = data.get('reason')

    reported_user = db.session.query(User).filter_by(email=reported_user_email).first()
    if not reported_user:
        return jsonify({"msg": "User not found!"}), 404

    report = Report(user_id=current_user_id, reported_user_id=reported_user.id, reason=reason)
    db.session.add(report)
    db.session.commit()

    return jsonify({"msg": "Report submitted successfully!"}), 201


# Admin: Ban and Unban Users
@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@jwt_required()
def ban_user(user_id):
    # Admin check
    admin_check = check_admin()
    if admin_check:
        return admin_check

    user = db.session.query(User).get(user_id)
    if not user:
        return jsonify({"msg": "User not found!"}), 404

    user.is_banned = True
    db.session.commit()
    return jsonify({"msg": "User banned successfully!"}), 200


@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@jwt_required()
def unban_user(user_id):
    # Admin check
    admin_check = check_admin()
    if admin_check:
        return admin_check

    user = db.session.query(User).get(user_id)
    if not user:
        return jsonify({"msg": "User not found!"}), 404

    user.is_banned = False
    db.session.commit()
    return jsonify({"msg": "User unbanned successfully!"}), 200

@app.route('/messages/<int:channel_id>/reply/<int:message_id>', methods=['POST'])
@jwt_required()
def reply_to_message(channel_id, message_id):
    current_user_id = session.get('user_id')
    data = request.get_json()

    # Check if the original message exists
    original_message = db.session.query(Message).get(message_id)
    if not original_message:
        return jsonify({"msg": "Original message not found!"}), 404

    # Check if the channel exists
    channel = db.session.query(Channel).get(channel_id)
    if not channel:
        return jsonify({"msg": "Channel not found!"}), 404

    # Create a new message as a reply
    new_message = Message(
        content=data['content'],
        sender_id=current_user_id,
        channel_id=channel_id,
        reply_to_id=message_id 
    )

    db.session.add(new_message)
    db.session.commit()

    return jsonify({"msg": "Reply sent successfully!", "reply_id": new_message.id}), 201

# Get all reports (Admin only)
@app.route('/admin/reports', methods=['GET'])
@jwt_required()
def get_reports():
    # Admin check
    admin_check = check_admin()
    if admin_check:
        return admin_check

    # Query to get all reports
    reports = db.session.query(Report).all()
    report_list = [{
        "id": report.id,
        "reporter_id": report.user_id,
        "reported_user_id": report.reported_user_id,
        "reason": report.reason,
        #"timestamp": report.timestamp
    } for report in reports]

    return jsonify({"reports": report_list}), 200


# Get all channels (Admin only)
@app.route('/admin/channels', methods=['GET'])
@jwt_required()
def get_all_channels():
    # Admin check
    admin_check = check_admin()
    if admin_check:
        return admin_check

    # Query to get all channels
    channels = db.session.query(Channel).all()
    channel_list = [{
        "id": channel.id,
        "name": channel.name,
        "description": channel.description,
        "owner_id": channel.owner_id
    } for channel in channels]

    return jsonify({"channels": channel_list}), 200

@app.route('/user/channels', methods=['GET'])
@jwt_required()
def get_user_channels():
    # Get the current logged-in user's ID from the JWT token
    current_user_id = get_jwt_identity()
    
    if not current_user_id:
        return jsonify({"msg": "You need to be logged in to view your channels!"}), 401

    # Query for channels owned by the user
    owned_channels = db.session.query(Channel).filter(Channel.owner_id == current_user_id).all()

    # Query for channels where the user is a member
    invited_channels = (
        db.session.query(Channel)
        .join(ChannelMember, Channel.id == ChannelMember.channel_id)
        .filter(ChannelMember.user_id == current_user_id)
        .all()
    )

    # Combine the two lists and remove duplicates using a dictionary keyed by channel ID
    unique_channels = {channel.id: channel for channel in (owned_channels + invited_channels)}

    # Format the response to return channel details
    channel_list = [{
        "id": channel.id,
        "name": channel.name,
        "description": channel.description,
        "owner_id": channel.owner_id
    } for channel in unique_channels.values()]

    return jsonify({"channels": channel_list}), 200


if __name__ == '__main__':
    app.run(debug=True)