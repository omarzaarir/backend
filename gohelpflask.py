from flask import Flask, jsonify, request ,send_file
import pymysql 
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import hashlib 
import time # for current date, time
from datetime import timedelta
import re
import dns.resolver # library to valid the email
from datetime import datetime
import firebase_admin
from firebase_admin import credentials,messaging
from sqlalchemy import or_ # like string matching, search for string or sub string
# from flask_socketio import SocketIO,join_room, leave_room, emit
import os

# ---------------------------------------------- Config --------------------------------------------------

app = Flask(__name__)
CORS(app)
# socketio = SocketIO(app)

UPLOAD_FOLDER = 'eventImage'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/gohelp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24,days=2)


db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ---------------------------------------------- UPLOAD IMAGES ------------------------------------------------


@app.route('/upload', methods=['POST'])
# @login_required
def upload_image():
    try:
     if 'image' not in request.files:
         return jsonify({"error": "No image file part in the request"}), 400
    
     file = request.files['image']
    
     if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

     if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            return jsonify({"message": "Image uploaded successfully", "filepath": filepath}), 200
   
    except Exception as e: # Rollback the transaction in case of error
        return jsonify({'error': str(e)}), 500



@app.route('/get_image/<filename>', methods=['GET'])
# @login_required
def get_image(filename):
    try:
        return send_file(f'eventImage/{filename}', mimetype='image/jpeg')
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# ---------------------------------------------- MODELS -------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    account_type = db.Column(db.String(50), nullable=False)
    firebase_token = db.Column(db.String(255), nullable=True, default='')

class OrganizationProfile(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, db.ForeignKey('accounts.id'), primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(11), nullable=False)
    bio = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(255), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('palestine_cities.id'), nullable=False)

class UserProfile(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(11), nullable=False)
    bio = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    city_id = db.Column(db.Integer, db.ForeignKey('palestine_cities.id'), nullable=False)

class Event(db.Model):
    __tablename__ = 'event'
    event_id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_datetime = db.Column(db.DateTime, nullable=False)
    end_datetime = db.Column(db.DateTime, nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('palestine_cities.id'), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    required_volunteers = db.Column(db.Integer, nullable=False)
    current_volunteers = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(255), nullable=False)
    visibility = db.Column(db.Enum('public', 'private'), nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    time_stamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Coin(db.Model):
    __tablename__ = 'coins'
    coin_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    time_stamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    amount = db.Column(db.Integer, nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)

class City(db.Model):
    __tablename__ = 'palestine_cities'
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(50), nullable=False)

class UsersInterest(db.Model):
    __tablename__ = 'accounts_interests'
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), primary_key=True)
    interest_id = db.Column(db.Integer, db.ForeignKey('interests.id'), primary_key=True)

class EventInterests(db.Model):
    __tablename__ = 'event_interests'
    event_id = db.Column(db.Integer, db.ForeignKey('event.event_id'), primary_key=True)
    interest_id = db.Column(db.Integer, db.ForeignKey('interests.id'), primary_key=True)

class Interest(db.Model):
    __tablename__ = 'interests'
    id = db.Column(db.Integer, primary_key=True)
    interest = db.Column(db.String(50), nullable=False)

class EventReplyPost(db.Model):
    __tablename__ = 'event_reply_post'
    post_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    time_stamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    rating = db.Column(db.Integer, nullable=False, default=0)
    event_id = db.Column(db.Integer, db.ForeignKey('event.event_id'), nullable=False)

class Rating(db.Model):
    __tablename__ = 'rating'
    rating_id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)  # The user who owns the reply post
    reply_post_id = db.Column(db.Integer, db.ForeignKey('event_reply_post.post_id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)  # The user who gives the rating
    create_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Report(db.Model):
    __tablename__ = 'report'
    report_id = db.Column(db.Integer, primary_key=True)
    reported_id = db.Column(db.Integer, db.ForeignKey('event.event_id'), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('pending', 'approved', 'rejected'), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class EventJoin(db.Model):
    __tablename__ = 'event_joins'
    event_id = db.Column(db.Integer, db.ForeignKey('event.event_id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), primary_key=True)

class Notification(db.Model):
    __tablename__ = 'event_notification'
    notifications_id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    type = db.Column(db.Enum('event', 'msg', 'reply'))
    create_at = db.Column(db.TIMESTAMP)
    event_id = db.Column(db.Integer) 

class GroupChat(db.Model):
    __tablename__ = 'group_chat'
    group_chat_id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(50), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.event_id'), nullable=False)

#...................create_event(new)..............................................................

def newGroupChat(eventID,Title):
    group_chat = GroupChat(
            group_name=Title,
            event_id=eventID
    )
    db.session.add(group_chat)
    db.session.commit()

def newNotificationEvent(eventId,Title):
    notification_content = f"Coming soon event called: {Title}"
    new_notification = Notification(
            content=notification_content,
            type='event',
            event_id=eventId
    )

    db.session.add(new_notification)
    db.session.commit()

@app.route('/create_event', methods=['POST'])
@login_required
def create_event():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Extract data from JSON request
        creator_id = current_user.id
        title = data.get('title')
        description = data.get('description')
        start_datetime = datetime.strptime(data.get('start_datetime'), '%Y-%m-%d %H:%M:%S')
        end_datetime = datetime.strptime(data.get('end_datetime'), '%Y-%m-%d %H:%M:%S')
        city_id = data.get('city_id')
        address = data.get('address')
        interests = data.get('interests', [])  # list of interest IDs, default to empty list
        required_volunteers = data.get('required_volunteers')
        current_volunteers = 0  # Initialize current volunteers to 0
        image = data.get('image')
        visibility = data.get('visibility', 'public')  # Default to public if not provided
        longitude = data.get('longitude')
        latitude = data.get('latitude')

        # Create new Event object
        new_event = Event(
            creator_id=creator_id,
            title=title,
            description=description,
            start_datetime=start_datetime,
            end_datetime=end_datetime,
            city_id=city_id,
            address=address,
            required_volunteers=required_volunteers,
            current_volunteers=current_volunteers,
            image=image,
            visibility=visibility,
            longitude=longitude,
            latitude=latitude
        )

        db.session.add(new_event)
        db.session.commit()

        # After committing the event, retrieve its event_id
        event_id = new_event.event_id

        # Create group chat with the same title as the event
        newGroupChat(eventID=event_id,Title=title)


        # Create notification for the event
        newNotificationEvent(eventId=event_id,Title=title)

        # Add interests to the event
        if interests:
            for interest_id in interests:
                event_interest = EventInterests(event_id=event_id, interest_id=interest_id)
                db.session.add(event_interest)
            db.session.commit()

        return jsonify({"message": "Event created successfully", "event_id": event_id})

    except Exception as e:
        db.session.rollback()  # Rollback the transaction in case of error
        return jsonify({'error': str(e)}), 500



#............................................. notifications ........................

# Check the current user's profile to determine if they are an individual user or part of an organization.
# Get the city_id based on the user's profile type.
# Fetch event IDs that have the same city_id as the user.
# Retrieve notifications for those events.


    
#this method get the events notification just
@app.route('/get_user_notifications', methods=['GET'])
@login_required
def get_user_notifications():
    try:
        user_id = current_user.id
        account_type = current_user.account_type

        if account_type == 'org':
            profile = OrganizationProfile.query.filter_by(id=user_id).first()
        elif account_type == 'user':
            profile = UserProfile.query.filter_by(user_id=user_id).first()
        else:
            return jsonify({'error': 'Invalid account type'}), 400

        if not profile:
            return jsonify({'error': 'Profile not found'}), 404

        city_id = profile.city_id

        # Fetch event IDs with the same city_id
        events = Event.query.filter_by(city_id=city_id).all()
        event_ids = [event.event_id for event in events]

        # Fetch notifications for those event IDs with type 'event'
        notifications = Notification.query.filter(
            Notification.event_id.in_(event_ids),
            Notification.type == 'event'
        ).all()

        # Convert notifications to JSON serializable format
        notifications_data = [
            {
                'notification_id': notification.notifications_id,
                'content': notification.content,
                'type': notification.type,
                'created_at': notification.create_at,
                'event_id': notification.event_id
            }
            for notification in notifications
        ]

        return jsonify({"notifications": notifications_data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#this method get the reply notfication for the events that created by the current user:
@app.route('/get_creator_notifications', methods=['GET'])
@login_required
def get_creator_notifications():
    try:
        user_id = current_user.id

        # Fetch event IDs where the current user is the creator
        events = Event.query.filter_by(creator_id=user_id).all()
        event_ids = [event.event_id for event in events]

        if not event_ids:
            return jsonify({"notifications": []})

        # Fetch notifications for those event IDs with type 'reply'
        notifications = Notification.query.filter(
            Notification.event_id.in_(event_ids),
            Notification.type == 'reply'
        ).all()

        # Convert notifications to JSON serializable format
        notifications_data = [
            {
                'notification_id': notification.notifications_id,
                'content': notification.content,
                'type': notification.type,
                'created_at': notification.create_at,
                'event_id': notification.event_id
            }
            for notification in notifications
        ]

        return jsonify({"notifications": notifications_data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------- LOGIN & REGISTER ---------------------------------------------

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return jsonify({'success': False, 'message': 'Unauthorized access, please log in.'}), 401


@app.route('/check_email', methods=['POST'])
def check_email():
    try:
        print("before1")
        data = request.json
        print("before2")
        if not data or 'email' not in data:
            return jsonify({'result': False,'message':'email not entered.'}), 400
        print("before3")
        email = data['email']
        print("before4")
        if not is_valid_email(email):
            return jsonify({'result': False,'message':'Invalid email address.'}), 400
        print("before5")
        email_exists = User.query.filter_by(email=email).first() is not None
        print("before6")
        if email_exists:
            return jsonify({'result': False, 'message': 'Email is already registered'}), 200
        else:
            return jsonify({'result': True, 'message': 'Email is available'}), 200
    except Exception as e:
        return jsonify({'result':False ,'message': 'Server error, Try in other time.'}), 500
    

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}),201

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


# valid the email:
def is_valid_email(email):
    # Basic email format validation
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(regex, email):
        return False

    domain = email.split('@')[1]

    try:
        
        records = dns.resolver.resolve(domain, 'MX')
        if records:
            return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False

    return False

# valid the password:
def is_valid_password(password):
    # at least 6 characters, contain both numbers and characters
    if len(password) < 6:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True


@app.route('/create_account_and_profile', methods=['POST'])
def create_account_and_profile():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        email = data.get('email')
        password = data.get('password')
        account_type = data.get('account_type', 'user')
        if not email or not password or not account_type:
            return jsonify({'error': 'Missing required fields'}), 400

        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email address'}), 400

        if not is_valid_password(password):
            return jsonify({'error': 'Password must be at least 6 characters long and contain both numbers and characters'}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        new_user = User(email=email, password=hashed_password, creation_date=datetime.utcnow(), account_type=account_type)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        # Create profile
        profile_data = {
            'username': data.get('username'),
            'phone_number': data.get('phone_number'),
            'bio': data.get('bio'),
            'profile_picture': data.get('profile_picture'),
            'city_id': data.get('city_id')
        }
        interests = data.get('interests')

        if account_type == 'org':
            profile = OrganizationProfile(
                id=new_user.id,
                name=data.get('name'),
                website=data.get('website'),
                **profile_data
            )
        elif account_type == 'user':
            profile = UserProfile(
                user_id=new_user.id,
                first_name=data.get('first_name'),
                last_name=data.get('last_name'),
                **profile_data
            )
        else:
            return jsonify({'error': 'Invalid account type'}), 400

        db.session.add(profile)
        db.session.commit()

        if interests:
            for interest_id in interests:
                user_interest = UsersInterest(user_id=new_user.id, interest_id=interest_id)
                db.session.add(user_interest)
            db.session.commit()

        return jsonify({"message": "Account and profile created successfully", "userId": new_user.id, "accountType": new_user.account_type})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# first step : choose the type {org,user} then enter the email and password with validation
# @app.route('/create_account', methods=['POST'])
# def create_account():
#     try:
#         data = request.json
#         if not data:
#             return jsonify({'error': 'No data provided'}), 400
#         email = data.get('email')
#         password = data.get('password')
#         #account_type = data.get('accountType')
#         account_type = "user"
#         if not email or not password or not account_type:
#             return jsonify({'error': 'Missing required fields'}), 400

#         # is valid email?
#         if not is_valid_email(email):
#             return jsonify({'error': 'Invalid email address'}), 400

#         # is valid password?
#         if not is_valid_password(password):
#             return jsonify({'error': 'Password must be at least 6 characters long and contain both numbers and characters'}), 400

#         # Generate hashed password
#         hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
#         token = hashlib.sha256((email + str(time.time())).encode()).hexdigest()

#         # Check if the email is already registered
#         if User.query.filter_by(email=email).first():
#             return jsonify({'error': 'Email already registered'}), 400

#         new_user = User(email=email, password=hashed_password, creation_date=datetime.utcnow(), account_type=account_type)
#         db.session.add(new_user)
#         db.session.commit()

#         login_user(new_user)

#         return jsonify({"message": "Account created and logged in successfully", "userId": new_user.id, "accountType": new_user.account_type})

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


# @app.route('/create_profile', methods=['POST'])
# @login_required
# def create_profile():
#     try:
#         data = request.json
#         if not data:
#             return jsonify({'error': 'No data provided'}), 400

#         account_type = current_user.account_type
#         interests = data.get('interests')  # list of interest IDs

#         if account_type == 'org':
#             profile = OrganizationProfile(
#                 id=current_user.id,
#                 username=data.get('username'),
#                 name=data.get('name'),
#                 phone_number=data.get('phone_number'),
#                 bio=data.get('bio'),
#                 profile_picture=data.get('profile_picture'),
#                 website=data.get('website'),
#                 city_id=data.get('city_id')
#             )
#         elif account_type == 'user':
#             profile = UserProfile(
#                 user_id=current_user.id,
#                 username=data.get('username'),
#                 first_name=data.get('first_name'),
#                 last_name=data.get('last_name'),
#                 phone_number=data.get('phone_number'),
#                 bio=data.get('bio'),
#                 profile_picture=data.get('profile_picture'),
#                 city_id=data.get('city_id')
#             )
#         else:
#             return jsonify({'error': 'Invalid account type'}), 400

#         db.session.add(profile)
#         db.session.commit()

#         if interests:
#             for interest_id in interests:
#                 user_interest = UsersInterest(user_id=current_user.id, interest_id=interest_id)
#                 db.session.add(user_interest)
#             db.session.commit()

#         return jsonify({"message": "Profile created successfully"})
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


# ---------------------------------------------- HOME PAGE ------------------------------------------------
@app.route('/')
def index():
    events = Event.query.all()
    events_data = [{"id": event.event_id, 'creator_id': event.creator_id, 'title': event.title, 'description': event.description, 'location': event.address, 'image': event.image} for event in events]
    return jsonify(events_data)


@app.route('/home/<pagenumber>', methods=['GET'])
@login_required
def get_home(pagenumber):
    try:
        events = Event.query.all()
        events_data = [{"id": event.event_id, 'creator_id': event.creator_id, 'title': event.title, 'description': event.description, 'location': event.address, 'image': event.image} for event in events]
        return jsonify(events_data)
    except pymysql.Error as e:
        return jsonify({'error': str(e)}), 500

# @app.route('/create_event', methods=['POST'])
# @login_required
# def create_event():
#     try:
#         data = request.json
#         if not data:
#             return jsonify({'error': 'No data provided'}), 400

#         creator_id = current_user.id
#         title = data.get('title')
#         description = data.get('description')
#         start_datetime = datetime.strptime(data.get('start_datetime'), '%Y-%m-%d %H:%M:%S')
#         end_datetime = datetime.strptime(data.get('end_datetime'), '%Y-%m-%d %H:%M:%S')
#         city_id = data.get('city_id')
#         address = data.get('address')
#         interests = data.get('interests', [])  # list of interest IDs, default to empty list
#         required_volunteers = data.get('required_volunteers')
#         current_volunteers = 0  # Initialize current volunteers to 0
#         image = data.get('image')
#         visibility = data.get('visibility', 'public')  # Default to public if not provided
#         longitude = data.get('longitude')
#         latitude = data.get('latitude')
        
#         # Create new Event object
#         new_event = Event(
#             creator_id=creator_id,
#             title=title,
#             description=description,
#             start_datetime=start_datetime,
#             end_datetime=end_datetime,
#             city_id=city_id,
#             address=address,
#             required_volunteers=required_volunteers,
#             current_volunteers=current_volunteers,
#             image=image,
#             visibility=visibility,
#             longitude=longitude,
#             latitude=latitude
#         )

#         db.session.add(new_event)
#         db.session.commit()

#         # After committing the event, retrieve its event_id
#         event_id = new_event.event_id

#         # Add interests to the event
#         if interests:
#             for interest_id in interests:
#                 event_interest = EventInterests(event_id=event_id, interest_id=interest_id)
#                 db.session.add(event_interest)
#             db.session.commit()

#         return jsonify({"message": "Event created successfully", "event_id": event_id})

#     except Exception as e:
#         db.session.rollback()  # Rollback the transaction in case of error
#         return jsonify({'error': str(e)}), 500

@app.route('/add_report_on_event', methods=['POST'])
@login_required
def add_report():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400

       
        reported_id = data.get('reported_id')
        content = data.get('content')

       
        event = Event.query.get(reported_id)
        if not event:
            return jsonify({'error': 'Event not found'}), 404

       
        new_report = Report(
            reported_id=reported_id,
            reporter_id=current_user.id,
            content=content,
            status='pending', 
            created_at=datetime.utcnow()
        )

        db.session.add(new_report)
        db.session.commit()

        return jsonify({"message": "Report added successfully", "report_id": new_report.report_id})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/search_events', methods=['POST'])
@login_required
def search_events():
    try:
        search_title = request.json.get('the_title', '').strip()  # Get and strip the search query parameter from the JSON body

        if not search_title:
            return jsonify({'events': []}), 200  # Return empty list if search_title is empty

        events = Event.query.filter(Event.title.ilike(f'%{search_title}%')).all()
        event_list = []
        for event in events:
            creator = UserProfile.query.filter_by(user_id=event.creator_id).first()
            event_data = {
                'event_id': event.event_id,
                'creator_id': event.creator_id,
                'creator_first_name':creator.first_name if creator else None,
                'creator_last_name':creator.last_name if creator else None,
                'creator_image':creator.profile_picture if creator else None,
                'title': event.title,
                'description': event.description,
                'start_datetime': event.start_datetime.isoformat(),
                'end_datetime': event.end_datetime.isoformat(),
                'city_id': event.city_id,
                'address': event.address,
                'required_volunteers': event.required_volunteers,
                'current_volunteers': event.current_volunteers,
                'image': event.image,
                'visibility': event.visibility,
                'longitude': event.longitude,
                'latitude': event.latitude
            }
            event_list.append(event_data)

        return jsonify({'events': event_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


   # this method take the event id when click on "join" and let the user join dirictly to the event, then increment the
   # # curr voulnteers by 1, and check if the room or event is full of voulnteers .. 
   # its make it update in event table also on the current voulnteers number      

# @app.route('/leave_event', methods=['POST'])
# @login_required
# def leave_event():
#     try:
#         data = request.json
#         event_id = data.get('event_id')
#         user_id = current_user.id

#         event = Event.query.get(event_id)
#         if not event:
#             return jsonify({'message': 'Event not found'}), 404
        
#         existing_join = EventJoin.query.filter_by(event_id=event_id, user_id=user_id).first()
#         if existing_join:
#             db.session.delete(existing_join)
#             db.session.commit()
#             # event.current_volunteers -= 1
#             return jsonify({'message': 'leaving the event'}), 200

#         return jsonify({'message': 'already not joined'}), 404
#     except Exception as e:
#         # db.session.rollback()  # Rollback the session in case of error
#      return jsonify({'error': str(e)}), 500

@app.route('/leave_event', methods=['POST'])
@login_required
def leave_event():
    try:
        data = request.json
        event_id = data.get('event_id')

        if not event_id:
            return jsonify({'error': 'Event ID is required'}), 400

        user_id = current_user.id

        # Find the event join record for the current user and the specified event
        event_join = EventJoin.query.filter_by(event_id=event_id, user_id=user_id).first()

        if not event_join:
            return jsonify({'error': 'You are not joined to this event'}), 404

        # Delete the event join record
        db.session.delete(event_join)
        db.session.commit()

        return jsonify({'message': 'Successfully left the event'}), 200

    except Exception as e:
        db.session.rollback()  # Rollback the transaction in case of error
        return jsonify({'error': str(e)}), 500

@app.route('/does_join', methods=['POST'])
@login_required
def does_join():
    try:
        data = request.json
        event_id = data.get('event_id')
        user_id = current_user.id
        existing_join = EventJoin.query.filter_by(event_id=event_id, user_id=user_id).first()
        if existing_join:
            return jsonify({'message': 'already joined the event'}), 200

        return jsonify({'message': 'not joined'}), 404
    except Exception as e:
        # db.session.rollback()  # Rollback the session in case of error
     return jsonify({'error': str(e)}), 500
    

@app.route('/city_event', methods=['POST'])
@login_required
def city_event():
    try:
        data = request.json
        cityID = data.get('cityID')
        
        if not cityID:
            return jsonify({'error': 'City ID is required'}), 400

        # Query events based on cityID, visibility, and order by start_datetime in descending order
        joined_events = Event.query.filter(
            Event.city_id == cityID,
            Event.visibility == 'public'
        ).order_by(Event.time_stamp.desc()).all()
        
        event_list = []
        for event in joined_events:
            creator = UserProfile.query.filter_by(user_id=event.creator_id).first()
            event_data = {
                'event_id': event.event_id,
                'creator_id': event.creator_id,
                'creator_username': creator.username if creator else None,
                'creator_first_name': creator.first_name if creator else None,
                'creator_last_name': creator.last_name if creator else None,
                'creator_image':creator.profile_picture if creator else None,
                'title': event.title,
                'description': event.description,
                'start_datetime': event.start_datetime.isoformat(),
                'end_datetime': event.end_datetime.isoformat(),
                'city_id': event.city_id,
                'address': event.address,
                'required_volunteers': event.required_volunteers,
                'current_volunteers': event.current_volunteers,
                'image': event.image,
                'visibility': event.visibility,
                'longitude': event.longitude,
                'latitude': event.latitude
            }
            event_list.append(event_data)

        return jsonify({'events': event_list}), 200
    except Exception as e:
         return jsonify({'error': str(e)}), 500


@app.route('/join_event', methods=['POST'])
@login_required
def join_event():
    try:
        data = request.json
        event_id = data.get('event_id')
        user_id = current_user.id  
        # Check if the user is already joined to the event
        existing_join = EventJoin.query.filter_by(event_id=event_id, user_id=user_id).first()
        if existing_join:
            return jsonify({'message': 'already joined the event'}), 400

        # Get the event
        event = Event.query.get(event_id)
        if not event:
            return jsonify({'message': 'Event not found'}), 404

        # Check if the event is already full
        if event.current_volunteers >= event.required_volunteers:
            return jsonify({'message': 'Full joins, sorry'}), 400

        # Add the user to the event
        new_join = EventJoin(event_id=event_id, user_id=user_id)
        db.session.add(new_join)
        event.current_volunteers += 1

        # Commit the changes
        db.session.commit()

        # Check if the event is now full
        if event.current_volunteers >= event.required_volunteers:
            return jsonify({'message': 'User joined the event successfully. Event is now full.'}), 200

        return jsonify({'message': 'User joined the event successfully'}), 200

    except Exception as e:
        # db.session.rollback()  # Rollback the session in case of error
        return jsonify({'error': str(e)}), 500


#method to get the events that joined by the current user "for test, login with the data of user who have id=18"
@app.route('/joined_events', methods=['GET'])
@login_required
def get_joined_events():
    try:
        user_id = current_user.id  # Get the current logged-in user's ID

        # Query for event IDs joined by the current user
        joined_event_ids = db.session.query(EventJoin.event_id).filter_by(user_id=user_id).all()
        joined_event_ids = [event_id for (event_id,) in joined_event_ids]  # Unpack tuples

        # Query for event details of the joined events
        joined_events = Event.query.filter(Event.event_id.in_(joined_event_ids)).all()

        # Prepare JSON response
        event_list = []
        for event in joined_events:
            event_data = {
                'event_id': event.event_id,
                'creator_id': event.creator_id,
                'title': event.title,
                'description': event.description,
                'start_datetime': event.start_datetime.isoformat(),
                'end_datetime': event.end_datetime.isoformat(),
                'city_id': event.city_id,
                'address': event.address,
                'required_volunteers': event.required_volunteers,
                'current_volunteers': event.current_volunteers,
                'image': event.image,
                'visibility': event.visibility,
                'longitude': event.longitude,
                'latitude': event.latitude
            }
            event_list.append(event_data)

        return jsonify({'events': event_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# get the current user info: img, fname, lname, city
@app.route('/profile/info', methods=['GET'])
@login_required
def get_profile_info():
    try:
        user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not user_profile:
            return jsonify({'error': 'User profile not found'}), 404

        city = City.query.filter_by(id=user_profile.city_id).first()
        city_name = city.city if city else 'Unknown'

        profile_info = {
            'profile_picture_url': user_profile.profile_picture,
            'first_name': user_profile.first_name,
            'last_name': user_profile.last_name,
            'city_name': city_name,
            'city_id': user_profile.city_id
        }

        return jsonify(profile_info), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# return the events the creted by the current user
@app.route('/user_events', methods=['POST'])
@login_required
def get_my_events():
    data = request.json
    current_user_id = data.get('profileID')

    # Query events created by the current user
    events = Event.query.filter_by(creator_id=current_user_id).all()

    # Create a list of events to return
    events_list = []
    for event in events:
        creator = UserProfile.query.filter_by(user_id=event.creator_id).first()
        events_list.append({
            'event_id': event.event_id,
            'creator_first_name':creator.first_name if creator else None,
            'creator_last_name':creator.last_name if creator else None,
            'creator_image':creator.profile_picture if creator else None,
            'creator_id': event.creator_id,
            'title': event.title,
            'description': event.description,
            'start_datetime': event.start_datetime.isoformat(),
            'end_datetime':event.start_datetime.isoformat(),
            'city_id': event.city_id,
            'address': event.address,
            'required_volunteers': event.required_volunteers,
            'current_volunteers': event.current_volunteers,
            'image': event.image,
            'visibility': event.visibility,
            'longitude': event.longitude,
            'latitude': event.latitude
        })

    return jsonify({'success': True, 'events': events_list})


# returrn the replys that crested by the current user
@app.route('/reply-posts', methods=['POST'])
@login_required
def get_my_reply_posts():
    data = request.json
    current_user_id = data.get('profileID')

    # Query reply posts created by the current user
    reply_posts = EventReplyPost.query.filter_by(user_id=current_user_id).all()

    # Create a list of reply posts to return
    reply_posts_list = []
    for post in reply_posts:
        reply_posts_list.append({
            'post_id': post.post_id,
            'user_id': post.user_id,
            'content': post.content,
            'time_stamp': post.time_stamp.strftime('%Y-%m-%d %H:%M:%S'),
            'rating': post.rating,
            'event_id': post.event_id
        })

    return jsonify({'success': True, 'reply_posts': reply_posts_list})

@app.route('/profile', methods=['GET'])
@login_required
def get_current_user_profile():
    try:
        user = User.query.get(current_user.id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.account_type == 'user':
            profile = UserProfile.query.filter_by(user_id=user.id).first()
        elif user.account_type == 'org':
            profile = OrganizationProfile.query.filter_by(id=user.id).first()
        else:
            return jsonify({'error': 'Invalid account type'}), 400

        if not profile:
            return jsonify({'error': 'Profile not found'}), 404

        profile_data = {
            'email': user.email,
            'creation_date': user.creation_date.isoformat(),
            'account_type': user.account_type,
            'username': profile.username,
            'first_name': profile.first_name if hasattr(profile, 'first_name') else None,
            'last_name': profile.last_name if hasattr(profile, 'last_name') else None,
            'phone_number': profile.phone_number,
            'bio': profile.bio,
            'profile_picture': profile.profile_picture,
            'website': profile.website if hasattr(profile, 'website') else "None",
            'city_id': profile.city_id,
            'userID': current_user.id
        }

        return jsonify({'profile': profile_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


#get events based on the city of the current user

@app.route('/events_based_on_city', methods=['GET'])
@login_required  
def get_events_by_city():
    user_id = current_user.id
    
    # Query user's city_id from UserProfile
    user_profile = UserProfile.query.filter_by(user_id=user_id).first()
    if not user_profile:
        return jsonify({'error': 'User profile not found'}), 404
    
    # user_city_id = user_profile.city_id
    user_city_id=1
    # Query to find events based on user city
    events = db.session.query(Event, City).join(City, Event.city_id == City.id).filter(
        Event.city_id == user_city_id,
        Event.visibility == 'public'  # Assuming we want only public events
    ).all()

    # Serialize the events data to JSON
    event_data = []
    for event, city in events:
        event_data.append({
            'event_id': event.event_id,
            'title': event.title,
            'description': event.description,
            'start_datetime': event.start_datetime.isoformat(),
            'end_datetime': event.end_datetime.isoformat(),
            'address': event.address,
            'image': event.image,
            'longitude': event.longitude,
            'latitude': event.latitude,
            'city_name': city.city
        })

    return jsonify({'events': event_data})


#get events based on the interests of the current user

@app.route('/events_based_on_interests', methods=['GET'])
@login_required  # Assuming you are using Flask-Login to manage authentication
def get_events_by_interests():
    user_id = current_user.id
    
    # Query user's interests
    user_interests = db.session.query(Interest).join(UsersInterest).filter(UsersInterest.user_id == user_id).all()
    if not user_interests:
        return jsonify({'error': 'No interests found for this user'}), 404
    
    user_interest_ids = [interest.id for interest in user_interests]
    
    # Query to find events based on user interests
    events = db.session.query(Event).join(EventInterests, Event.event_id == EventInterests.event_id).filter(
        EventInterests.interest_id.in_(user_interest_ids),
        Event.visibility == 'public'  # Assuming we want only public events
    ).distinct().all()

    # Serialize the events data to JSON
    event_data = []
    for event in events:
        event_data.append({
            'event_id': event.event_id,
            'title': event.title,
            'description': event.description,
            'start_datetime': event.start_datetime.isoformat(),
            'end_datetime': event.end_datetime.isoformat(),
            'address': event.address,
            'image': event.image,
            'longitude': event.longitude,
            'latitude': event.latitude,
            'city_id': event.city_id
        })

    return jsonify({'events': event_data})


# for displaying user coins number:
@app.route('/coins', methods=['GET'])
@login_required
def get_coins():
    try:
        user_id = current_user.id
        user_coins = Coin.query.filter_by(user_id=user_id).all()
        total_coins = sum(coin.amount for coin in user_coins)
        return jsonify({'coins': total_coins})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/top_users', methods=['GET'])
def get_top_users():
    try:
        top_users = db.session.query(UserProfile, Location).join(Location).order_by(UserProfile.coins.desc()).limit(5).all()

        top_users_data = []
        for user, location in top_users:
            user_data = {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'city': location.city,
                'coins': user.coins
            }
            top_users_data.append(user_data)

        return jsonify(top_users_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------- ALL ABOUT REPLY POST ROUTES ---------------------------------------------


# to create new reply post on event, get the event id , add content, the rating is 0 because no one rate this reply yet
@app.route('/add_reply_post', methods=['POST'])
@login_required
def add_reply_post():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        user_id = current_user.id
        event_id = data.get('event_id')
        content = data.get('content')
        # Validate the required fields
        if not event_id or not content:
            return jsonify({'error': 'Missing required fields'}), 400
        # Create new EventReplyPost object with rating set to 0
        new_reply_post = EventReplyPost(
            user_id=user_id,
            event_id=event_id,
            content=content,
            rating=0  # Default rating to 0 upon creation
        )
        db.session.add(new_reply_post)
        db.session.commit()
        # Fetch the event title
        event = Event.query.filter_by(event_id=event_id).first()
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        event_title = event.title
        # Create the notification
        notification_content = f"You have a new reply on '{event_title}'"
        new_notification = Notification(
            content=notification_content,
            type='reply',
            create_at=datetime.utcnow(),
            event_id=event_id
        )
        db.session.add(new_notification)
        db.session.commit()

        return jsonify({"message": "Reply post added successfully", "post_id": new_reply_post.post_id})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# rate the reply post, rate from 1 to 5,  recalculate the rating (the avg of all rating) then display the new rate on the reply post..
@app.route('/rate_reply_post', methods=['POST'])
@login_required
def rate_reply_post():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        post_id = data.get('post_id')
        rating_value = data.get('rating')
        
        # Validate the required fields
        if not post_id or rating_value is None:
            return jsonify({'error': 'Missing required fields'}), 400

        # Validate the rating
        if not isinstance(rating_value, int) or rating_value < 1 or rating_value > 5:
            return jsonify({'error': 'Rating must be an integer between 1 and 5'}), 400

        # Check if the user has already rated this reply post
        existing_rating = Rating.query.filter_by(reply_post_id=post_id, sender_id=current_user.id).first()
        if existing_rating:
            return jsonify({'error': 'You have already rated this reply post'}), 400

        # Get the reply post
        reply_post = EventReplyPost.query.filter_by(post_id=post_id).first()
        if not reply_post:
            return jsonify({'error': 'Reply post not found'}), 404
        
        # Create new Rating object
        new_rating = Rating(
            rating=rating_value,
            user_id=reply_post.user_id,  # The user who owns the reply post
            reply_post_id=post_id,
            sender_id=current_user.id
        )

        db.session.add(new_rating)
        db.session.commit()

        # Recalculate the average rating for the reply post
        all_ratings = Rating.query.filter_by(reply_post_id=post_id).all()
        avg_rating = sum(r.rating for r in all_ratings) / len(all_ratings)

        # Update the reply post with the new average rating
        reply_post.rating = avg_rating
        db.session.commit()

        return jsonify({"message": "Rating added successfully", "average_rating": avg_rating})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# @app.route('/events_replies', methods=['POST'])
# @login_required
# def get_replies_by_event():
#     data = request.json
#     event_id = data.get('event_id')

#     if not event_id:
#         return jsonify({'error': 'Event ID is required'}), 400

#     # Query to find all replies for the given event_id
#     replies = EventReplyPost.query.filter_by(event_id=event_id).all()

#     if not replies:
#         return jsonify({'error': 'No replies found for this event'}), 404

#     # Serialize the replies data to JSON
#     replies_data = []
#     for reply in replies:
#         replies_data.append({
#             'post_id': reply.post_id,
#             'user_id': reply.user_id,
#             'content': reply.content,
#             'time_stamp': reply.time_stamp.isoformat(),
#             'rating': reply.rating,
#             'event_id': reply.event_id
#         })

#     return jsonify({'replies': replies_data})

@app.route('/events_replies', methods=['POST'])
@login_required
def get_replies_by_event():
    data = request.get_json()
    event_id = data.get('event_id')

    if not event_id:
        return jsonify({'error': 'Event ID is required'}), 400

    try:
        # Query to find all replies for the given event_id
        replies = EventReplyPost.query.filter_by(event_id=event_id).all()

        if not replies:
            return jsonify({'message': 'No replies found for this event'}), 404

        # Serialize the replies data to JSON
        replies_data = []
        for reply in replies:
            user_profile = UserProfile.query.filter_by(user_id=reply.user_id).first()
            reply_data = {
                'post_id': reply.post_id,
                'user_id': reply.user_id,
                'content': reply.content,
                'time_stamp': reply.time_stamp.isoformat(),
                'rating': reply.rating,
                'event_id': reply.event_id,
                'creator_username': user_profile.username if user_profile else 'Unknown'
            }
            replies_data.append(reply_data)

        return jsonify({'replies': replies_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ---------------------------------------------- ROUTES WE NEED ---------------------------------------------

# method to get palestine cities and fill selection box with it, user will choose from it its city
@app.route('/cities', methods=['GET'])
def get_cities():
    try:
        cities = City.query.all()
        city_list = [{'id': city.id, 'city': city.city} for city in cities]
        return jsonify(city_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/interests', methods=['GET'])
def get_interests():
    try:
        interests = Interest.query.all()
        interest_list = [{'id': interest.id, 'interest': interest.interest} for interest in interests]
        return jsonify(interest_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --------------------------------------------- PUSH NOTIFYCATION --------------------------------------------------------

cred = credentials.Certificate('firebaseouth.json')
firebase_admin.initialize_app(cred)

fire_token="firebase notyfication token"

def send_to_token():
    registration_token = fire_token
    message = messaging.Message(
         notification=messaging.Notification(
        title="Hello",
        body="This is a test notification"
    ),
    token=registration_token
    )
    response = messaging.send(message)
    print('Successfully sent message:', response)

@app.route("/noty",methods=['Get'])
def notyL():
    send_to_token()
    return "done"

# ---------------------------------------------- RUN Main --------------------------------------------------------

if __name__ == '__main__':
  #  db.create_all()  # Ensure this is called only once to create the tables
    app.run(debug=True)

