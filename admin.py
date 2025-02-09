from flask import Flask, jsonify, request , session
import pymysql 
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import hashlib 
import time # for current date, time
import re
import dns.resolver # library to valid the email
# import requests
from datetime import datetime
import firebase_admin
from firebase_admin import credentials,messaging
from sqlalchemy import or_ # like string matching, search for string or sub string
from flask_socketio import SocketIO, join_room, leave_room, emit
from sqlalchemy import text
from flask import Flask, jsonify, request ,send_file
import os
from datetime import timedelta
import secrets


app2 = Flask(__name__)
CORS(app2)

# Configuration for SQLAlchemy and LoginManager
app2.config['SECRET_KEY'] = 'supersecretkey'
app2.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/gohelp'
app2.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app2.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24,days=2)

db = SQLAlchemy(app2)
login_manager = LoginManager(app2)
login_manager.login_view = 'login'

# ---------------------------------------------- MODELS -------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    account_type = db.Column(db.String(50), nullable=False)
    firebase_token = db.Column(db.String(255), nullable=True, default='')
class Admin(db.Model, UserMixin):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    def get_id(self):
           return (self.admin_id)
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
class Report(db.Model):
    __tablename__ = 'report'
    report_id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, nullable=False)
    reported_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('pending', 'reviewed'), nullable=False, default='pending')
    created_at = db.Column(db.TIMESTAMP, nullable=False, default=datetime.utcnow)
    report_type = db.Column(db.Enum('event', 'user'), nullable=False)
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
class DeletedEvent(db.Model):
    __tablename__ = 'deleted_events'
    event_id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(50), nullable=False)
    admin_id = db.Column(db.Integer, nullable=False)
    admin_name = db.Column(db.String(50), nullable=False)
    reason_for_deletion = db.Column(db.String(100), nullable=False)
class Notification(db.Model):
    __tablename__ = 'event_notification'  # Assuming your table name is 'notification'
    notifications_id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    type = db.Column(db.Enum('event', 'msg', 'reply','review'))
    create_at = db.Column(db.TIMESTAMP)
    event_id = db.Column(db.Integer) 

class City(db.Model):
    __tablename__ = 'palestine_cities'
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(50), nullable=False)


@app2.route('/get_image/<filename>', methods=['GET'])
# @login_required
def get_image(filename):
    try:
        return send_file(f'eventImage/{filename}', mimetype='image/jpeg')
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# Flask-Login user loader
@login_manager.user_loader
def load_user(admin_id):
    return Admin.query.get(int(admin_id))

# Login endpoint
@app2.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    print("oooooo1")
    admin = Admin.query.filter_by(email=email).first()
    print("oooooo2")
    
    if admin and admin.password == password:
        print("oooooo3")
        login_user(admin)
        print("oooooo2")
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'})

# Logout endpoint
@app2.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app2.route('/test_endpoint', methods=['GET', 'POST'])
def test_endpoint():
    if request.method == 'GET':
        return jsonify({'message': 'Test endpoint reached successfully via GET'})
    elif request.method == 'POST':
        return jsonify({'message': 'Test endpoint reached successfully via POST'})
    else:
        return jsonify({'error': 'Method Not Allowed'}), 405


@app2.route('/reports', methods=['GET'])
# @login_required
def get_newest_reports():
    try:
        # Query for newest reports ordered by created_at descending
        reports = Report.query.order_by(Report.created_at.desc()).all()

        # Prepare list to store serialized reports
        reports_list = []
        for report in reports:
            reports_data = {
                'report_id': report.report_id,
                'reporter_id': report.reporter_id,
                'reported_id': report.reported_id,
                'content': report.content,
                'status': report.status,
                'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'report_type': report.report_type
            }
            reports_list.append(reports_data)

        return jsonify(reports_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app2.route('/event/<int:event_id>', methods=['GET'])
# @login_required
def get_event_info(event_id):
    try:
        event = Event.query.get(event_id)

        if event:
            event_data = {
                'event_id': event.event_id,
                'creator_id': event.creator_id,
                'title': event.title,
                'description': event.description,
                'start_datetime': event.start_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                'end_datetime': event.end_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                'city_id': event.city_id,
                'address': event.address,
                'required_volunteers': event.required_volunteers,
                'current_volunteers': event.current_volunteers,
                'image': event.image,
                'visibility': event.visibility,
                'longitude': event.longitude,
                'latitude': event.latitude
            }
            return jsonify(event_data), 200
        else:
            return jsonify({'error': 'Event not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app2.route('/delete_event/<int:event_id>', methods=['DELETE'])
def delete_event(event_id):
    try:
        # Find the event to delete
        event = Event.query.get(event_id)
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        # Send notification
        notification_content = f"Your event '{event.title}' has been removed from GoHelp because it is against our standards."
        notification = Notification(
            content=notification_content,
            type='review',
            event_id=event.event_id
        )
        db.session.add(notification)

        # Delete the event from Event table
        db.session.delete(event)

        db.session.commit()

        return jsonify({"message": "Event deleted successfully and notification sent"}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Run the application
if __name__ == '__main__':
    app2.run(port=5001,debug=True)




#..................................................................................
# from flask import Flask, jsonify, request ,send_file
# from flask_cors import CORS
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from datetime import datetime
# from datetime import timedelta


# app2 = Flask(__name__)
# CORS(app2)


# app2.config['SECRET_KEY'] = 'supersecretkey'
# app2.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/gohelp'
# app2.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app2.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24,days=2)

# db = SQLAlchemy(app=app2)


# login_manager = LoginManager(app=app2)
# login_manager.login_view = 'login'


# @app2.route('/')
# def hello():
#     return "admin server for GOHELP mobile app"


# @app2.route('/get_image/<filename>', methods=['GET'])
# @login_required
# def get_image(filename):
#     try:
#         return send_file(f'eventImage/{filename}', mimetype='image/jpeg')
#     except FileNotFoundError:
#         return jsonify({"error": "File not found"}), 404




# if __name__ == '__main__':
#     app2.run(port=5001)  # Port 5001