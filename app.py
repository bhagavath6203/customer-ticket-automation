from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from pymongo.errors import ServerSelectionTimeoutError
from urllib.parse import quote
import os
import secrets
import base64
from email.mime.text import MIMEText
from dotenv import load_dotenv
import requests
from requests.auth import HTTPDigestAuth

# Load environment variables from .env file
load_dotenv()

# Importing Google API Client Libraries
import google.auth
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# MongoDB Atlas configuration
username = os.getenv('MONGO_USERNAME')
password = os.getenv('MONGO_PASSWORD')
atlas_group_id = os.getenv('ATLAS_GROUP_ID')
atlas_api_key_public = os.getenv('ATLAS_API_KEY_PUBLIC')
atlas_api_key_private = os.getenv('ATLAS_API_KEY_PRIVATE')

# Ensure that MongoDB credentials are set
if username is None or password is None:
    raise ValueError("Environment variables MONGO_USERNAME and MONGO_PASSWORD must be set")

# Encode the password for MongoDB URI
password = quote(password)

# Function to get the public IP address of the current environment
def get_public_ip():
    response = requests.get("https://api.ipify.org")
    return response.text

# Function to whitelist the current IP address in MongoDB Atlas
def whitelist_ip_in_mongo(ip):
    resp = requests.post(
        f"https://cloud.mongodb.com/api/atlas/v1.0/groups/{atlas_group_id}/accessList",
        auth=HTTPDigestAuth(atlas_api_key_public, atlas_api_key_private),
        json=[{'ipAddress': ip, 'comment': 'From PythonAnywhere'}]  # the comment is optional
    )
    if resp.status_code in (200, 201):
        print("MongoDB Atlas accessList request successful", flush=True)
    else:
        print(
            f"MongoDB Atlas accessList request problem: status code was {resp.status_code}, content was {resp.content}",
            flush=True
        )

# Get the current public IP and whitelist it in MongoDB Atlas
current_ip = get_public_ip()
whitelist_ip_in_mongo(current_ip)

# MongoDB URI configuration
app.config["MONGO_URI"] = f"mongodb+srv://{username}:{password}@customertickerautomatio.bik3ced.mongodb.net/customerTickerAutomation?retryWrites=true&w=majority"
mongo = PyMongo(app)

# Gmail API configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
creds = None

# Determine the directory of the current script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the path to the auth directory and credentials file
auth_dir = os.path.join(current_dir, 'auth')
credentials_path = os.path.join(auth_dir, 'credentials.json')
token_path = os.path.join(auth_dir, 'token.pickle')

# Load Gmail API credentials from file
if os.path.exists(token_path):
    with open(token_path, 'rb') as token:
        creds = pickle.load(token)

# If there are no (valid) credentials available, let the user log in.
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
        creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open(token_path, 'wb') as token:
        pickle.dump(creds, token)

# Build the Gmail service
service = build('gmail', 'v1', credentials=creds)

# Function to send email using Gmail API
def send_email(to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message = {'raw': raw}
    try:
        message = (service.users().messages().send(userId='me', body=message).execute())
        print('Message Id: %s' % message['id'])
        return message
    except Exception as error:
        print(f'An error occurred: {error}')
        return None

# Route for the main home page
@app.route('/')
def main_home():
    return render_template('main_home.html')

# Route for the login page
@app.route('/login')
def login_page():
    return render_template('login.html')

# Route for the signup page
@app.route('/signup')
def signup_page():
    return render_template('signup.html')

# Route for the forgot password page
@app.route('/forgot_password')
def forgot_password_page():
    return render_template('forgot_password.html')

# Route for the reset password page with token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = mongo.db.password_resets.find_one({'token': token})
    if not user:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('login_page'))
    
    if request.method == 'POST':
        new_password = request.form.get('newPassword')
        mongo.db.users.update_one({'email': user['email']}, {'$set': {'password': new_password}})
        mongo.db.password_resets.delete_one({'token': token})
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login_page'))

    return render_template('reset_password.html', token=token)

# Route for the home page after login
@app.route('/home/<username>')
def home(username):
    return render_template('home.html', username=username)

# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form.get('loginEmail')
        password = request.form.get('loginPassword')
        user = mongo.db.users.find_one({'email': email})
        if user:
            if user['password'] == password:
                flash('Login successful!', 'success')
                return redirect(url_for('home', username=user['username']))
            else:
                flash('Wrong password. Please try again.', 'danger')
                return redirect(url_for('login_page'))
        else:
            flash('Invalid email. Please try again.', 'danger')
            return redirect(url_for('login_page'))
    except ServerSelectionTimeoutError:
        flash('Could not connect to MongoDB. Please try again later.', 'danger')
        return redirect(url_for('login_page'))

# Route for handling signup form submission
@app.route('/signup', methods=['POST'])
def signup():
    try:
        username = request.form.get('signUpUsername')
        email = request.form.get('signUpEmail')
        password = request.form.get('signUpPassword')
        user = mongo.db.users.find_one({'email': email})
        if user:
            flash('Email already exists', 'danger')
            return redirect(url_for('signup_page'))
        else:
            mongo.db.users.insert_one({'username': username, 'email': email, 'password': password})
            flash('Sign up successful!', 'success')
            return redirect(url_for('login_page'))
    except ServerSelectionTimeoutError:
        flash('Could not connect to MongoDB. Please try again later.', 'danger')
        return redirect(url_for('signup_page'))

# Route for handling forgot password form submission
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    try:
        email = request.form.get('forgotPasswordEmail')
        user = mongo.db.users.find_one({'email': email})
        if user:
            token = secrets.token_urlsafe(32)
            mongo.db.password_resets.insert_one({'email': email, 'token': token})
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = 'Password Reset Request'
            body = f'Click the link to reset your password: {reset_url}'
            send_email(email, subject, body)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email not found', 'danger')
        return redirect(url_for('forgot_password_page'))
    except ServerSelectionTimeoutError:
        flash('Could not connect to MongoDB. Please try again later.', 'danger')
        return redirect(url_for('forgot_password_page'))

# Route for handling logout
@app.route('/logout')
def logout():
    # Here you should add the logic to clear the session or any other logout handling
    flash('You have been logged out.', 'success')
    return redirect(url_for('login_page'))

# Run the app in debug mode
if __name__ == '__main__':
    app.run(debug=True)
