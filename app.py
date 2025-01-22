import gspread
from oauth2client.service_account import ServiceAccountCredentials
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort, g, send_file, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import dotenv
import json
from datetime import datetime
import pymongo
import bcrypt
import waitress
import ipaddress
import logging
import secrets
import requests
import time
import gridfs
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId

logging.basicConfig(level=logging.INFO)


dotenv.load_dotenv()

scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
credentials_json = os.getenv('CREDENTIALS_JSON')
credentials_dict = json.loads(credentials_json)
creds = ServiceAccountCredentials.from_json_keyfile_dict(credentials_dict, scope)
client = gspread.authorize(creds)

SHEET_ID = os.getenv('SHEET_ID')

spreadsheet = client.open_by_key(SHEET_ID)
sheet = spreadsheet.worksheet('Sheet1')

SECRET_KEY = os.getenv('SECRET_KEY')
app = Flask(__name__)
app.secret_key = SECRET_KEY

RECAPTCHA_SECRET = os.getenv('RECAPTCHA_SECRET')

MONGO_URI = os.getenv('MONGO_URI')
client = pymongo.MongoClient(MONGO_URI)
db = client['aws_application']
fs = gridfs.GridFS(db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, reg_no, name, email, status, admin, cv_id=None):
        self.reg_no = reg_no
        self.name = name
        self.email = email
        self.status = status
        self.admin = admin
        self.cv_id = cv_id
    
    def get_id(self):
        return str(self.reg_no)

@login_manager.user_loader
def load_user(reg_no):
    user = db.applications.find_one({'reg_no': reg_no})
    if user:
        return User(user['reg_no'], user['name'], user['email'], user['status'], user['admin'], user.get('cv_id', None))
    return None

class_d_range = ipaddress.IPv4Network('224.0.0.0/4')  # Class D (Multicast)
class_e_range = ipaddress.IPv4Network('240.0.0.0/4')  # Class E (Experimental)

def is_class_d_or_e(ip):
    ip_addr = ipaddress.IPv4Address(ip)
    return ip_addr in class_d_range or ip_addr in class_e_range

@app.before_request
def before_request():
    client_ip = request.remote_addr
    if is_class_d_or_e(client_ip):
        logging.warning(f'Blocking request from IP {client_ip}')
        abort(403)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        gender = request.form.get('gender')
        reg_no = request.form.get('reg_no')
        mobile_no = request.form.get('mobile_no')
        stream = request.form.get('stream')
        year_of_study = request.form.get('year_of_study')
        role_applied = request.form.get('role_applied')
        dedication = request.form.get('dedication')
        rate_yourself = request.form.get('rate_yourself')
        why_interested = request.form.get('why_interested')
        other_organization = request.form.get('other_organization')
        experience = request.form.get('experience')
        links = request.form.get('links')
        contribution = request.form.get('contribution')
        how_did_you_know = request.form.get('how_did_you_know')
        aws_account = request.form.get('aws_account')
        used_aws = request.form.get('used_aws')
        password = request.form.get('password')
        cv = request.files['cv']

        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the reCAPTCHA.', 'error')
            return redirect(url_for('index'))

        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {'secret': RECAPTCHA_SECRET, 'response': recaptcha_response}
        try:
            recaptcha_verification = requests.post(verify_url, data=payload)
            recaptcha_result = recaptcha_verification.json()
            if not recaptcha_result.get('success'):
                flash('reCAPTCHA verification failed. Please try again.', 'error')
                return redirect(url_for('index'))
        except Exception as e:
            logging.error(f'Error verifying reCAPTCHA: {e}')
            flash('Error verifying reCAPTCHA. Please try again later.', 'error')
            return redirect(url_for('index'))

        if cv and cv.filename!='':
            filename = secure_filename(cv.filename)
            cv_id = fs.put(cv.read(), filename=filename) 
            

        if reg_no and not reg_no.isdigit() and len(reg_no) != 8:
            flash('Invalid registration number', 'error')
            return redirect(url_for('index'))

        if not email or not name:
            flash('All fields are required', 'error')
            return redirect(url_for('index'))
        
        if role_applied == 'Select Here':
            flash('Please select a role', 'error')
            return redirect(url_for('index'))
        
        if rate_yourself == 'Select Here':
            flash('Please rate yourself', 'error')
            return redirect(url_for('index'))
        
        if aws_account == 'Select Here':
            flash('Please select if you have an AWS account', 'error')
            return redirect(url_for('index'))
        
        if used_aws == 'Select Here':
            flash('Please select if you have used AWS before', 'error')
            return redirect(url_for('index'))
        
        data = [
            email, name, gender, reg_no, mobile_no, stream, year_of_study, 
            role_applied, dedication, rate_yourself, why_interested, other_organization,
            experience, links, contribution, how_did_you_know, aws_account, used_aws
        ]

        try:
            try:
                if db.applications.count_documents({'reg_no': reg_no}) > 0:
                    flash('Application already submitted with this registration number', 'error')
                    return redirect(url_for('index'))
            except Exception as e:
                logging.error(f'Error checking if application exists: {e}')
                flash(f'Error submitting the form: {e}', 'error')
                return redirect(url_for('index'))
            try:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                db.applications.insert_one({
                    'email': email,
                    'name': name,
                    'gender': gender,
                    'reg_no': reg_no,
                    'mobile_no': mobile_no,
                    'stream': stream,
                    'year_of_study': year_of_study,
                    'role_applied': role_applied,
                    'dedication': dedication,
                    'rate_yourself': rate_yourself,
                    'why_interested': why_interested,
                    'other_organization': other_organization,
                    'experience': experience,
                    'links': links,
                    'contribution': contribution,
                    'how_did_you_know': how_did_you_know,
                    'aws_account': aws_account,
                    'used_aws': used_aws,
                    'cv_id': cv_id,
                    'status': 'Pending',
                    'submitted_at': datetime.now(),
                    'reviewed_by': None,
                    'password': hashed_password,
                    'admin': False
                })
            except Exception as e:
                flash(f'Error submitting the form: {e}', 'error')
            sheet.append_row(data)
            flash('Your application has been submitted successfully!', 'success')
        except Exception as e:
            flash(f'Error submitting the form: {e}', 'error')
        return redirect(url_for('index'))
    elif request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        else:
            return render_template('apply.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        reg_no = request.form.get('reg_no')
        password = request.form.get('password')

        if not reg_no or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('login'))

        try:
            user = db.applications.find_one({'reg_no': str(reg_no)})
            if not user:
                flash(f"User with registration number {reg_no} not found", 'error')
                return redirect(url_for('login'))

            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                user_obj = User(user['reg_no'], user['name'], user['email'], user['status'], user.get('admin', False), user.get('cv_id', None))
                login_user(user_obj)
                if str(reg_no) == str(password):
                    flash('First time login detected. Please change your password', 'warning')
                    return redirect(url_for('change_password'))

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(f"Invalid password for registration number {reg_no}", 'error')
                return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error logging in: {e}', 'error')
            logging.error(f'Error logging in: {e}')
            return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if not current_user.is_authenticated:
        flash('You need to login to view this page', 'error')
        return redirect(url_for('login'))
    if current_user.admin:
        applications = list(db.applications.find())
        applications = [app for app in applications if app['admin'] == False]
        return render_template('admin_dashboard.html', applications=applications, current_user=current_user)
    else:
        application = db.applications.find_one({'reg_no': str(current_user.reg_no)})
        return render_template('user_dashboard.html', current_user=current_user, application=application)
    
@app.route('/add/user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.admin:
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        reg_no = request.form.get('reg_no')
        password = request.form.get('password')
        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            db.applications.insert_one({
                'name':name,
                'reg_no': reg_no,
                'password': hashed_password,
                'admin': True,
                'email': "None",
                'status': 'Admin',
                'cv_id': None,
            })
        except Exception as e:
            flash(f'Error adding user: {e}', 'error')
            return redirect(url_for('add_user'))
        logging.info(f'User {name} added successfully by {current_user.name}')
        return redirect(url_for('dashboard'))

    return render_template('add_user.html')

@app.route('/change/password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not old_password or not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash('New password and confirm password do not match', 'error')
            return redirect(url_for('change_password'))
        try:
            user = db.applications.find_one({'reg_no': str(current_user.reg_no)})
            if bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                db.applications.update_one({'reg_no': str(current_user.reg_no)}, {'$set': {'password': hashed_password}})
                flash('Password changed successfully!', 'success')
            else:
                flash('Incorrect old password', 'error')
        except Exception as e:
            flash(f'Error changing password: {e}', 'error')
        return redirect(url_for('change_password'))
    return render_template('change_password.html')

@app.route('/application/<reg_no>', methods=['GET', 'POST'])
@login_required
def view_application(reg_no):
    if not current_user.admin:
        flash('You do not have permission to view this page', 'error')
        return redirect(url_for('dashboard'))

    application = db.applications.find_one({'reg_no': reg_no})
    if not application:
        flash('Application not found', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_status = request.form.get('status')
        if new_status not in ['Approved', 'Declined']:
            flash('Invalid status update', 'error')
            return redirect(url_for('view_application', reg_no=reg_no))
        db.applications.update_one(
            {'reg_no': reg_no},
            {
                '$set': {
                    'status': new_status,
                    'reviewed_by': current_user.name
                }
            }
        )
        flash('Application status updated successfully!', 'success')
        return redirect(url_for('view_application', reg_no=reg_no))

    return render_template('view_application.html', application=application)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_server_error(e):
    flash("Oops! Something went wrong. Please try again later", 'error')
    logging.error(f'Internal Server Error: {e}')
    return redirect(url_for('index'))

@app.route('/cv/download/<cv_id>')
@login_required
def download_cv(cv_id):
    try:
        file_id = ObjectId(cv_id)
        file = fs.get(file_id)
        response = Response(file.read(), mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename="{file.filename}"'
        return response
    except gridfs.errors.NoFile:
        flash('CV not found', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    
@app.route('/cv/upload', methods=['POST'])
@login_required
def upload_cv():
    if 'cv' not in request.files or request.files['cv'].filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    cv = request.files['cv']
    if cv and cv.filename != '':
        filename = secure_filename(cv.filename)
        cv_id = fs.put(cv.read(), filename=filename)
        db.applications.update_one(
            {'reg_no': current_user.reg_no},
            {'$set': {'cv_id': cv_id}}
        )
        flash('CV uploaded successfully', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Failed to upload CV', 'error')
        return redirect(url_for('dashboard'))

@app.errorhandler(403)
def forbidden(e):
    """
    Handle 403 Forbidden errors.
    """
    return render_template('403.html'), 403

@app.errorhandler(404)
def notfound(e):
    """
    Handle 404 Forbidden errors.
    """
    return redirect(url_for('index'))

def run_test_server():
    logging.info("Running Test Flask Server")
    app.run(host='0.0.0.0', port=80, debug=True)

def run_production_server():
    logging.info("Running Production Server")
    waitress.serve(app, host='0.0.0.0', port=80)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)