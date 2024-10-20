import gspread
from oauth2client.service_account import ServiceAccountCredentials
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import dotenv
import json
from datetime import datetime
import pymongo
import bcrypt
import waitress


dotenv.load_dotenv()

scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
client = gspread.authorize(creds)

SHEET_ID = os.getenv('SHEET_ID')

spreadsheet = client.open_by_key(SHEET_ID)
sheet = spreadsheet.worksheet('Sheet1')

SECRET_KEY = os.getenv('SECRET_KEY')
app = Flask(__name__)
app.secret_key = SECRET_KEY

MONGO_URI = os.getenv('MONGO_URI')
client = pymongo.MongoClient(MONGO_URI)
db = client['aws_application']

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, reg_no, name, email, status, admin):
        self.reg_no = reg_no
        self.name = name
        self.email = email
        self.status = status
        self.admin = admin
    
    def get_id(self):
        return str(self.reg_no)

@login_manager.user_loader
def load_user(reg_no):
    user = db.applications.find_one({'reg_no': reg_no})
    if user:
        return User(user['reg_no'], user['name'], user['email'], user['status'], user['admin'])
    return None

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
        acknowledge = request.form.get('acknowledge')
        password = request.form.get('password')

        # Validation checks
        if reg_no and not reg_no.isdigit():
            flash('Invalid registration number', 'error')
            return redirect(url_for('index'))
        
        if reg_no and len(reg_no) != 8:
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
            experience, links, contribution, how_did_you_know, aws_account, used_aws, acknowledge
        ]

        try:
            try:
                if db.applications.count_documents({'reg_no': reg_no}) > 0:
                    flash('Application already submitted with this registration number', 'error')
                    return redirect(url_for('index'))
            except Exception as e:
                flash(f'Error submitting the form: {e}', 'error')
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
                    'acknowledge': acknowledge,
                    'status': 'Pending',
                    'submitted_at': datetime.now(),
                    'reviewed_by': None,
                    'password': hashed_password,
                    'admin': False
                })
                print('Application inserted into MongoDB')
            except Exception as e:
                print('Error inserting into MongoDB:', e)
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
    if request.method == 'POST':
        reg_no = request.form.get('reg_no')
        password = request.form.get('password')

        print(f"Received login request: reg_no={reg_no}, password={'***' if password else None}")

        if not reg_no or not password:
            print("Missing registration number or password")
            flash('All fields are required', 'error')
            return redirect(url_for('login'))

        try:
            user = db.applications.find_one({'reg_no': str(reg_no)})
            if not user:
                print(f"User not found for reg_no={reg_no}")
                flash('Invalid credentials', 'error')
                return redirect(url_for('login'))

            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                print(f"Password match for user {reg_no}")
                user_obj = User(user['reg_no'], user['name'], user['email'], user['status'], user.get('admin', False))
                login_user(user_obj)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                print(f"Incorrect password for user {reg_no}")
                flash('Invalid credentials', 'error')
                return redirect(url_for('login'))

        except Exception as e:
            print(f"Error during login: {e}")
            flash(f'Error logging in: {e}', 'error')
            return redirect(url_for('login'))
    else:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
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
                'status': 'Admin'
            })
        except Exception as e:
            flash(f'Error adding user: {e}', 'error')
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def run_test_server():
    app.run(host='0.0.0.0', port=8080, debug=True)

def run_production_server():
    waitress.serve(app, host='0.0.0.0', port=8080)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)