from flask import Flask, request, flash, session
from flask_login import current_user, LoginManager, login_user, login_required
from flask_migrate import Migrate
from flask import render_template, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functions import UserModel,ReportModel
from config import SECRET_KEY, MAIL_PASSWORD, TWILIO_ACCOUNT_SIID, TWILIO_AUTH_TOKEEN
from twilio.rest import Client
import random
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from mimetypes import guess_type

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Configure your Flask app to use Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mail.helpsetu@gmail.com'
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mail = Mail(app)
mail= Mail(app)
# Function to send mail
def send_email(r_email,new_report,file_path):
    subject='New Report added to HelpSetu'
    recipients = [r_email]
    sender = app.config['MAIL_USERNAME']
    body = (
        f"Victim's Name - {new_report['victim_name']}\n"
        f"Located at {new_report['address']}, {new_report['block']}, {new_report['district']}, {new_report['state']}.\n"
        f"Witnessed by {new_report['name']} who can be contacted at {new_report['contact']}.\n"
        f"The proof image is attached below:-"
    )
    msg = Message(subject, sender=sender, recipients=recipients, body=body)
    if file_path:
        # Guess the MIME type of the file based on its extension
        mime_type, _ = guess_type(file_path)
        if mime_type:
            # Extract the file name from the file path
            file_name = file_path.split('/')[-1]
            with app.open_resource(file_path) as fp:
                msg.attach(file_name, mime_type, fp.read())
    # Sends the mail
    mail.send(msg)

# Twilio Credintials
TWILIO_ACCOUNT_SID=TWILIO_ACCOUNT_SIID
TWILIO_AUTH_TOKEN=TWILIO_AUTH_TOKEEN
TWILIO_PHONE_NUMBER='+17722120629'

# Intialize the twilio client account
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# In Memory Storage for OTPs
otp_storage={}

# Generate OTP
def generate_otp():
    return str(random.randint(100000,999999))

# Send OTP via SMS
def send_otp(phone_number,otp):
    formatted_phone_number=f'+91{phone_number}'
    message=client.messages.create(
        body=f'Thank You for reaching HelpSetu, Your requested OTP is: {otp}',
        from_=TWILIO_PHONE_NUMBER,
        to=formatted_phone_number
    )
    return message.sid

# Setting the path to store images of the report
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'Uploads')

# Setting the extensions which are allowed to send in the report
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


# Database file is stored in /instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)

# Initialize the login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initializing the migration support
migrate = Migrate(app, db)

# Setting the models of database
User = UserModel(db=db)
Report = ReportModel(db)


# Function to check the extension of images
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for the Home page
@app.route('/')
def index():
    # If user is logged in then no need to logged in again
    user_initial = session.get('user_initial', None)
    return render_template('index.html',user_initial=user_initial)

# Route for the sendus form page
@app.route('/sendus',methods=['GET','POST'])
def sendus():
    # Check if user is logged in
    if 'user_initial' not in session:
        flash('Please log in to report the issue.','login')
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name')
        contact = request.form.get('contact')
        victim_name= request.form.get('subject')
        address= request.form.get('address')
        state= request.form.get('state')
        district = request.form.get('district')
        block = request.form.get('block')
        latitude = request.form.get('latitude') or 'Not Provided'
        longitude = request.form.get('longitude') or 'Not Provided'
        more_details = request.form.get('more_details')

        # Handle file upload
        file = request.files.get('child_photo')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Create a new report instance
            new_report = Report(name=name, contact=contact, victim_name=victim_name,
                                address=address, state=state, district=district,
                                block=block, location=f'{latitude}, {longitude}', child_photo=file_path,
                                more_details=more_details)
            # Calling the send_email function
            send_email('mail.helpsetu@gmail.com',{
                'name': new_report.name,
                'contact': new_report.contact,
                'victim_name': new_report.victim_name,
                'address': new_report.address,
                'state': new_report.state,
                'district': new_report.district,
                'block': new_report.block,
            }, file_path)

            # Add to the database session and commit
            db.session.add(new_report)
            db.session.commit()
            # Increment user's points by 10 per report
            current_user = User.query.filter_by(mobilenum=session.get('login_mobilenum')).first()
            if current_user.is_authenticated:
                current_user.point += 10
                db.session.commit()
            return render_template('tq.html')
        
        else:
            flash('Invalid file type or no file uploaded.','sendus')
            return redirect(url_for('sendus'))    
    return render_template('sendus.html')

# Route for parterns page
@app.route('/partners')
def partners():
    return render_template('partners.html')

# Route for About-us page
@app.route('/part')
def part():
    return render_template('part.html')

# Route for donate us page
@app.route('/donate')
def donate():
    return render_template('donate.html')

# Route for rewards page
@app.route('/rewards')
@login_required
def rewards():
    # Checks the user points if not then 0
    user_points = current_user.point if current_user.is_authenticated else 0
    return render_template('rewards.html',user_points=user_points)


# Route for login page
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action')
        fullname = request.form.get('username')
        mobilenum = request.form.get('tel')
        password = request.form.get('log_password')
        session['login_mobilenum']=mobilenum
        session['login_fullname']=fullname
        session['login_password']=password

        # Check if the mobile number exists in the database
        user = User.query.filter_by(mobilenum=mobilenum).first()

        # Verify password
        if action == 'login':
            if user:
                if check_password_hash(user.password_hash, password):
                    session.pop('login_mobilenum', None)
                    session.pop('login_fullname', None)
                    session.pop('login_password', None)
                    # Login successful
                    session['user_initial'] = user.fullname[0].upper() if user.fullname else None
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    # Invalid credentials
                    flash ('Incorrect password! Please try again', 'login')
                    return redirect(url_for('login'))
            else:
                #Mobile number not registered
                flash('Mobile number not registered! Please sign up', 'login')
                session.pop('login_mobilenum', None)
                session.pop('login_fullname', None)
                session.pop('login_password', None)
                return redirect(url_for('create_account'))
    else:
        # Serve the login page for GET request
        mobilenum = session.get('login_mobilenum', '')
        fullname = session.get('login_fullname', '')
        password = session.get('login_password', '')
        return render_template('login.html', login_mobilenum=mobilenum, login_fullname=fullname, login_password=password)

# Route for setting the password page    
@app.route('/reset_password', methods=['GET','POST'])
def reset_password():
    if request.method == 'POST':
        action= request.form.get('action')
        if action == 'sendotp':
            mobile_number= request.form.get('mob')
            otp = generate_otp()
            # Store OTP with associated mobile number
            otp_storage[mobile_number] = otp  
            send_otp(mobile_number, otp)
            flash('OTP sent succesfully', 'reset')
            return redirect(url_for('reset_password'))
        elif action == 'reset_button':
            mobile_number= request.form.get('mob')
            otp = request.form.get('otp')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            if otp_storage.get(mobile_number) == otp:
                if new_password == confirm_password:
                    hashed_password=generate_password_hash(new_password)
                    user= User.query.filter_by(mobilenum=mobile_number).first()
                    if user:
                        user.password_hash = hashed_password
                        db.session.commit()
                        # Clear the otp storage after succesfully reset password
                        del otp_storage[mobile_number]
                        flash('Password reset succesfully.Please login', 'login')
                        return redirect(url_for('login'))
                    else:
                        flash('Mobile number not found.Please check', 'reset')
                        return redirect(url_for('reset_password'))
                else:
                    flash('Passwords do not match.','reset')
                    return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP.','reset')
                return redirect(url_for('reset_password'))
            
    else:
        return render_template('forgot.html')

# To logOut the user
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Route for creating the account
@app.route('/create_account', methods=['GET','POST'])
def create_account():
    if request.method == 'POST':
        action = request.form.get('action')
        fullname = request.form.get('create_username')
        mobilenum = request.form.get('create_tel')
        password = request.form.get('create_password')
        session['create_mobilenum']=mobilenum
        session['create_fullname']=fullname
        session['create_password']=password
        
        if action == 'send_otp':
            # Check if the mobile number is already registered
            existing_user = User.query.filter_by(mobilenum=mobilenum).first()
            if existing_user:
                flash('Mobile number already registered!!', 'create_account')
                return redirect(url_for('create_account'))

            # User wants to send an OTP
            otp = generate_otp()
            otp_storage[mobilenum] = otp
            send_otp(mobilenum, otp)
            flash('OTP sent succesfully', 'create_account')
            return redirect(url_for('create_account'))

        
        elif action == 'Create_account':
            # User wants to create an account
            fullname = request.form.get('create_username')
            mobilenum = request.form.get('create_tel')
            password = request.form.get('create_password')
            otp = request.form.get('otp')

            # Verify OTP
            if otp_storage.get(mobilenum) == otp:
                session.pop('create_mobilenum', None)
                session.pop('create_fullname', None)
                session.pop('create_password', None)
                # Hash password and create account
                hashed_password = generate_password_hash(password)
                new_user = User(fullname=fullname, mobilenum=mobilenum, password_hash=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                # Clear the OTP from storage after successful verification
                del otp_storage[mobilenum]
                flash('Account created successfully, Please login', 'login')
                return redirect(url_for('login'))
            else:
                flash('Inavalid OTP!', 'create_account')
                return redirect(url_for('create_account'))

    else:
        # Redirect to the index page if the method is GET
        mobilenum = session.get('create_mobilenum', '')
        fullname = session.get('create_fullname', '')
        password = session.get('create_password', '')
        return render_template('login.html', create_mobilenum=mobilenum, create_fullname=fullname, create_password=password)


# Running the file from command line
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)