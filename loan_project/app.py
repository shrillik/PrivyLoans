# app.py
from dotenv import load_dotenv
load_dotenv()

import os
import uuid
import hashlib
import random
import joblib
import pandas as pd
import io
import base64

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import pyotp
import qrcode
from crypto_utils import generate_keys, sign_data, verify_signature
from zkp_utils import pedersen_commit, point_to_bytes, prove_pedersen_opening, verify_pedersen_opening
from encryption_utils import encrypt_data, decrypt_data
from database import db, Application, Admin, User

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///privyloans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- INITIALIZE EXTENSIONS ---
db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- LOAD ML MODEL ---
try:
    loan_approval_model = joblib.load('loan_model.joblib')
except FileNotFoundError:
    loan_approval_model = None
    app.logger.error("loan_model.joblib not found. ML predictions will be disabled.")

# --- USER AUTHENTICATION SETUP ---
@login_manager.user_loader
def load_user(user_id):
    if session.get('user_type') == 'Admin':
        return Admin.query.get(int(user_id))
    return User.query.get(int(user_id))

# --- CRYPTO SETUP ---
private_key, public_key = generate_keys()

# --- HELPER FUNCTIONS ---
def check_eligibility(age, income):
    errors = []
    if not 21 <= age <= 60:
        errors.append("Eligibility Error: Age must be between 21 and 60.")
    if income < 250000:
        errors.append("Eligibility Error: Annual income must be at least ₹2,50,000.")
    return errors

# --- GENERAL & USER ROUTES ---
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and isinstance(current_user, User):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            session['user_type'] = 'User'
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_type', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if isinstance(current_user, Admin): return redirect(url_for('admin'))
    decrypted_apps = [{'id': app.id, 'amount': app.amount, 'purpose': decrypt_data(app.encrypted_purpose)}
                      for app in current_user.applications]
    return render_template('dashboard.html', applications=decrypted_apps)

# --- APPLICATION FLOW ROUTES ---
@app.route('/apply/verify-phone', methods=['GET', 'POST'])
@login_required
def verify_phone():
    if request.method == 'POST':
        phone = request.form.get('phone')
        if len(phone) == 10 and phone.isdigit():
            otp = str(random.randint(100000, 999999))
            session['otp_for_verification'] = otp
            session['phone_for_verification'] = phone
            flash(f"For demo purposes, your OTP for {phone} is: {otp}", "info")
            return redirect(url_for('verify_otp'))
        else:
            flash("Please enter a valid 10-digit phone number.", "danger")
    return render_template('verify_phone.html')

@app.route('/apply/verify-otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    if 'phone_for_verification' not in session: return redirect(url_for('verify_phone'))
    if request.method == 'POST':
        if request.form.get('otp') == session.get('otp_for_verification'):
            session['phone_verified'] = session.get('phone_for_verification')
            for key in ['otp_for_verification', 'phone_for_verification']: session.pop(key, None)
            flash("Phone number verified successfully!", "success")
            return redirect(url_for('apply'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
    return render_template('verify_otp.html', phone=session.get('phone_for_verification'))

@app.route('/apply', methods=["GET", "POST"])
@login_required
def apply():
    if isinstance(current_user, Admin):
        flash("Admins cannot apply for loans.", "danger")
        return redirect(url_for('admin'))
    if 'phone_verified' not in session:
        flash("Please verify your phone number first.", "warning")
        return redirect(url_for('verify_phone'))
    if request.method == "POST":
        form_data = request.form
        try:
            name, email, pan, purpose = form_data.get("name"), form_data.get("email"), form_data.get("pan"), form_data.get("purpose")
            age, term, income, amount = int(form_data.get("age", 0)), int(form_data.get("term", 0)), int(form_data.get("income", 0)), int(form_data.get("amount", 0))
        except (ValueError, TypeError):
            return jsonify({"success": False, "message": "Invalid number format in form."}), 400
        
        eligibility_errors = check_eligibility(age, income)
        if eligibility_errors: return jsonify({"success": False, "message": eligibility_errors[0]}), 400

        app_id = str(uuid.uuid4())
        value_int = int.from_bytes(hashlib.sha256(f"{name}-{amount}".encode()).digest(), "big")
        C_point, v, r = pedersen_commit(value_int)
        commitment_bytes = point_to_bytes(C_point)
        proof = prove_pedersen_opening(C_point, v, r)
        signature = sign_data(private_key, commitment_bytes)
        
        new_application = Application(id=app_id, user_id=current_user.id, name=name, amount=amount,
                                      encrypted_email=encrypt_data(email), encrypted_phone=encrypt_data(session['phone_verified']),
                                      encrypted_pan=encrypt_data(pan.upper()), encrypted_age=encrypt_data(str(age)),
                                      encrypted_purpose=encrypt_data(purpose), encrypted_term=encrypt_data(str(term)),
                                      encrypted_income=encrypt_data(str(income)), signature=signature.hex(),
                                      commitment=commitment_bytes.hex(), proof_t=proof['t'],
                                      proof_s1=proof['s1'], proof_s2=proof['s2'])
        db.session.add(new_application)
        db.session.commit()
        session.pop('phone_verified', None)
        return jsonify({"success": True, "redirect_url": url_for("success", app_id=app_id)})
    return render_template("apply.html", verified_phone=session.get('phone_verified'))

@app.route('/success')
@login_required
def success():
    return render_template("success.html", app_id=request.args.get('app_id'))

@app.route('/status', methods=['GET', 'POST'])
def status():
    # ... This logic remains the same as your uploaded file ...
    application_status = None
    if request.method == 'POST':
        app_record = Application.query.get(request.form.get('app_id'))
        if app_record:
            commitment_bytes, signature_bytes = bytes.fromhex(app_record.commitment), bytes.fromhex(app_record.signature)
            proof = {'t': app_record.proof_t, 's1': app_record.proof_s1, 's2': app_record.proof_s2}
            is_valid = verify_signature(public_key, commitment_bytes, signature_bytes) and verify_pedersen_opening(app_record.commitment, proof)
            application_status = {"name": app_record.name, "valid": is_valid}
    return render_template("status.html", application=application_status)

# --- ADMIN ROUTES ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and isinstance(current_user, Admin): return redirect(url_for('admin'))
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and bcrypt.check_password_hash(admin.password_hash, password):
            login_user(admin)
            session['user_type'] = 'Admin'
            if admin.mfa_enabled:
                session['mfa_user_id'] = admin.id
                return redirect(url_for('verify_mfa'))
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin username or password.', 'danger')
    return render_template('login.html')

@app.route('/admin')
@login_required
def admin():
    if not isinstance(current_user, Admin): 
        return redirect(url_for('dashboard'))
    
    apps = Application.query.all()
    applications_data = []
    for app in apps:
        commitment_bytes = bytes.fromhex(app.commitment)
        signature_bytes = bytes.fromhex(app.signature)
        proof = {'t': app.proof_t, 's1': app.proof_s1, 's2': app.proof_s2}
        is_valid = verify_signature(public_key, commitment_bytes, signature_bytes) and verify_pedersen_opening(app.commitment, proof)
        
        prediction = "N/A"
        if is_valid and loan_approval_model:
            try:
                age = int(decrypt_data(app.encrypted_age))
                income = int(decrypt_data(app.encrypted_income))
                term = int(decrypt_data(app.encrypted_term))
                amount = app.amount

                applicant_data = pd.DataFrame({
                    'Age': [age],
                    'Income': [income],
                    'Credit_Score': [750],
                    'Loan_Amount': [amount],
                    'Loan_Term': [term],
                    'Employment_Status_Unemployed': [0]
                })
                ordered_cols = ['Age', 'Income', 'Credit_Score', 'Loan_Amount', 'Loan_Term', 'Employment_Status_Unemployed']
                result = loan_approval_model.predict(applicant_data[ordered_cols])[0]
                prediction = "Approved" if result == 1 else "Rejected"
            except Exception as e:
                # This is the corrected block
                prediction = "Error"
                app.logger.error(f"ML Prediction failed for app {app.id}: {e}")

        applications_data.append({
            "id": app.id, 
            "name": app.name, 
            "amount": app.amount, 
            "valid": is_valid, 
            "prediction": prediction
        })
        
    return render_template("admin.html", applications=applications_data)

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    # ... This logic remains the same as your uploaded file ...
    if 'mfa_user_id' not in session: return redirect(url_for('admin_login'))
    if request.method == 'POST':
        admin = Admin.query.get(session['mfa_user_id'])
        user = load_user(admin.id) # Re-wrap as Admin for mfa_secret property
        mfa_code = request.form.get('mfa_code')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(mfa_code):
            login_user(user)
            session.pop('mfa_user_id', None)
            return redirect(url_for('admin'))
        else:
            flash("Invalid authentication code.", "danger")
    return render_template('verify_mfa.html')
    
@app.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    # ... This logic remains the same as your uploaded file ...
    if not isinstance(current_user, Admin): return redirect(url_for('dashboard'))
    admin = current_user
    if admin.mfa_enabled:
        flash("MFA is already enabled.", "info")
        return redirect(url_for('admin'))
    if request.method == 'POST':
        mfa_code = request.form.get('mfa_code')
        totp = pyotp.TOTP(session['mfa_secret'])
        if totp.verify(mfa_code):
            admin.mfa_secret, admin.mfa_enabled = session['mfa_secret'], True
            db.session.commit()
            flash("MFA enabled successfully!", "success")
            session.pop('mfa_secret', None)
            return redirect(url_for('admin'))
        else:
            flash("Invalid code. Please try again.", "danger")
            return redirect(url_for('setup_mfa'))
    secret = pyotp.random_base32()
    session['mfa_secret'] = secret
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=admin.username, issuer_name="PrivyLoans")
    img = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_image = base64.b64encode(buffered.getvalue()).decode()
    return render_template("setup_mfa.html", qr_code_image=qr_code_image)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)