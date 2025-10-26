# database.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    applications = db.relationship('Application', backref='applicant', lazy=True)

class Application(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    encrypted_email = db.Column(db.String, nullable=False)
    encrypted_phone = db.Column(db.String, nullable=False)
    encrypted_pan = db.Column(db.String, nullable=False)
    encrypted_age = db.Column(db.String, nullable=False)
    encrypted_purpose = db.Column(db.String(100), nullable=False)
    encrypted_term = db.Column(db.String, nullable=False)
    encrypted_income = db.Column(db.String, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    commitment = db.Column(db.Text, nullable=False)
    proof_t = db.Column(db.Text, nullable=False)
    proof_s1 = db.Column(db.Text, nullable=False)
    proof_s2 = db.Column(db.Text, nullable=False)

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    mfa_secret = db.Column(db.String(120), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)