import os
import base64
import requests
import cv2
import numpy as np
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    history = db.relationship('ScanHistory', backref='author', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def decode_qr_code(file_stream):
    try:
        file_bytes = np.frombuffer(file_stream.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)
        if data:
            return data
        return None
    except:
        return None

def get_virustotal_report(url_to_scan):
    if not VT_API_KEY:
        return {"status": "ERROR", "message": "API Key Missing", "color": "dark"}

    try:
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}

        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)

            if malicious > 0:
                return {"status": "DANGER", "color": "danger", "malicious_count": malicious, "message": f"Flagged by {malicious} vendors!"}
            else:
                return {"status": "SAFE", "color": "success", "malicious_count": 0, "message": "Clean URL."}
        elif response.status_code == 404:
            return {"status": "UNKNOWN", "color": "warning", "message": "URL not found in VirusTotal database."}
        else:
            return {"status": "ERROR", "color": "secondary", "message": "Connection Error"}
    except:
        return {"status": "ERROR", "color": "secondary", "message": "Internal Error"}

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username taken', 'danger')
            return redirect(url_for('signup'))
        
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed', 'danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    report = None
    url_to_scan = None
    
    if request.method == 'POST':
        url_to_scan = request.form.get('url')
        if url_to_scan:
            report = get_virustotal_report(url_to_scan)
            new_scan = ScanHistory(url=url_to_scan, status=report['status'], user_id=user_id)
            db.session.add(new_scan)
            db.session.commit()

    history = ScanHistory.query.filter_by(user_id=user_id).order_by(ScanHistory.scan_date.desc()).limit(20).all()
    return render_template('dashboard.html', report=report, url=url_to_scan, history=history)

@app.route('/scan-qr', methods=['GET', 'POST'])
def scan_qr():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    report = None
    url_to_scan = None
    
    if request.method == 'POST':
        if 'qr_file' in request.files and request.files['qr_file'].filename != '':
            file = request.files['qr_file']
            decoded_url = decode_qr_code(file)
            
            if decoded_url:
                url_to_scan = decoded_url
                report = get_virustotal_report(url_to_scan)
                new_scan = ScanHistory(url=url_to_scan, status=report['status'], user_id=user_id)
                db.session.add(new_scan)
                db.session.commit()
            else:
                flash("Could not read QR Code", "warning")

    history = ScanHistory.query.filter_by(user_id=user_id).order_by(ScanHistory.scan_date.desc()).limit(20).all()
    return render_template('scan_qr.html', report=report, url=url_to_scan, history=history)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)