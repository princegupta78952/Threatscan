import os
import base64
import cv2
import numpy as np
import pickle
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import webbrowser
from threading import Timer

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

print("⏳ AI Model loading...")
try:
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('tfidf_vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    print(" Model and Vectorizer Ready!")
except Exception as e:
    print(f"❌ Error: Model files not found. {e}")
    model = None
    vectorizer = None

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

def analyze_url_with_ml(url_to_scan):
    if model is None or vectorizer is None:
        return {"status": "ERROR", "color": "secondary", "message": "ML Model missing!", "malicious_count": 0}

    try:
        url_vector = vectorizer.transform([url_to_scan])
        prediction = model.predict(url_vector)[0]

        if prediction == 0:
            return {"status": "DANGER", "color": "danger", "malicious_count": 1, "message": " Warning: Phishing URL Detected!"}
        else:
            return {"status": "SAFE", "color": "success", "malicious_count": 0, "message": " Verified: Clean URL."}
    except Exception as e:
        return {"status": "ERROR", "color": "warning", "message": "Scan Failed", "malicious_count": 0}

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
            report = analyze_url_with_ml(url_to_scan)
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
                report = analyze_url_with_ml(url_to_scan)
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

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ == '__main__':
    Timer(1, open_browser).start()
    app.run(debug=True)