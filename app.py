import os
import threading
import time
import pandas as pd
import joblib
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
from models import db, User

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db.init_app(app)

# === LOGIN REQUIRED DECORATOR ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Load model and encoders
model = joblib.load('model/ids_model.pkl')
le_protocol = joblib.load('model/le_protocol.pkl')
le_service = joblib.load('model/le_service.pkl')
le_flag = joblib.load('model/le_flag.pkl')

# ==== FCFS IDS Queue System ====
file_queue = []
queue_lock = threading.Lock()

def scan_file(filepath):
    # ... your scan_file code stays unchanged ...
    df = pd.read_csv(filepath)
    features = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'logged_in', 'wrong_fragment', 'same_srv_count', 'same_srv_rate'
    ]
    results = []
    for idx, row in df.iterrows():
        try:
            sample = [
                int(row['duration']),
                le_protocol.transform([row['protocol_type']])[0],
                le_service.transform([row['service']])[0],
                le_flag.transform([row['flag']])[0],
                int(row['src_bytes']),
                int(row['dst_bytes']),
                int(row['logged_in']),
                int(row['wrong_fragment']),
                int(row['same_srv_count']),
                float(row['same_srv_rate'])
            ]
            pred = model.predict([sample])[0]
            results.append({'row': idx+1, 'attack': pred})
        except Exception as e:
            results.append({'row': idx+1, 'attack': f"Error: {str(e)}"})
    attacks = [r for r in results if r['attack'] != "normal" and not str(r['attack']).startswith("Error")]
    return results, attacks

def process_queue():
    while True:
        with queue_lock:
            for fileinfo in file_queue:
                if fileinfo['status'] == 'waiting':
                    fileinfo['status'] = 'processing'
                    try:
                        results, attacks = scan_file(fileinfo['filepath'])
                        fileinfo['results'] = results
                        fileinfo['attacks'] = attacks
                        fileinfo['status'] = 'done'
                    except Exception as e:
                        fileinfo['results'] = []
                        fileinfo['attacks'] = [{'row': 0, 'attack': f"Error: {str(e)}"}]
                        fileinfo['status'] = 'done'
                    break  # FCFS: one at a time
        time.sleep(1)

threading.Thread(target=process_queue, daemon=True).start()

# ==== ROUTES ====

# Publicly accessible routes (no login required)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(url_for('signup'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            flash(f"Password reset link sent to {user.email}. (Simulated)")
        else:
            flash("Username not found!")
    return render_template('forgot_password.html')


# HOME PAGE: redirect to login if not logged in
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')


# All routes below this point require login!
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Logged out.')
    return render_template('logout.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        with queue_lock:
            file_queue.append({
                'filename': filename,
                'filepath': filepath,
                'status': 'waiting',
                'results': [],
                'attacks': []
            })
        flash(f'File {filename} uploaded and added to scan queue (FCFS).')
        return redirect(url_for('queue_status'))
    return render_template('upload.html')

@app.route('/queue')
@login_required
def queue_status():
    with queue_lock:
        queue_snapshot = list(file_queue)
    return render_template('queue.html', file_queue=queue_snapshot)

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    deleted = False
    with queue_lock:
        for i, f in enumerate(file_queue):
            if f['filename'] == filename:
                if os.path.exists(f['filepath']):
                    os.remove(f['filepath'])
                del file_queue[i]
                deleted = True
                flash(f'File {filename} deleted from queue.')
                break
    if not deleted:
        flash('Cannot delete: File not found.')
    return redirect(url_for('queue_status'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/team')
@login_required
def team():
    return render_template('team.html')

@app.route('/simulate_traffic', methods=['POST'])
@login_required
def simulate_traffic():
    data = request.form
    try:
        features = [
            int(data['duration']),
            le_protocol.transform([data['protocol_type']])[0],
            le_service.transform([data['service']])[0],
            le_flag.transform([data['flag']])[0],
            int(data['src_bytes']),
            int(data['dst_bytes']),
            int(data['logged_in']),
            int(data['wrong_fragment']),
            int(data['same_srv_count']),
            float(data['same_srv_rate'])
        ]
        pred = model.predict([features])[0]
    except Exception as e:
        pred = f"Error: {str(e)}"
    return render_template('index.html', prediction=pred)

@app.route('/upload_scan', methods=['GET', 'POST'])
@login_required
def upload_scan():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            job_id = f"{session['username']}_{int(time.time())}"
            # Assuming scan_queue still exists for legacy scan functionality
            scan_queue.put({'file_path': filepath, 'job_id': job_id})
            flash(f"File uploaded. Scan queued (Job ID: {job_id}).")
            return redirect(url_for('scan_status', job_id=job_id))
    return render_template('scan_result.html', results=None, job_id=None, status=None)

@app.route('/scan_status/<job_id>')
@login_required
def scan_status(job_id):
    # Assuming scan_results still exists for legacy scan functionality
    results = scan_results.get(job_id)
    if results is not None:
        status = "Completed"
    else:
        status = "Queued or Running"
    return render_template('scan_result.html', results=results, job_id=job_id, status=status)

# Database tables creation for Flask 3.x+ (no before_first_request)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)