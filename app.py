from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
import os
import json

# ---------------------------------------------------------------------
# Config & env
# ---------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# load .env (if present) so environment variables populate in development
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'streetfindr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# optional: limit upload size (8 MB)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Authlib (Google OAuth)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ---------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # allow null for OAuth-only accounts
    password = db.Column(db.String(200), nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=True)
    google_id = db.Column(db.String(200), unique=True, nullable=True)
    is_vendor = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref='vendors')

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    starts_at = db.Column(db.DateTime)
    ends_at = db.Column(db.DateTime)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    vendor = db.relationship('Vendor', backref='events')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text)
    image = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
    vendor = db.relationship('Vendor', backref='reviews')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def is_safe_redirect_url(target):
    """
    Prevent open redirects: ensure redirect stays on same host.
    """
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in ('http', 'https') and host_url.netloc == redirect_url.netloc

def allowed_file(filename):
    ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ---------------------------------------------------------------------
# OAuth routes (Google)
# ---------------------------------------------------------------------

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('auth_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def auth_google():
    # exchange code for token and validate id_token
    token = oauth.google.authorize_access_token()
    # Authlib: parse and validate id_token using provider metadata
    userinfo = None
    try:
        userinfo = oauth.google.parse_id_token(token)
    except Exception:
        # fallback: some setups may use userinfo endpoint
        try:
            resp = oauth.google.get('userinfo')
            userinfo = resp.json()
        except Exception:
            userinfo = None

    if not userinfo:
        flash('Failed to fetch user info from Google', 'danger')
        return redirect(url_for('login'))

    google_id = userinfo.get('sub')
    email = userinfo.get('email')
    email_verified = userinfo.get('email_verified', False)
    name = userinfo.get('name') or (email.split('@')[0] if email else 'googleuser')

    # It's recommended to require verified email
    if email and not email_verified:
        flash('Google account email is not verified', 'danger')
        return redirect(url_for('login'))

    # Find existing user by google_id or email
    user = None
    if google_id:
        user = User.query.filter_by(google_id=google_id).first()
    if not user and email:
        user = User.query.filter_by(email=email).first()

    if user:
        # link google_id if it wasn't set before
        if not user.google_id and google_id:
            user.google_id = google_id
            db.session.commit()
    else:
        # create a new user
        base_username = (name or (email.split('@')[0] if email else 'googleuser')).strip()
        username = base_username
        i = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{i}"
            i += 1
        user = User(username=username, password=None, email=email, google_id=google_id)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    next_url = request.args.get('next') or url_for('index')
    if not is_safe_redirect_url(next_url):
        next_url = url_for('index')
    return redirect(next_url)

# ---------------------------------------------------------------------
# ROUTES — Pages
# ---------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/discover')
def discover():
    return render_template('discover.html')

@app.route('/vendor/<int:vendor_id>')
def vendor_page(vendor_id):
    v = Vendor.query.get_or_404(vendor_id)
    return render_template('vendor.html', vendor=v)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        hashed = generate_password_hash(password)
        u = User(username=username, password=hashed)
        db.session.add(u)
        db.session.commit()
        login_user(u)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        u = User.query.filter_by(username=username).first()
        if not u or not u.password or not check_password_hash(u.password, password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
        login_user(u)
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ---------------------------------------------------------------------
# VENDOR & EVENT CREATION
# ---------------------------------------------------------------------

@app.route('/vendor/create', methods=['GET', 'POST'])
@login_required
def vendor_create():
    if request.method == 'POST':
        name = request.form['name']
        desc = request.form.get('description')
        lat = float(request.form['latitude'])
        lng = float(request.form['longitude'])
        addr = request.form.get('address')
        file = request.files.get('image')
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        v = Vendor(
            name=name,
            description=desc,
            latitude=lat,
            longitude=lng,
            address=addr,
            owner_id=current_user.id,
            image=filename
        )
        db.session.add(v)
        db.session.commit()
        return redirect(url_for('vendor_page', vendor_id=v.id))
    return render_template('vendor_form.html')

@app.route('/event/create', methods=['POST'])
@login_required
def event_create():
    data = request.form
    title = data['title']
    lat = float(data['latitude'])
    lng = float(data['longitude'])
    starts = datetime.fromisoformat(data['starts_at']) if data.get('starts_at') else None
    ends = datetime.fromisoformat(data['ends_at']) if data.get('ends_at') else None
    vendor_id = int(data.get('vendor_id')) if data.get('vendor_id') else None
    e = Event(
        title=title,
        description=data.get('description'),
        latitude=lat,
        longitude=lng,
        starts_at=starts,
        ends_at=ends,
        vendor_id=vendor_id
    )
    db.session.add(e)
    db.session.commit()
    return redirect(url_for('index'))

# ---------------------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------------------

@app.route('/api/vendors')
def api_vendors():
    minlat = request.args.get('minlat', type=float)
    maxlat = request.args.get('maxlat', type=float)
    minlng = request.args.get('minlng', type=float)
    maxlng = request.args.get('maxlng', type=float)
    q = Vendor.query.filter_by(is_active=True)
    if None not in (minlat, maxlat, minlng, maxlng):
        q = q.filter(
            Vendor.latitude >= minlat,
            Vendor.latitude <= maxlat,
            Vendor.longitude >= minlng,
            Vendor.longitude <= maxlng
        )
    vendors = q.all()
    out = []
    for v in vendors:
        out.append({
            'id': v.id,
            'name': v.name,
            'description': v.description,
            'latitude': v.latitude,
            'longitude': v.longitude,
            'address': v.address,
            'image': url_for('uploaded_file', filename=v.image) if v.image else None
        })
    return jsonify(out)

@app.route('/api/events')
def api_events():
    events = Event.query.filter(
        (Event.ends_at == None) | (Event.ends_at >= datetime.utcnow())
    ).all()
    out = []
    for e in events:
        out.append({
            'id': e.id,
            'title': e.title,
            'description': e.description,
            'latitude': e.latitude,
            'longitude': e.longitude,
            'starts_at': e.starts_at.isoformat() if e.starts_at else None,
            'ends_at': e.ends_at.isoformat() if e.ends_at else None
        })
    return jsonify(out)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------------------------------------------------------
# SIMPLE NOTIFICATIONS STREAM (SSE)
# ---------------------------------------------------------------------

_subscribers = []

@app.route('/stream/notifications')
def stream_notifications():
    def gen():
        q = []
        _subscribers.append(q)
        try:
            while True:
                if q:
                    data = q.pop(0)
                    yield f"data: {json.dumps(data)}\n\n"
                else:
                    yield ': heartbeat\n\n'
        except GeneratorExit:
            _subscribers.remove(q)
    return Response(gen(), mimetype='text/event-stream')

@app.route('/admin/broadcast', methods=['POST'])
def admin_broadcast():
    data = request.get_json() or {}
    for q in list(_subscribers):
        q.append(data)
    return jsonify({'sent': True})

# ---------------------------------------------------------------------
# REVIEWS
# ---------------------------------------------------------------------

@app.route('/vendor/<int:vendor_id>/review', methods=['POST'])
@login_required
def post_review(vendor_id):
    rating = int(request.form['rating'])
    text = request.form.get('text')
    file = request.files.get('image')
    filename = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    r = Review(
        user_id=current_user.id,
        vendor_id=vendor_id,
        rating=rating,
        text=text,
        image=filename
    )
    db.session.add(r)
    db.session.commit()
    return redirect(url_for('vendor_page', vendor_id=vendor_id))

# ---------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------

if __name__ == '__main__':
    # For dev: create DB tables if missing (use migrations for production)
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
