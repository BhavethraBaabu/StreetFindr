from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'streetfindr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # plaintext for demo ONLY
    is_vendor = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        u = User(username=username, password=password)
        db.session.add(u)
        db.session.commit()
        login_user(u)
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        u = User.query.filter_by(username=username, password=password).first()
        if not u:
            flash('Invalid credentials')
            return redirect(url_for('login'))
        login_user(u)
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


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
        if file:
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
                    yield f"data: {json.dumps(data)}\\n\\n"
                else:
                    yield ': heartbeat\\n\\n'
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
    if file:
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




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
