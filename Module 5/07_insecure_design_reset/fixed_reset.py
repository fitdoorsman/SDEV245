# fixed_reset.py
from flask import request, jsonify, url_for
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, User

app.config['SECRET_KEY'] = 'change-me'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(app, key_func=get_remote_address)

@app.post('/request-reset')
@limiter.limit("5 per hour")
def request_reset():
    email = request.form.get('email', '')
    user = User.query.filter_by(email=email).first()
    if user:
        token = s.dumps({'uid': user.id})
        # send token via email with a short expiry link (omitted)
        user.reset_token = token
        db.session.commit()
    # always same response to avoid enumeration
    return jsonify(message="If the account exists, a reset link has been sent")

@app.post('/reset-password')
@limiter.limit("5 per hour")
def reset_password():
    token = request.form.get('token', '')
    new_pw = request.form.get('new_password', '')
    try:
        data = s.loads(token, max_age=15*60)
    except (BadSignature, SignatureExpired):
        return jsonify(error='Invalid or expired token'), 400

    user = User.query.get_or_404(data['uid'])
    if user.reset_token != token:
        return jsonify(error='Invalid token'), 400

    user.set_password(new_pw)   # uses a secure hasher (see cryptographic fixes)
    user.reset_token = None
    db.session.commit()
    return jsonify(message='Password reset')
