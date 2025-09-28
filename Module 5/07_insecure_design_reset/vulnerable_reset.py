# vulnerable_reset.py
from flask import request

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password   # directly set plaintext password
    db.session.commit()
    return "Password reset"
