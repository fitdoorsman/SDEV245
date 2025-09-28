# vulnerable.py
from flask import jsonify

@app.route('/account/<user_id>')
def get_account(user_id):
    # No authentication or authorization!
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
